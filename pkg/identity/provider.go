package identity

import (
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
)

type CertificateRequest struct {
	Token string `json:"token"`
	CSR   string `json:"csr"`
}

type Provider struct {
	http.Server

	router   *mux.Router
	ca       *CertificationAuthority
	attestor *ProxyAttestor
	logger   logrus.FieldLogger
}

func NewProvider(attestor *ProxyAttestor, ca *CertificationAuthority, logger logrus.FieldLogger, host string, port int32, dnsName string) (*Provider, error) {
	sCert, sKey, err := ca.CreateCertificate(dnsName)
	if err != nil {
		return nil, err
	}

	router := mux.NewRouter()

	idp := &Provider{
		Server: http.Server{
			Addr:         fmt.Sprintf("%s:%d", host, port),
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 5 * time.Second,
			Handler:      router,
			TLSConfig: &tls.Config{
				Certificates: []tls.Certificate{
					{
						Certificate: [][]byte{sCert.Raw},
						PrivateKey:  sKey,
					},
				},
			},
		},

		router:   router,
		ca:       ca,
		attestor: attestor,
		logger:   logger,
	}

	router.HandleFunc("/health", idp.health).Methods(http.MethodGet)
	router.HandleFunc("/trust-bundle", idp.getTrustBundle).Methods(http.MethodGet)
	router.HandleFunc("/sign", idp.signCertificate).Methods(http.MethodPost)

	return idp, nil
}

func (p *Provider) health(rw http.ResponseWriter, _ *http.Request) {
	rw.WriteHeader(http.StatusOK)
}

func (p *Provider) getTrustBundle(rw http.ResponseWriter, _ *http.Request) {
	rw.WriteHeader(http.StatusOK)

	if _, err := rw.Write(p.ca.TrustBundle()); err != nil {
		p.logger.Error(err)
	}
}

func (p *Provider) signCertificate(rw http.ResponseWriter, req *http.Request) {
	certRequest := &CertificateRequest{}
	decoder := json.NewDecoder(req.Body)

	if err := decoder.Decode(certRequest); err != nil {
		http.Error(rw, "Unable to decode signing request", http.StatusBadRequest)
		return
	}

	// We first attest that the caller identity is a proxy.
	err := p.attestor.Attest(req.Context(), certRequest.Token)
	if err != nil {
		http.Error(rw, "Forbidden", http.StatusForbidden)
		return
	}

	// Then we parse and check that the CSR is valid.
	csr, err := p.ca.ParseAndValidateCertificateRequest(certRequest.CSR)
	if err != nil {
		http.Error(rw, "Invalid certificate request", http.StatusBadRequest)
		return
	}

	cert, err := p.ca.SignCertificate(csr)
	if err != nil {
		http.Error(rw, "Unable to sign certificate", http.StatusInternalServerError)
		return
	}

	if err := pem.Encode(rw, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); err != nil {
		http.Error(rw, "Unable to encode signed certificate", http.StatusInternalServerError)
	}
}
