package identity

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

const (
	defaultTickerInterval              = 5 * time.Second
	defaultServiceAccountTokenFilePath = "/var/run/secrets/kubernetes.io/serviceaccount/token"
)

type Agent struct {
	mu     sync.Mutex
	stopCh chan struct{}

	spiffeID  string
	issuerURL string
	cert      *x509.Certificate
	logger    logrus.FieldLogger
}

func NewAgent(logger logrus.FieldLogger, trustDomain, namespace, serviceAccountName, issuerURL string) *Agent {
	return &Agent{
		stopCh:    make(chan struct{}),
		spiffeID:  fmt.Sprintf("spiffe://%s/ns/%s/sa/%s", trustDomain, namespace, serviceAccountName),
		issuerURL: issuerURL,
		logger:    logger,
	}
}

func (a *Agent) Run() error {
	ticker := time.NewTicker(defaultTickerInterval)
	defer ticker.Stop()

	for {
		select {
		case <-a.stopCh:
		case <-ticker.C:
			trustBundle, err := a.fetchTrustBundle()
			if err != nil {
				return err
			}

			csr, _, err := CreateCertificateRequest(a.spiffeID)
			if err != nil {
				return err
			}

			cert, err := a.sendCertificateRequest(trustBundle, csr)
			if err != nil {
				return err
			}

			a.logger.Debugf("Certificate received for: %s", cert.URIs[0])
		}
	}
}

func (a *Agent) Shutdown() {
	a.mu.Lock()
	defer a.mu.Unlock()

	select {
	case <-a.stopCh:
		// Already closed. Don't close again.
	default:
		// Safe to close. We're the only closer, guarded by c.mu.
		close(a.stopCh)
	}
}

func (a *Agent) fetchTrustBundle() ([]byte, error) {
	httpClient := http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	res, err := httpClient.Get(a.issuerURL + "/trust-bundle")
	if err != nil {
		return nil, fmt.Errorf("unable to fetch trust bundle: %w", err)
	}

	defer res.Body.Close()

	trustBundle, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("unable to read trust bundle: %w", err)
	}

	return trustBundle, nil
}

func (a *Agent) sendCertificateRequest(trustBundle []byte, csr *x509.CertificateRequest) (*x509.Certificate, error) {
	token, err := ioutil.ReadFile(defaultServiceAccountTokenFilePath)
	if err != nil {
		return nil, err
	}

	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(trustBundle)

	client := http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: certPool,
			},
		},
	}

	csrBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csr.Raw,
	})

	bodyBytes, err := json.Marshal(&CertificateRequest{Token: string(token), CSR: string(csrBytes)})
	if err != nil {
		return nil, fmt.Errorf("unable to mashal certificate request: %w", err)
	}

	res, err := client.Post(a.issuerURL+"/sign", "application/json", bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("unable to post certificate request: %w", err)
	}

	cert, err := ParsePEMCertificate(res.Body)
	if err != nil {
		return nil, fmt.Errorf("unable to parse signed certificate: %w", err)
	}

	return cert, nil

}
