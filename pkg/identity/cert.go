package identity

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/url"

	"github.com/spiffe/go-spiffe/spiffe"
)

func CreateCertificateRequest(spiffeID string) (*x509.CertificateRequest, *rsa.PrivateKey, error) {
	keyBytes, err := rsa.GenerateKey(rand.Reader, defaultRSABits)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to generate RSA key pair: %w", err)
	}

	spiffeURL, err := spiffe.ParseID(spiffeID, spiffe.AllowAnyTrustDomainWorkload())
	if err != nil {
		return nil, nil, err
	}

	template := &x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: "Traefik Mesh Proxy"},
		SignatureAlgorithm: x509.SHA256WithRSA,
		URIs:               []*url.URL{spiffeURL},
	}

	derCSR, err := x509.CreateCertificateRequest(rand.Reader, template, keyBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to create certificate request: %w", err)
	}

	csr, err := x509.ParseCertificateRequest(derCSR)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to parse certificate request: %w", err)
	}

	return csr, keyBytes, nil
}

func ParsePEMCertificate(reader io.ReadCloser) (*x509.Certificate, error) {
	defer reader.Close()

	pemCert, err := ioutil.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("unable to read PEM bytes: %w", err)
	}

	block, _ := pem.Decode(pemCert)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("unable to decode PEM certificate")
	}

	return x509.ParseCertificate(block.Bytes)
}
