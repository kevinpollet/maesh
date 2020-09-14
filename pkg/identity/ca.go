package identity

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"time"

	"github.com/spiffe/go-spiffe/spiffe"
)

const (
	defaultRSABits            = 2048
	defaultCACertValidity     = 10 * 365 * 24 * time.Hour
	defaultClientCertValidity = 30 * 24 * time.Hour
)

type CertificationAuthority struct {
	trustDomain string
	cert        *x509.Certificate
	key         *rsa.PrivateKey
}

func NewCertificationAuthority(trustDomain string) (*CertificationAuthority, error) {
	var err error

	ca := &CertificationAuthority{
		trustDomain: trustDomain,
	}

	ca.cert, ca.key, err = ca.generateCA()
	if err != nil {
		return nil, err
	}

	return ca, nil
}

func (ca *CertificationAuthority) TrustBundle() []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: ca.cert.Raw,
	})
}

func (ca *CertificationAuthority) SignCertificate(csr *x509.CertificateRequest) (*x509.Certificate, error) {
	if err := csr.CheckSignature(); err != nil {
		return nil, err
	}

	now := time.Now()
	notAfter := now.Add(defaultClientCertValidity)

	serialNumber, err := newSerialNumber()
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               csr.Subject,
		Issuer:                ca.cert.Subject,
		URIs:                  csr.URIs,
		NotBefore:             now,
		NotAfter:              notAfter,
		Signature:             csr.Signature,
		SignatureAlgorithm:    csr.SignatureAlgorithm,
		PublicKeyAlgorithm:    csr.PublicKeyAlgorithm,
		PublicKey:             csr.PublicKey,
		IPAddresses:           csr.IPAddresses,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}

	derCert, err := x509.CreateCertificate(rand.Reader, template, ca.cert, csr.PublicKey, ca.key)
	if err != nil {
		return nil, fmt.Errorf("unable to sign certificate request: %w", err)
	}

	cert, err := x509.ParseCertificate(derCert)
	if err != nil {
		return nil, fmt.Errorf("unable to signed certificate: %w", err)
	}

	return cert, nil
}

func (ca *CertificationAuthority) ParseAndValidateCertificateRequest(csrPEM string) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, errors.New("unable to decode certificate request")
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("unable to parse certificate request: %w", err)
	}

	if len(csr.URIs) != 1 {
		return nil, errors.New("certificate request must have exactly one URI SAN")
	}

	// TODO: should we check that the URI is matching: spiffe://<trust-domain>/ns/<namespace>/sa/<serviceaccount>?
	if err := spiffe.ValidateURI(csr.URIs[0], spiffe.AllowTrustDomainWorkload(ca.trustDomain)); err != nil {
		return nil, fmt.Errorf("invalid certificate request URI: %w", err)
	}

	return csr, nil
}

// TODO use a csr to create server cert?
func (ca *CertificationAuthority) CreateCertificate(dnsName string) (*x509.Certificate, *rsa.PrivateKey, error) {
	serialNumber, err := newSerialNumber()
	if err != nil {
		return nil, nil, err
	}

	keyBytes, err := rsa.GenerateKey(rand.Reader, defaultRSABits)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to generate server key: %w", err)
	}

	now := time.Now()
	notAfter := now.Add(defaultCACertValidity)

	spiffeID, err := spiffe.ParseID(fmt.Sprintf("spiffe://%s/identity", ca.trustDomain), spiffe.AllowTrustDomainWorkload(ca.trustDomain))
	if err != nil {
		return nil, nil, err
	}

	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		NotBefore:             now,
		NotAfter:              notAfter,
		URIs:                  []*url.URL{spiffeID},
		Subject:               pkix.Name{CommonName: dnsName},
		DNSNames:              []string{dnsName},
		BasicConstraintsValid: true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	derCert, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &keyBytes.PublicKey, ca.key)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to create server certifiacte: %w", err)
	}

	cert, err := x509.ParseCertificate(derCert)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to parse server certificate: %w", err)
	}

	return cert, keyBytes, nil
}

func (ca *CertificationAuthority) generateCA() (*x509.Certificate, *rsa.PrivateKey, error) {
	serialNumber, err := newSerialNumber()
	if err != nil {
		return nil, nil, err
	}

	keyBytes, err := rsa.GenerateKey(rand.Reader, defaultRSABits)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to generate ca key: %w", err)
	}

	now := time.Now()
	notAfter := now.Add(defaultCACertValidity)
	spiffeID := spiffe.TrustDomainURI(ca.trustDomain)

	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{CommonName: "Traefik Mesh"},
		URIs:                  []*url.URL{spiffeID},
		NotBefore:             now,
		NotAfter:              notAfter,
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}

	derCert, err := x509.CreateCertificate(rand.Reader, template, template, &keyBytes.PublicKey, keyBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to create ca cert: %w", err)
	}

	cert, err := x509.ParseCertificate(derCert)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to parse ca cert: %w", err)
	}

	return cert, keyBytes, nil
}

func newSerialNumber() (*big.Int, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)

	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("unable to create serial number: %w", err)
	}

	return serialNumber, nil
}
