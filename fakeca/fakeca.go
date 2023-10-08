// Package fakeca implements a fake root CA for signing fake TLS certificates.
package fakeca

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"time"
)

// FakeCA is a fake root CA for signing fake TLS certificates.
type FakeCA struct {
	PrivKey *rsa.PrivateKey
	Cert    *x509.Certificate

	PrivKeyPEM []byte
	CertPEM    []byte
}

func newName() pkix.Name {
	return pkix.Name{
		CommonName:    "Fake CA",
		Organization:  []string{"Fake CA"},
		Country:       []string{"US"},
		Province:      []string{"California"},
		Locality:      []string{"San Jose"},
		StreetAddress: []string{"First Street"},
		PostalCode:    []string{"95113"},
	}
}

// FromKeyPair converts a key pair in PEM bytes into a FakeCA.
func FromKeyPair(keyPEM, certPEM []byte) (*FakeCA, error) {
	keyDER, _ := pem.Decode(keyPEM)
	if keyDER == nil || keyDER.Type != "RSA PRIVATE KEY" {
		return nil, errors.New("invalid private key")
	}

	privKey, err := x509.ParsePKCS1PrivateKey(keyDER.Bytes)
	if err != nil {
		return nil, err
	}

	certDER, _ := pem.Decode(certPEM)
	if privKey == nil || certDER.Type != "CERTIFICATE" {
		return nil, errors.New("invalid certificate")
	}

	cert, err := x509.ParseCertificate(certDER.Bytes)
	if err != nil {
		return nil, err
	}

	return &FakeCA{
		PrivKey: privKey,
		Cert:    cert,

		PrivKeyPEM: keyPEM,
		CertPEM:    certPEM,
	}, nil
}

// NewCA returns a new fake root CA.
func NewCA() (*FakeCA, error) {
	caCert := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject:      newName(),
		NotBefore:    time.Now().AddDate(0, 0, -30),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		IsCA:         true,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,

		BasicConstraintsValid: true,
	}

	caPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, err
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, caCert, caCert, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return nil, err
	}

	caPEM := new(bytes.Buffer)
	pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})

	caPrivKeyPEM := new(bytes.Buffer)
	pem.Encode(caPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(caPrivKey),
	})

	return &FakeCA{
		PrivKey: caPrivKey,
		Cert:    caCert,

		PrivKeyPEM: caPrivKeyPEM.Bytes(),
		CertPEM:    caPEM.Bytes(),
	}, nil
}

// NewCert creates a fake certificate for the given domain names.
func (ca *FakeCA) NewCert(dnsNames []string) (certPEM, privKeyPEM []byte, err2 error) {
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1658),
		Subject:      newName(),
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:    time.Now().AddDate(0, 0, -7),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		DNSNames:     dnsNames,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	certPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		err2 = err
		return
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, ca.Cert, &certPrivKey.PublicKey, ca.PrivKey)
	if err != nil {
		err2 = err
		return
	}

	keyBuf := new(bytes.Buffer)
	pem.Encode(keyBuf, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certPrivKey),
	})

	certBuf := new(bytes.Buffer)
	if err := pem.Encode(certBuf, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes}); err != nil {
		err2 = err
		return
	}

	return certBuf.Bytes(), keyBuf.Bytes(), nil
}
