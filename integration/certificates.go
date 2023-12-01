package integration

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"time"
)

func writeSelfSignedCerts(host string, caFile, keyFile io.Writer) error {
	ca := &x509.Certificate{
		Subject:               pkix.Name{CommonName: host},
		DNSNames:              []string{host},
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	privKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return err
	}

	b, err := x509.CreateCertificate(rand.Reader, ca, ca, &privKey.PublicKey, privKey)
	if err != nil {
		return err
	}

	if err = pem.Encode(caFile, &pem.Block{Type: "CERTIFICATE", Bytes: b}); err != nil {
		return err
	}

	if b, err = x509.MarshalPKCS8PrivateKey(privKey); err == nil {
		err = pem.Encode(keyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: b})
	}
	return err
}
