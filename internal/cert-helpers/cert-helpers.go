// Copyright 2022 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package certhelpers

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

const (
	Year = time.Hour * 24 * 365
)

func PrivateKeyPEM(key []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key})
}

func CertPEM(key []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: key})
}

func X509CertificateFromDER(der []byte) (*x509.Certificate, error) {
	return x509.ParseCertificate(der)
}

// GenerateCA generates a new certificate authority for inspektor gadget. This is used to create server
// and client certificates to communicate via gRPC
func GenerateCA() ([]byte, []byte, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generating keypair: %w", err)
	}

	now := time.Now()

	tpl := &x509.Certificate{
		SerialNumber: new(big.Int).SetInt64(0),
		Subject: pkix.Name{
			CommonName: "inspektor-gadget-ca",
		},
		DNSNames:              []string{"inspektor-gadget-ca"},
		NotBefore:             now.UTC(),
		NotAfter:              now.Add(Year * 10).UTC(), // 10 years
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tpl, tpl, privateKey.Public(), privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("self-signing cert: %w", err)
	}

	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("self-signing cert: %w", err)
	}

	return certDER, privateKeyDER, nil
}

// GenerateCertificate generates a new private key and a certificate signed by the given CA
func GenerateCertificate(name string, usage x509.ExtKeyUsage, validFor time.Duration, caCertDER, caPrivateKeyDER []byte) ([]byte, []byte, error) {
	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		return nil, nil, fmt.Errorf("reading CA certificate: %w", err)
	}

	caPrivateKey, err := x509.ParsePKCS8PrivateKey(caPrivateKeyDER)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing CA private key: %w", err)
	}

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generating keypair: %w", err)
	}

	now := time.Now()

	tpl := &x509.Certificate{
		SerialNumber: new(big.Int).SetInt64(0),
		Subject: pkix.Name{
			CommonName: name,
		},
		DNSNames:    []string{name},
		NotBefore:   now.UTC(),
		NotAfter:    now.Add(validFor).UTC(),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{usage},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tpl, caCert, privateKey.Public(), caPrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("signing cert: %w", err)
	}

	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("self-signing cert: %w", err)
	}

	return certDER, privateKeyDER, nil
}
