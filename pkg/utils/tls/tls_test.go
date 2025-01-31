// Copyright 2025 The Inspektor Gadget authors
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

package tls

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"testing"
	"time"
)

func generateTestCert(t *testing.T, validFor time.Duration) (certFile, keyFile string) {
	t.Helper()

	certFile = mustTempFile(t)
	keyFile = mustTempFile(t)

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	now := time.Now()
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-cert"},
		NotBefore:             now,
		NotAfter:              now.Add(validFor),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	certOut, err := os.Create(certFile)
	if err != nil {
		t.Fatalf("Failed to create cert file: %v", err)
	}
	defer certOut.Close()
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyOut, err := os.Create(keyFile)
	if err != nil {
		t.Fatalf("Failed to create key file: %v", err)
	}
	defer keyOut.Close()
	pem.Encode(keyOut, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	return certFile, keyFile
}

func TestLoadTLSCert(t *testing.T) {
	t.Run("valid certificate", func(t *testing.T) {
		certFile, keyFile := generateTestCert(t, 1*time.Hour)
		defer os.Remove(certFile)
		defer os.Remove(keyFile)

		cert, err := LoadTLSCert(certFile, keyFile)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if len(cert.Certificate) == 0 {
			t.Error("Expected certificate data, got empty")
		}
	})

	t.Run("missing certificate file", func(t *testing.T) {
		_, err := LoadTLSCert("nonexistent.crt", "test.key")
		if err == nil {
			t.Fatal("Expected error for missing certificate file")
		}
	})

	t.Run("invalid certificate format", func(t *testing.T) {
		f := mustTempFile(t)
		defer os.Remove(f)
		os.WriteFile(f, []byte("invalid data"), 0644)

		_, err := LoadTLSCert(f, "test.key")
		if err == nil {
			t.Fatal("Expected error for invalid certificate format")
		}
	})

	t.Run("expired certificate", func(t *testing.T) {
		certFile, keyFile := generateTestCert(t, -1*time.Hour)
		defer os.Remove(certFile)
		defer os.Remove(keyFile)

		cert, err := LoadTLSCert(certFile, keyFile)
		if err != nil {
			t.Fatalf("Unexpected error loading expired certificate: %v", err)
		}

		x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			t.Fatalf("Failed to parse certificate: %v", err)
		}

		if time.Now().Before(x509Cert.NotAfter) {
			t.Error("Certificate should be expired but is still valid")
		}
	})

	t.Run("valid PEM with invalid certificate content", func(t *testing.T) {
		f := mustTempFile(t)
		defer os.Remove(f)

		block := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: []byte("invalid certificate content"),
		}
		pemData := pem.EncodeToMemory(block)
		if err := os.WriteFile(f, pemData, 0644); err != nil {
			t.Fatalf("Failed to write PEM file: %v", err)
		}

		keyFile := mustTempFile(t)
		defer os.Remove(keyFile)
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("Failed to generate private key: %v", err)
		}
		keyOut, err := os.Create(keyFile)
		if err != nil {
			t.Fatalf("Failed to create key file: %v", err)
		}
		defer keyOut.Close()
		pem.Encode(keyOut, &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
		})

		_, err = LoadTLSCert(f, keyFile)
		if err == nil {
			t.Fatal("Expected error for invalid certificate content in valid PEM")
		}
	})
}

func TestLoadTLSCA(t *testing.T) {
	t.Run("valid CA certificate", func(t *testing.T) {
		certFile, _ := generateTestCert(t, 1*time.Hour)
		defer os.Remove(certFile)

		pool, err := LoadTLSCA(certFile)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if pool == nil {
			t.Error("Expected valid cert pool, got nil")
		}
	})

	t.Run("missing CA file", func(t *testing.T) {
		_, err := LoadTLSCA("nonexistent.crt")
		if err == nil {
			t.Fatal("Expected error for missing CA file")
		}
	})

	t.Run("invalid CA data", func(t *testing.T) {
		f := mustTempFile(t)
		defer os.Remove(f)
		os.WriteFile(f, []byte("invalid data"), 0644)

		_, err := LoadTLSCA(f)
		if err == nil {
			t.Fatal("Expected error for invalid CA data")
		}
	})
}

func mustTempFile(t *testing.T) string {
	t.Helper()
	f, err := os.CreateTemp("", "testfile")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	f.Close()
	return f.Name()
}
