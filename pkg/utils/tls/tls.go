// Copyright 2024 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tls

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
)

func LoadTLSCert(serverCert, serverKey string) (tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(serverCert, serverKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("loading TLS keypair: %w", err)
	}

	return cert, nil
}

func LoadTLSCA(clientCA string) (*x509.CertPool, error) {
	ca := x509.NewCertPool()
	caBytes, err := os.ReadFile(clientCA)
	if err != nil {
		return nil, fmt.Errorf("loading client CA certificate: %w", err)
	}

	if ok := ca.AppendCertsFromPEM(caBytes); !ok {
		return nil, errors.New("parsing client CA certificate")
	}

	return ca, nil
}
