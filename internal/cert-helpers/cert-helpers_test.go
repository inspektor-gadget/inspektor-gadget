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
	"crypto/tls"
	"crypto/x509"
	"testing"
)

func TestCerts(t *testing.T) {
	caCert, caPrivateKey, err := GenerateCA()
	if err != nil {
		t.Fatal(err)
	}
	serverCert, serverPrivateKey, err := GenerateCertificate("server", x509.ExtKeyUsageServerAuth, Year, caCert, caPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	clientCert, clientPrivateKey, err := GenerateCertificate("client", x509.ExtKeyUsageClientAuth, Year, caCert, caPrivateKey)
	if err != nil {
		t.Fatal(err)
	}

	ca, err := x509.ParseCertificate(caCert)
	if err != nil {
		t.Fatal(err)
	}

	server, err := x509.ParseCertificate(serverCert)
	if err != nil {
		t.Fatal(err)
	}

	client, err := x509.ParseCertificate(clientCert)
	if err != nil {
		t.Fatal(err)
	}

	if err := server.CheckSignatureFrom(ca); err != nil {
		t.Errorf("checking server signature: %v", err)
	}
	if err := client.CheckSignatureFrom(ca); err != nil {
		t.Errorf("checking server signature: %v", err)
	}

	_, err = tls.X509KeyPair(CertPEM(clientCert), PrivateKeyPEM(clientPrivateKey))
	if err != nil {
		t.Errorf("loading client key pair: %v", err)
	}
	_, err = tls.X509KeyPair(CertPEM(serverCert), PrivateKeyPEM(serverPrivateKey))
	if err != nil {
		t.Errorf("loading server key pair: %v", err)
	}
}
