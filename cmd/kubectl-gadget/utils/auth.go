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

package utils

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os/user"

	"k8s.io/client-go/kubernetes"

	certhelpers "github.com/inspektor-gadget/inspektor-gadget/internal/cert-helpers"
	"github.com/inspektor-gadget/inspektor-gadget/internal/certs"
)

// getTLSConfig returns a tls.Config for use with a gRPC client; node is the name of the node you connect to and
// will be verified against the certificate
func getTLSConfig(node string, clientset *kubernetes.Clientset) (*tls.Config, error) {
	name := "gadget-user"

	// Use local username if possible for certificate
	if currentUser, err := user.Current(); err == nil {
		name = currentUser.Username
	}

	cert, key, ca, err := certs.GenerateClientCertificate(context.Background(), name, clientset)
	if err != nil {
		return nil, fmt.Errorf("loading certificates: %w", err)
	}
	crt, err := tls.X509KeyPair(certhelpers.CertPEM(cert), certhelpers.PrivateKeyPEM(key))
	if err != nil {
		return nil, fmt.Errorf("loading x509 keypair: %w", err)
	}

	certPool := x509.NewCertPool()
	certPool.AddCert(ca)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{crt},
		RootCAs:      certPool,
		ServerName:   node,
	}
	return tlsConfig, nil
}
