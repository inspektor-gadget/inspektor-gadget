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

package certs

import (
	"context"
	"crypto/x509"
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	certhelpers "github.com/inspektor-gadget/inspektor-gadget/internal/cert-helpers"
)

const (
	CASecretName    = "ca"
	GadgetNamespace = "gadget" // TODO: this needs to be moved somewhere else - right now it's in cmd/kubectl-gadget/utils
)

// loadCA loads the CA cert and private key from a secret
func loadCA(ctx context.Context, clientset *kubernetes.Clientset) ([]byte, []byte, error) {
	obj, err := clientset.CoreV1().Secrets(GadgetNamespace).Get(ctx, CASecretName, metav1.GetOptions{})
	if err != nil {
		return nil, nil, fmt.Errorf("get gadget CA secret: %w", err)
	}
	return obj.Data["cert"], obj.Data["key"], nil
}

// GenerateCertificate generates a new server certificate for the node
func GenerateCertificate(ctx context.Context, node string, keyUsage x509.ExtKeyUsage, duration time.Duration, clientset *kubernetes.Clientset) ([]byte, []byte, *x509.Certificate, error) {
	caCert, caPrivateKey, err := loadCA(ctx, clientset)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("get CA: %w", err)
	}

	ca, err := x509.ParseCertificate(caCert)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse CA: %w", err)
	}

	cert, privateKey, err := certhelpers.GenerateCertificate(node, keyUsage, duration, caCert, caPrivateKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("generate server key: %w", err)
	}

	return cert, privateKey, ca, nil
}

func GenerateClientCertificate(ctx context.Context, node string, clientset *kubernetes.Clientset) ([]byte, []byte, *x509.Certificate, error) {
	return GenerateCertificate(ctx, node, x509.ExtKeyUsageClientAuth, time.Hour*24, clientset)
}

func GenerateServerCertificate(ctx context.Context, node string, clientset *kubernetes.Clientset) ([]byte, []byte, *x509.Certificate, error) {
	return GenerateCertificate(ctx, node, x509.ExtKeyUsageServerAuth, certhelpers.Year*10, clientset)
}
