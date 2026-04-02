// Copyright 2026 The Inspektor Gadget authors
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

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const (
	secretName    = "gadget-kubelet-certificate"
	secretKey     = "ca.crt"
	kubeletPort   = "10250"
	namespaceFile = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
)

func main() {
	hostIP := os.Getenv("HOST_IP")
	if hostIP == "" {
		log.Fatal("HOST_IP environment variable is not set")
	}

	log.Printf("Connecting to kubelet at %s:%s ...", hostIP, kubeletPort)

	pemData, err := getKubeletCACert(hostIP)
	if err != nil {
		log.Fatalf("Failed to get kubelet CA cert: %v", err)
	}

	log.Printf("Extracted certificate:\n%s", pemData)

	if err := saveToSecret(pemData); err != nil {
		log.Fatalf("Failed to save secret: %v", err)
	}

	log.Println("Done.")
}

func getKubeletCACert(hostIP string) ([]byte, error) {
	addr := net.JoinHostPort(hostIP, kubeletPort)

	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return nil, fmt.Errorf("TLS dial %s: %w", addr, err)
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, fmt.Errorf("no peer certificates received from %s", addr)
	}

	log.Printf("Received %d certificate(s) in chain:", len(certs))
	for i, c := range certs {
		log.Printf("  [%d] Subject:  %s", i, c.Subject)
		log.Printf("       Issuer:   %s", c.Issuer)
		log.Printf("       IsCA:     %v", c.IsCA)
		log.Printf("       NotBefore: %s", c.NotBefore)
		log.Printf("       NotAfter:  %s", c.NotAfter)
		log.Printf("       DNS Names: %s", strings.Join(c.DNSNames, ", "))
	}

	// Last cert in the chain is the root / highest CA
	ca := certs[len(certs)-1]
	if !ca.IsCA {
		log.Printf("WARNING: selected certificate (index %d) is not marked as CA", len(certs)-1)
	}

	var buf bytes.Buffer
	if err := pem.Encode(&buf, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: ca.Raw,
	}); err != nil {
		return nil, fmt.Errorf("PEM encode: %w", err)
	}

	return buf.Bytes(), nil
}

func saveToSecret(pemData []byte) error {
	config, err := rest.InClusterConfig()
	if err != nil {
		return fmt.Errorf("in-cluster config: %w", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("create clientset: %w", err)
	}

	nsBytes, err := os.ReadFile(namespaceFile)
	if err != nil {
		return fmt.Errorf("read namespace: %w", err)
	}
	namespace := strings.TrimSpace(string(nsBytes))

	log.Printf("Using namespace: %s", namespace)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	secretsClient := clientset.CoreV1().Secrets(namespace)

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: namespace,
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			secretKey: pemData,
		},
	}

	existing, err := secretsClient.Get(ctx, secretName, metav1.GetOptions{})
	if k8serrors.IsNotFound(err) {
		log.Printf("Creating secret %s/%s ...", namespace, secretName)
		_, err = secretsClient.Create(ctx, secret, metav1.CreateOptions{})
		if k8serrors.IsAlreadyExists(err) {
			// Race: another instance created it between our Get and Create
			log.Printf("Secret was created concurrently, updating instead ...")
			existing, err = secretsClient.Get(ctx, secretName, metav1.GetOptions{})
			if err != nil {
				return fmt.Errorf("re-get secret: %w", err)
			}
			existing.Data = secret.Data
			_, err = secretsClient.Update(ctx, existing, metav1.UpdateOptions{})
		}
		if err != nil {
			return fmt.Errorf("create secret: %w", err)
		}
		log.Printf("Secret %s/%s created.", namespace, secretName)
		return nil
	}
	if err != nil {
		return fmt.Errorf("get secret: %w", err)
	}

	log.Printf("Updating existing secret %s/%s ...", namespace, secretName)
	existing.Data = secret.Data
	if _, err := secretsClient.Update(ctx, existing, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("update secret: %w", err)
	}
	log.Printf("Secret %s/%s updated.", namespace, secretName)
	return nil
}
