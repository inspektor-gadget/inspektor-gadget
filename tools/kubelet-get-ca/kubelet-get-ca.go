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
		log.Printf("  [%d] Subject: %s  Issuer: %s  IsCA: %v",
							 i, c.Subject, c.Issuer, c.IsCA)
	}

	// Store ALL certificates from the chain.
	// This mirrors what kubelet CA files (e.g. minikube's ca.crt) contain:
	// the full trust chain needed to verify the TLS connection.
	var buf bytes.Buffer
	for _, c := range certs {
		if err := pem.Encode(&buf, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: c.Raw,
		}); err != nil {
			return nil, fmt.Errorf("PEM encode: %w", err)
		}
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

	log.Printf("Creating secret %s/%s ...", namespace, secretName)
	_, err = secretsClient.Create(ctx, secret, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("create secret: %w", err)
	}

	log.Printf("Secret %s/%s created.", namespace, secretName)
	return nil
}
