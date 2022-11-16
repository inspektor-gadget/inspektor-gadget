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

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"k8s.io/client-go/kubernetes"
	controllerruntime "sigs.k8s.io/controller-runtime"

	certhelpers "github.com/inspektor-gadget/inspektor-gadget/internal/cert-helpers"
	"github.com/inspektor-gadget/inspektor-gadget/internal/certs"
)

func streamInterceptor() func(srv interface{}, serverStream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	return func(srv interface{}, serverStream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		p, ok := peer.FromContext(serverStream.Context())
		if !ok {
			return status.Errorf(codes.Unauthenticated, "invalid certificate")
		}
		tlsInfo := p.AuthInfo.(credentials.TLSInfo)
		subject := tlsInfo.State.VerifiedChains[0][0].Subject
		log.Infof("stream request from %s", subject)
		return handler(srv, serverStream)
	}
}

func unaryInterceptor() func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
		p, ok := peer.FromContext(ctx)
		if !ok {
			return nil, status.Errorf(codes.Unauthenticated, "invalid certificate")
		}
		tlsInfo := p.AuthInfo.(credentials.TLSInfo)
		subject := tlsInfo.State.VerifiedChains[0][0].Subject
		log.Infof("request from %s", subject)
		return handler(ctx, req)
	}
}

// getTLSConfig returns a tls.Config for use with a gRPC endpoint; this also enables
// client verification by checking client certificates against our CA
func getTLSConfig(node string) (*tls.Config, error) {
	cfg := controllerruntime.GetConfigOrDie()
	clientset := kubernetes.NewForConfigOrDie(cfg)

	cert, key, ca, err := certs.GenerateServerCertificate(context.Background(), node, clientset)
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
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    certPool,
	}
	return tlsConfig, nil
}
