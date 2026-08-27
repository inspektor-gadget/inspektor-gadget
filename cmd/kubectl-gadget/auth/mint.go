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

// Package auth mints audience-scoped Kubernetes ServiceAccount tokens for
// authenticating kubectl-gadget to a multi-tenant gadget service.
package auth

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"
	authv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	serviceauth "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/auth"
	grpcruntime "github.com/inspektor-gadget/inspektor-gadget/pkg/runtime/grpc"
)

const (
	flagAuthServiceAccount  = "auth-service-account"
	flagAuthTokenExpiration = "auth-token-expiration"
)

type Options struct {
	ServiceAccount string
	Expiration     time.Duration
}

func AddFlags(cmd *cobra.Command) *Options {
	o := &Options{}
	cmd.PersistentFlags().StringVar(&o.ServiceAccount, flagAuthServiceAccount, "",
		"ServiceAccount used to authenticate to the gadget service, in the form <namespace>/<name>.")
	cmd.PersistentFlags().DurationVar(&o.Expiration, flagAuthTokenExpiration, time.Hour,
		"Requested lifetime of the audience-scoped token.")
	return o
}

func MintToken(ctx context.Context, restCfg *rest.Config, namespace, name string, expiration time.Duration) (string, error) {
	if expiration <= 0 {
		return "", fmt.Errorf("--%s must be positive", flagAuthTokenExpiration)
	}
	client, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		return "", fmt.Errorf("building Kubernetes client: %w", err)
	}
	expirationSeconds := int64(expiration.Seconds())
	request, err := client.CoreV1().ServiceAccounts(namespace).CreateToken(ctx, name, &authv1.TokenRequest{
		Spec: authv1.TokenRequestSpec{
			Audiences:         []string{serviceauth.Audience},
			ExpirationSeconds: &expirationSeconds,
		},
	}, metav1.CreateOptions{})
	if err != nil {
		return "", fmt.Errorf("creating token for ServiceAccount %s/%s: %w", namespace, name, err)
	}
	if request.Status.Token == "" {
		return "", fmt.Errorf("kube-apiserver returned an empty token for %s/%s", namespace, name)
	}
	return request.Status.Token, nil
}

func parseServiceAccount(value string) (string, string, error) {
	namespace, name, ok := strings.Cut(value, "/")
	if !ok || namespace == "" || name == "" || strings.Contains(name, "/") {
		return "", "", fmt.Errorf("--%s=%q is not in the form <namespace>/<name>", flagAuthServiceAccount, value)
	}
	return namespace, name, nil
}

func MaybeMintAndApply(ctx context.Context, restCfg *rest.Config, runtime *grpcruntime.Runtime, o *Options) error {
	if o.ServiceAccount == "" {
		return nil
	}
	namespace, name, err := parseServiceAccount(o.ServiceAccount)
	if err != nil {
		return err
	}
	token, err := MintToken(ctx, restCfg, namespace, name, o.Expiration)
	if err != nil {
		return err
	}
	runtime.SetAuthToken(token)
	return nil
}
