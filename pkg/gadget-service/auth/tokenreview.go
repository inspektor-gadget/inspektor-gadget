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

// Package auth authenticates gadget service requests with Kubernetes.
package auth

import (
	"context"
	"fmt"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	authv1 "k8s.io/api/authentication/v1"
	authzv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
)

const Audience = "inspektor-gadget"

const authorizationHeader = "authorization"

type ScopeConfig struct {
	APIGroup string
	Resource string
	Verb     string
}

func DefaultScopeConfig() ScopeConfig {
	return ScopeConfig{Resource: "pods", Verb: "create"}
}

type PolicyScope struct {
	// A nil slice means namespace policy is disabled. A non-nil empty slice
	// means the caller is authenticated but has no authorized namespaces.
	AllowedNamespaces []string
}

type policyScopeContextKey struct{}

func ContextWithPolicyScope(ctx context.Context, scope PolicyScope) context.Context {
	return context.WithValue(ctx, policyScopeContextKey{}, scope)
}

func WithoutPolicyScope(ctx context.Context) context.Context {
	// Shadow any scope inherited from ctx while gadget metadata is inspected.
	return context.WithValue(ctx, policyScopeContextKey{}, PolicyScope{})
}

func PolicyScopeFromContext(ctx context.Context) (PolicyScope, bool) {
	scope, ok := ctx.Value(policyScopeContextKey{}).(PolicyScope)
	return scope, ok && scope.AllowedNamespaces != nil
}

func extractBearer(ctx context.Context) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}
	for _, value := range md.Get(authorizationHeader) {
		scheme, token, ok := strings.Cut(value, " ")
		if ok && strings.EqualFold(scheme, "bearer") && token != "" {
			return token
		}
	}
	return ""
}

func allowedNamespaces(ctx context.Context, client kubernetes.Interface, user authv1.UserInfo, scope ScopeConfig) ([]string, error) {
	namespaces, err := client.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("listing namespaces: %w", err)
	}

	// Kubernetes has no bulk SubjectAccessReview, so resolve the configured
	// permission independently for each namespace and fail closed on errors.
	allowed := make([]string, 0, len(namespaces.Items))
	for _, namespace := range namespaces.Items {
		review, err := client.AuthorizationV1().SubjectAccessReviews().Create(ctx, &authzv1.SubjectAccessReview{
			Spec: authzv1.SubjectAccessReviewSpec{
				User:   user.Username,
				UID:    user.UID,
				Groups: user.Groups,
				Extra:  convertExtra(user.Extra),
				ResourceAttributes: &authzv1.ResourceAttributes{
					Namespace: namespace.Name,
					Verb:      scope.Verb,
					Group:     scope.APIGroup,
					Resource:  scope.Resource,
				},
			},
		}, metav1.CreateOptions{})
		if err != nil {
			return nil, fmt.Errorf("reviewing namespace %q: %w", namespace.Name, err)
		}
		if review.Status.Allowed {
			allowed = append(allowed, namespace.Name)
		}
	}
	return allowed, nil
}

func convertExtra(extra map[string]authv1.ExtraValue) map[string]authzv1.ExtraValue {
	if len(extra) == 0 {
		return nil
	}
	converted := make(map[string]authzv1.ExtraValue, len(extra))
	for key, value := range extra {
		converted[key] = authzv1.ExtraValue(value)
	}
	return converted
}

func authenticate(ctx context.Context, client kubernetes.Interface, log logger.Logger, method string, scope ScopeConfig) (context.Context, error) {
	token := extractBearer(ctx)
	if token == "" {
		return ctx, status.Error(codes.Unauthenticated, "missing bearer token")
	}
	// Restrict TokenReview to the gadget audience so ordinary ServiceAccount
	// tokens cannot be replayed against this service.
	review, err := client.AuthenticationV1().TokenReviews().Create(ctx, &authv1.TokenReview{
		Spec: authv1.TokenReviewSpec{
			Token:     token,
			Audiences: []string{Audience},
		},
	}, metav1.CreateOptions{})
	if err != nil {
		return ctx, status.Errorf(codes.Unavailable, "token review failed: %v", err)
	}
	if !review.Status.Authenticated {
		return ctx, status.Error(codes.Unauthenticated, "token was not authenticated")
	}

	allowed, err := allowedNamespaces(ctx, client, review.Status.User, scope)
	if err != nil {
		return ctx, status.Errorf(codes.Unavailable, "resolving namespace access: %v", err)
	}
	log.Debugf("auth: %s: user=%q allowedNamespaces=%v", method, review.Status.User.Username, allowed)
	return ContextWithPolicyScope(ctx, PolicyScope{AllowedNamespaces: allowed}), nil
}

func UnaryInterceptor(client kubernetes.Interface, log logger.Logger, scope ScopeConfig) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		ctx, err := authenticate(ctx, client, log, info.FullMethod, scope)
		if err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}
}

func StreamInterceptor(client kubernetes.Interface, log logger.Logger, scope ScopeConfig) grpc.StreamServerInterceptor {
	return func(srv any, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		ctx, err := authenticate(stream.Context(), client, log, info.FullMethod, scope)
		if err != nil {
			return err
		}
		return handler(srv, &serverStreamWithContext{ServerStream: stream, ctx: ctx})
	}
}

type serverStreamWithContext struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *serverStreamWithContext) Context() context.Context {
	// gRPC stream handlers read their context from the stream rather than from
	// a separate argument, so preserve the authenticated scope in this wrapper.
	return s.ctx
}
