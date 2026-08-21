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

package auth

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	authv1 "k8s.io/api/authentication/v1"
	authzv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
)

func TestExtractBearer(t *testing.T) {
	for _, test := range []struct {
		header string
		want   string
	}{
		{"Bearer token", "token"},
		{"bEaReR token", "token"},
		{"Basic token", ""},
		{"Bearer ", ""},
	} {
		ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(authorizationHeader, test.header))
		assert.Equal(t, test.want, extractBearer(ctx))
	}
}

func TestAuthenticateAddsPolicyScope(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "team-a"}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "team-b"}},
	)
	client.PrependReactor("create", "tokenreviews", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, &authv1.TokenReview{Status: authv1.TokenReviewStatus{
			Authenticated: true,
			User:          authv1.UserInfo{Username: "tenant"},
		}}, nil
	})
	client.PrependReactor("create", "subjectaccessreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
		review := action.(k8stesting.CreateAction).GetObject().(*authzv1.SubjectAccessReview)
		assert.Equal(t, "create", review.Spec.ResourceAttributes.Verb)
		return true, &authzv1.SubjectAccessReview{Status: authzv1.SubjectAccessReviewStatus{
			Allowed: review.Spec.ResourceAttributes.Namespace == "team-a",
		}}, nil
	})

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(authorizationHeader, "Bearer token"))
	ctx, err := authenticate(ctx, client, logger.DefaultLogger(), "test", DefaultScopeConfig())
	require.NoError(t, err)
	scope, ok := PolicyScopeFromContext(ctx)
	require.True(t, ok)
	assert.Equal(t, []string{"team-a"}, scope.AllowedNamespaces)
}

func TestAuthenticateRequiresToken(t *testing.T) {
	_, err := authenticate(context.Background(), fake.NewSimpleClientset(), logger.DefaultLogger(), "test", DefaultScopeConfig())
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}
