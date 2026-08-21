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

package kubemanager

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/auth"
	kubemanagerpolicy "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/kubemanager/policy"
)

func policyContext(namespaces ...string) context.Context {
	return auth.ContextWithPolicyScope(context.Background(), auth.PolicyScope{AllowedNamespaces: namespaces})
}

func TestEnforcePolicyScopeOnParamValues(t *testing.T) {
	for _, test := range []struct {
		name     string
		allowed  []string
		values   api.ParamValues
		want     string
		wantErr  bool
		noPolicy bool
	}{
		{
			name:    "all namespaces becomes allowed namespaces",
			allowed: []string{"team-a", "team-b"},
			values:  api.ParamValues{"operator.KubeManager.all-namespaces": "true"},
			want:    "team-a,team-b",
		},
		{
			name:    "allowed list is preserved",
			allowed: []string{"team-a", "team-b"},
			values:  api.ParamValues{"operator.KubeManager.namespace": "team-b,team-a"},
			want:    "team-b,team-a",
		},
		{
			name:    "unauthorized namespace",
			allowed: []string{"team-a"},
			values:  api.ParamValues{"operator.KubeManager.namespace": "team-b"},
			want:    "team-b",
			wantErr: true,
		},
		{
			name:    "exclusion is rejected",
			allowed: []string{"team-a"},
			values:  api.ParamValues{"operator.KubeManager.namespace": "!team-b"},
			want:    "!team-b",
			wantErr: true,
		},
		{
			name:     "disabled policy preserves values",
			values:   api.ParamValues{},
			noPolicy: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := policyContext(test.allowed...)
			if test.noPolicy {
				ctx = context.Background()
			}
			err := kubemanagerpolicy.EnforcePolicyScopeOnParamValues(ctx, test.values)
			if test.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, test.want, test.values["operator.KubeManager.namespace"])
			if !test.wantErr && !test.noPolicy {
				assert.Equal(t, "true", test.values["operator.KubeManager."+kubemanagerpolicy.ParamPolicyScope])
			}
		})
	}
}

func TestAuthorizeParamValues(t *testing.T) {
	values := api.ParamValues{"operator.KubeManager.namespace": "team-a"}
	require.NoError(t, kubemanagerpolicy.AuthorizeParamValues(policyContext("team-a"), values))
	err := kubemanagerpolicy.AuthorizeParamValues(policyContext("team-b"), values)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	assert.NotContains(t, err.Error(), "team-a")
}
