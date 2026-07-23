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

package policy

import (
	"context"
	"slices"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/auth"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/common"
)

const (
	ParamAllNamespaces  = "all-namespaces"
	ParamPolicyScope    = "multi-tenancy-policy"
	operatorParamPrefix = "operator.KubeManager."
)

func requestedNamespaces(values api.ParamValues, prefix string) ([]string, bool, error) {
	if strings.EqualFold(values[prefix+ParamAllNamespaces], "true") {
		return nil, true, nil
	}
	namespace := values[prefix+common.ParamNamespace]
	if namespace == "" {
		namespace = values[prefix+common.ParamK8sNamespace]
	}
	if namespace == "" {
		namespace = "default"
	}
	if strings.Contains(namespace, "!") {
		return nil, false, status.Errorf(codes.InvalidArgument, "namespace exclusions are not supported in multi-tenancy mode: %q", namespace)
	}
	namespaces := strings.Split(namespace, ",")
	for i := range namespaces {
		namespaces[i] = strings.TrimSpace(namespaces[i])
		if namespaces[i] == "" {
			return nil, false, status.Errorf(codes.InvalidArgument, "invalid namespace filter %q", namespace)
		}
	}
	return namespaces, false, nil
}

func authorizeNamespaces(scope auth.PolicyScope, namespaces []string) error {
	if len(scope.AllowedNamespaces) == 0 {
		return status.Error(codes.PermissionDenied, "no Kubernetes namespaces are authorized for this request")
	}
	for _, namespace := range namespaces {
		if !slices.Contains(scope.AllowedNamespaces, namespace) {
			return status.Error(codes.PermissionDenied, "requested Kubernetes namespace is not authorized")
		}
	}
	return nil
}

func enforcePolicyScope(scope auth.PolicyScope, values api.ParamValues, prefix string) error {
	namespaces, all, err := requestedNamespaces(values, prefix)
	if err != nil {
		return err
	}
	if all {
		namespaces = scope.AllowedNamespaces
	}
	if err := authorizeNamespaces(scope, namespaces); err != nil {
		return err
	}
	values[prefix+ParamAllNamespaces] = "false"
	values[prefix+common.ParamNamespace] = strings.Join(namespaces, ",")
	values[prefix+ParamPolicyScope] = "true"
	delete(values, prefix+common.ParamK8sNamespace)
	return nil
}

func EnforcePolicyScopeOnParamValues(ctx context.Context, values api.ParamValues) error {
	scope, ok := auth.PolicyScopeFromContext(ctx)
	if !ok {
		return nil
	}
	return enforcePolicyScope(scope, values, operatorParamPrefix)
}

func EnforcePolicyScopeFromContext(ctx context.Context, values api.ParamValues) error {
	scope, ok := auth.PolicyScopeFromContext(ctx)
	if !ok {
		return nil
	}
	return enforcePolicyScope(scope, values, "")
}

func AuthorizeParamValues(ctx context.Context, values api.ParamValues) error {
	scope, ok := auth.PolicyScopeFromContext(ctx)
	if !ok {
		return nil
	}
	namespaces, all, err := requestedNamespaces(values, operatorParamPrefix)
	if err != nil {
		return err
	}
	if all {
		return status.Error(codes.PermissionDenied, "all-namespaces gadget instances are not allowed in multi-tenancy mode")
	}
	return authorizeNamespaces(scope, namespaces)
}
