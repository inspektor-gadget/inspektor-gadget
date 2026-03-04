// Copyright 2023 The Inspektor Gadget authors
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

package gadgets

import "github.com/inspektor-gadget/inspektor-gadget/pkg/params"

const (
	LocalContainer   params.ValueHint = "local:container"
	LocalImageDigest params.ValueHint = "local:image-digest"
	LocalImageID     params.ValueHint = "local:image-id"
	K8SNodeName      params.ValueHint = "k8s:node"
	K8SNodeList      params.ValueHint = "k8s:node-list"
	K8SPodName       params.ValueHint = "k8s:pod"
	K8SNamespace     params.ValueHint = "k8s:namespace"
	K8SContainerName params.ValueHint = "k8s:container"
	K8SLabels        params.ValueHint = "k8s:labels"
)
