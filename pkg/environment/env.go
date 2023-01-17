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

// Package environment is a temporary workaround to have a simple means of
// knowing what environment we're running in. It's supposed to be set by the
// main.go of local-gadget and kubectl-gadget respectively. Right now this
// is only used to distinguish whether we can rely on and should show the contents
// of the `container` column for network related gadgets.
package environment

type Type int

const (
	Undefined Type = iota
	Kubernetes
	Local
)

var Environment Type
