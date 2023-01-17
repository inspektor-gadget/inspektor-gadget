// Copyright 2022-2023 The Inspektor Gadget authors
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

type GadgetInstance interface{}

// GadgetInstantiate is the same interface as Gadget but adds one call to instantiate an actual
// tracer
type GadgetInstantiate interface {
	Gadget

	// NewInstance creates a new gadget tracer and returns it; the tracer should be allocated and configured but
	// should not run any code that depends on cleanup
	NewInstance(Runner) (GadgetInstance, error)
}
