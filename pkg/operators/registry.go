// Copyright 2024 The Inspektor Gadget authors
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

package operators

import (
	"maps"
	"sync"
)

var (
	registryLock sync.Mutex

	dataOperators = map[string]DataOperator{}

	// imageOperatorsByMediaType is a map of mediaTypes to operators
	imageOperatorsByMediaType = map[string]ImageOperator{}
)

// RegisterOperatorForMediaType registers operators for specific media types
func RegisterOperatorForMediaType(mediaType string, operator ImageOperator) {
	registryLock.Lock()
	defer registryLock.Unlock()

	imageOperatorsByMediaType[mediaType] = operator
}

// RegisterDataOperator registers a DataOperator
func RegisterDataOperator(operator DataOperator) {
	registryLock.Lock()
	defer registryLock.Unlock()
	dataOperators[operator.Name()] = operator
}

func GetDataOperators() map[string]DataOperator {
	registryLock.Lock()
	defer registryLock.Unlock()
	return maps.Clone(dataOperators)
}

// GetImageOperatorForMediaType returns a copy of the map of operators matching the given
// media type
func GetImageOperatorForMediaType(mediaType string) (ImageOperator, bool) {
	registryLock.Lock()
	defer registryLock.Unlock()

	op, ok := imageOperatorsByMediaType[mediaType]
	return op, ok
}
