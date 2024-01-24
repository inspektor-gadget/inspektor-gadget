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

	imageOperators  = map[string]ImageOperator{}
	dataOperators   = map[string]DataOperator{}
	targetOperators = map[string]TargetOperator{}

	// imageOperatorsByMediaType is a map of mediaTypes to a map of operator names to operators
	imageOperatorsByMediaType = map[string]map[string]ImageOperator{}
)

// RegisterOperatorForMediaType registers operator for specific media types
func RegisterOperatorForMediaType(mediaType string, operator ImageOperator) {
	registryLock.Lock()
	defer registryLock.Unlock()

	imageOperators[operator.Name()] = operator

	if _, ok := imageOperatorsByMediaType[mediaType]; !ok {
		imageOperatorsByMediaType[mediaType] = make(map[string]ImageOperator)
	}
	imageOperatorsByMediaType[mediaType][operator.Name()] = operator
}

// RegisterOperator registers any DataOperator or TargetOperator; for ImageOperators,
// use RegisterOperatorForMediaType
func RegisterOperator(operator any) {
	registryLock.Lock()
	defer registryLock.Unlock()

	registered := false

	if op, ok := operator.(DataOperator); ok {
		dataOperators[op.Name()] = op
		registered = true
	}
	if op, ok := operator.(TargetOperator); ok {
		targetOperators[op.Name()] = op
		registered = true
	}

	if !registered {
		panic("invalid operator")
	}
}

func GetDataOperators() map[string]DataOperator {
	registryLock.Lock()
	defer registryLock.Unlock()
	return maps.Clone(dataOperators)
}

// GetImageOperatorsForMediaType returns a copy of the map of operators matching the given
// media type
func GetImageOperatorsForMediaType(mediaType string) map[string]ImageOperator {
	registryLock.Lock()
	defer registryLock.Unlock()

	res := make(map[string]ImageOperator)
	if ops, ok := imageOperatorsByMediaType[mediaType]; ok {
		for k, v := range ops {
			res[k] = v
		}
	}
	return res
}
