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

package datasource

import "sync"

var (
	annotationMutex             sync.Mutex
	annotationTemplateCallbacks []func(string, map[string]string) bool
)

func init() {
	annotationTemplateCallbacks = make([]func(string, map[string]string) bool, 0)
}

func RegisterAnnotationTemplateCallback(cb func(string, map[string]string) bool) {
	annotationMutex.Lock()
	defer annotationMutex.Unlock()
	annotationTemplateCallbacks = append(annotationTemplateCallbacks, cb)
}

func ApplyAnnotationTemplates(name string, annotations map[string]string) bool {
	annotationMutex.Lock()
	defer annotationMutex.Unlock()

	handled := false
	for _, cb := range annotationTemplateCallbacks {
		if ok := cb(name, annotations); ok {
			handled = true
		}
	}
	return handled
}
