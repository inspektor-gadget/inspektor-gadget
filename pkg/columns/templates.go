// Copyright 2022 The Inspektor Gadget authors
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

package columns

import (
	"fmt"
	"sync"
)

var (
	templates    = map[string]string{}
	templateLock sync.Mutex
)

// RegisterTemplate registers the column settings template in value to name. Whenever a column has "template:name" set,
// this template will be used.  Plausibility and syntax checks will only be applied when the template gets used.
func RegisterTemplate(name, value string) error {
	templateLock.Lock()
	defer templateLock.Unlock()

	if name == "" {
		return fmt.Errorf("no template name given")
	}
	if value == "" {
		return fmt.Errorf("no value given for template %q", name)
	}

	if _, ok := templates[name]; ok {
		return fmt.Errorf("template with name %q already exists", name)
	}

	templates[name] = value
	return nil
}

// MustRegisterTemplate calls RegisterTemplate and will panic if an error occurs.
func MustRegisterTemplate(name, value string) {
	err := RegisterTemplate(name, value)
	if err != nil {
		panic(err)
	}
}

// getTemplate returns a template that has previously been registered as name.
func getTemplate(name string) (string, bool) {
	templateLock.Lock()
	defer templateLock.Unlock()

	tpl, ok := templates[name]
	return tpl, ok
}
