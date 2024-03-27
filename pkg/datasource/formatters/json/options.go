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

package json

type Option func(*Formatter)

// WithFields specifies exactly which fields to export using this formatter;
// field names can be prefixed with +/- to add or remove the field from the
// output - if all fields are prefixed, the default visible fields will be
// honored, otherwise only the fields specified will be considered. If fields
// is nil, the default will be used - if fields is empty, no field will
// be returned.
func WithFields(fields []string) Option {
	return func(formatter *Formatter) {
		formatter.fields = fields
		if fields != nil {
			formatter.useDefault = false
		}
	}
}

func WithShowAll(val bool) Option {
	return func(formatter *Formatter) {
		formatter.showAll = val
		formatter.useDefault = true
	}
}
