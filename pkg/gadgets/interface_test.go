// Copyright 2019-2021 The Inspektor Gadget authors
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

import (
	"testing"
)

type fakeTraceFactory struct {
	BaseFactory

	deleted bool
}

type fakeTrace struct {
	dummy int
}

func (f *fakeTraceFactory) Operations() map[string]TraceOperation {
	return nil
}

func (f *fakeTraceFactory) DeleteTrace(name string, t interface{}) {
	f.deleted = true
}

func TestDeleteTrace(t *testing.T) {
	f := &fakeTraceFactory{}

	f.LookupOrCreate("mytrace", func() interface{} {
		return &fakeTrace{10}
	})
	f.Delete("mytrace")

	if !f.deleted {
		t.Fatalf("DeleteTrace has not been called")
	}
}
