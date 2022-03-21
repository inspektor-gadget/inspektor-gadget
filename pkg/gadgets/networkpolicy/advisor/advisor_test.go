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

package advisor

import (
	"errors"
	"io/ioutil"
	"path/filepath"
	"runtime"
	"testing"
)

func TestLoad(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	dir := filepath.Dir(filename)
	match, err := filepath.Glob(filepath.Join(dir, "testdata/*.input"))
	if err != nil {
		t.Fatal(err)
	}
	if len(match) == 0 {
		t.Fatal(errors.New("no files found in testdata"))
	}

	for _, inputFile := range match {

		a := NewAdvisor()

		err := a.LoadFile(inputFile)
		if err != nil {
			t.Fatal(err)
		}
		a.GeneratePolicies()
		generatedOuput := a.FormatPolicies()

		goldenFile := inputFile[:len(inputFile)-len(".input")] + ".golden"
		goldenOutputBytes, err := ioutil.ReadFile(goldenFile)
		if err != nil {
			t.Fatal(err)
		}
		goldenOutput := string(goldenOutputBytes)

		if generatedOuput != goldenOutput {
			t.Errorf("Unexpected policy from %s:\n%s\nExpected:\n%s\n", inputFile, generatedOuput, goldenOutput)
		}
	}
}
