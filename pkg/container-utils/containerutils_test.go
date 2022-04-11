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

package containerutils

import (
	"io/ioutil"
	"path/filepath"
	"testing"
)

func TestParseOCIState(t *testing.T) {
	match, err := filepath.Glob("testdata/*.input")
	if err != nil {
		t.Fatal(err)
	}

	for _, inputFile := range match {
		t.Logf("Parsing OCI state from file %s", inputFile)
		stateBuf, err := ioutil.ReadFile(inputFile)
		if err != nil {
			t.Fatal(err)
		}
		ID, PID, err := ParseOCIState(stateBuf)
		if err != nil {
			t.Errorf("Cannot parse file %s: %s", inputFile, err)
		}
		if ID != "92646e8e819a27d43a9435cd195dc1f38a0c5ff897b4ca660fcbfbfe7502b47a" {
			t.Errorf("Cannot get ID in %s", inputFile)
		}
		if PID != 210223 {
			t.Errorf("Cannot get PID in %s", inputFile)
		}
	}
}
