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
