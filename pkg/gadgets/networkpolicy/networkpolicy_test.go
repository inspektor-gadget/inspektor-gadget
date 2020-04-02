package networkpolicy

import (
	"io/ioutil"
	"path/filepath"
	"testing"
)

func TestLoad(t *testing.T) {
	match, err := filepath.Glob("testdata/*.input")
	if err != nil {
		t.Fatal(err)
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
