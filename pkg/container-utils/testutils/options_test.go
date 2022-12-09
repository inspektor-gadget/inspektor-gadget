package testutils

import (
	"testing"
)

func TestContainerOptions(t *testing.T) {
	opts := defaultContainerOptions()

	if opts.name != DefaultContainerName {
		t.Errorf("Expected default container name to be %q", DefaultContainerName)
	}
	if opts.image != DefaultContainerImage {
		t.Errorf("Expected default container image to be %q", DefaultContainerImage)
	}
	if opts.seccompProfile != "" {
		t.Errorf("Expected default seccompProfile to be empty")
	}

	if !opts.logs {
		t.Errorf("Expected default logs to be true")
	}
	if !opts.wait {
		t.Errorf("Expected default wait to be true")
	}
	if !opts.removal {
		t.Errorf("Expected default removal to be true")
	}
}
