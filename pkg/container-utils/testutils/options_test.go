package testutils

import (
	"testing"
)

func TestContainerOptions(t *testing.T) {
	opts := defaultContainerOptions()

	if opts.image != DefaultContainerImage {
		t.Errorf("Expected default container image to be %q", DefaultContainerImage)
	}
	if opts.imageTag != DefaultContainerImageTag {
		t.Errorf("Expected default container image tag to be %q", DefaultContainerImageTag)
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
