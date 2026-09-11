// Copyright 2026 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package selinuxperms

import (
	"os/exec"
	"testing"
)

func TestGeneratedClassPermsCurrent(t *testing.T) {
	cmd := exec.Command(
		"python3", "generate_classperms.py",
		"--source", "testdata/classmap.h",
		"--output", "classperms.go",
		"--check",
	)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("generated permission table is stale: %v\n%s", err, output)
	}
}
