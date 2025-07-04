package main

import (
	"os/exec"
)

type execGenerator struct {
	baseGenerator
}

func NewExecGenerator(_ string) (Generator, error) {
	cb := func() error {
		return exec.Command("/bin/true").Run()
	}

	return &execGenerator{
		baseGenerator: NewBaseGen(cb),
	}, nil
}

func init() {
	RegisterGenerator("exec", NewExecGenerator)
}
