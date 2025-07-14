package main

import (
	"os"
)

type openGenerator struct {
	baseGenerator
}

func newOpenGenerator(_ string) (Generator, error) {
	cb := func() error {
		file, err := os.Open("/dev/null")
		if err != nil {
			return err
		}
		defer file.Close()
		return nil
	}

	return &openGenerator{
		baseGenerator: NewBaseGen(cb),
	}, nil
}

func init() {
	registerGenerator("open", newOpenGenerator)
}
