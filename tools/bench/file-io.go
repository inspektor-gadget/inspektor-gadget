package main

import (
	"fmt"
	"math/rand"
	"os"

	"github.com/google/uuid"
)

type fileIOGenerator struct {
	baseGenerator
}

func NewFileIOGenerator(_ string) (Generator, error) {
	cb := func() error {
		uuid := uuid.New()
		path := fmt.Sprintf("test-file-io-%s.txt", uuid.String())

		// Generate 10 MB random buffer
		buffer := make([]byte, 10*1024*1024) // 1 MB
		rand.Read(buffer)

		defer os.Remove(path)
		return os.WriteFile(path, buffer, 0644)
	}

	return &fileIOGenerator{
		baseGenerator: NewBaseGen(cb),
	}, nil
}

func init() {
	RegisterGenerator("file-io", NewFileIOGenerator)
}
