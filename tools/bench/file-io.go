// Copyright 2025 The Inspektor Gadget authors
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
