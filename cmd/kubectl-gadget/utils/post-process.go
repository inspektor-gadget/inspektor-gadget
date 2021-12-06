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

package utils

import (
	"fmt"
	"io"
	"strings"
	"sync/atomic"
)

type PostProcess struct {
	firstLinePrinted uint64
	OutStreams       []*postProcessSingle
	ErrStreams       []*postProcessSingle
}

type postProcessSingle struct {
	orig             io.Writer
	Node             string
	callback         func(line string, node string)
	transform        func(line string) string
	firstLinePrinted *uint64
	buffer           string // buffer to save incomplete strings
	skipFirstLine    bool
	verbose          bool
}

type PostProcessConfig struct {
	// Number of flow this should process.
	Flows int

	// Function to be called each time there is new data from the node.
	Callback func(line string, node string)

	// Function to be called to transform the output before printing.
	// It's only called if Callback is nil.
	Transform func(line string) string

	// Streams to print the standard and error outputs.
	OutStream io.Writer
	ErrStream io.Writer

	// Only print the first line once.
	SkipFirstLine bool

	// Verbose mode
	Verbose bool
}

func NewPostProcess(config *PostProcessConfig) *PostProcess {
	p := &PostProcess{
		firstLinePrinted: 0,
		OutStreams:       make([]*postProcessSingle, config.Flows),
		ErrStreams:       make([]*postProcessSingle, config.Flows),
	}

	for i := 0; i < config.Flows; i++ {
		p.OutStreams[i] = &postProcessSingle{
			orig:             config.OutStream,
			callback:         config.Callback,
			transform:        config.Transform,
			firstLinePrinted: &p.firstLinePrinted,
			skipFirstLine:    config.SkipFirstLine,
			verbose:          config.Verbose,
		}

		p.ErrStreams[i] = &postProcessSingle{
			orig:      config.ErrStream,
			callback:  config.Callback,
			transform: config.Transform,
		}
	}

	return p
}

func (post *postProcessSingle) Write(p []byte) (n int, err error) {
	asStr := post.buffer + string(p)

	lines := strings.Split(asStr, "\n")
	if len(lines) == 0 {
		return len(p), nil
	}

	// Print all complete lines
	for _, line := range lines[0 : len(lines)-1] {
		// Skip printing the first line (header) multiple times if requested by the caller
		if post.skipFirstLine {
			post.skipFirstLine = false // we already processed the first line. Don't care about it anymore.
			if atomic.AddUint64(post.firstLinePrinted, 1) != 1 {
				// first line already printed by another stream, skip it.
				continue
			}
		}

		if post.callback != nil {
			post.callback(line, post.Node)
		} else {
			if post.transform != nil {
				line = post.transform(line)
			}

			if line != "" {
				fmt.Fprintf(post.orig, "%s\n", line)
			}
		}
	}

	post.buffer = lines[len(lines)-1] // Buffer last line to print in next iteration

	return len(p), err
}
