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
	"testing"
)

type mockWriter struct {
	output []byte
}

func (mock *mockWriter) Write(p []byte) (n int, err error) {
	mock.output = append(mock.output, p...)
	return len(p), nil
}

// TestPostProcessFirstLineOutStream tests that the first line is printed
// only once among the different nodes using out stream
func TestPostProcessFirstLineOutStream(t *testing.T) {
	mock := &mockWriter{[]byte{}}

	postProcess := NewPostProcess(&PostProcessConfig{
		Flows:         2,
		OutStream:     mock,
		ErrStream:     mock,
		SkipFirstLine: true,
	})

	postProcess.OutStreams[0].Write([]byte("COMM  PID    PPID   RET ARGS\n"))
	postProcess.OutStreams[1].Write([]byte("COMM  PID    PPID   RET ARGS\n"))

	expected := `
COMM  PID    PPID   RET ARGS
`
	if "\n"+string(mock.output) != expected {
		t.Fatalf("%v != %v", string(mock.output), expected)
	}
}

// TestPostProcessFirstLineErrStream tests that the first line is always
// printed for errStream
func TestPostProcessFirstLineErrStream(t *testing.T) {
	mock := &mockWriter{[]byte{}}
	postProcess := NewPostProcess(&PostProcessConfig{
		Flows:         2,
		OutStream:     mock,
		ErrStream:     mock,
		SkipFirstLine: true,
	})

	postProcess.ErrStreams[0].Write([]byte("error in node0\n"))
	postProcess.ErrStreams[1].Write([]byte("error in node1\n"))

	expected := `
error in node0
error in node1
`
	if "\n"+string(mock.output) != expected {
		t.Fatalf("%v != %v", string(mock.output), expected)
	}
}

func TestPostProcessMultipleLines(t *testing.T) {
	var expected string
	mock := &mockWriter{[]byte{}}
	postProcess := NewPostProcess(&PostProcessConfig{
		Flows:         1,
		OutStream:     mock,
		ErrStream:     mock,
		SkipFirstLine: true,
	})

	postProcess.OutStreams[0].Write([]byte("COMM  PID    PPID   RET ARGS\n"))

	postProcess.OutStreams[0].Write([]byte("wget   "))
	expected = `
COMM  PID    PPID   RET ARGS
`
	if "\n"+string(mock.output) != expected {
		t.Fatalf("%v != %v", string(mock.output), expected)
	}

	postProcess.OutStreams[0].Write([]byte("200000 200000   0 /usr/bin/wget\n"))

	expected = `
COMM  PID    PPID   RET ARGS
wget   200000 200000   0 /usr/bin/wget
`
	if "\n"+string(mock.output) != expected {
		t.Fatalf("%v != %v", string(mock.output), expected)
	}
}

func TestMultipleNodes(t *testing.T) {
	mock := &mockWriter{[]byte{}}
	postProcess := NewPostProcess(&PostProcessConfig{
		Flows:         3,
		OutStream:     mock,
		ErrStream:     mock,
		SkipFirstLine: true,
	})

	postProcess.OutStreams[0].Write([]byte("COMM  PID    PPID   RET ARGS\n"))
	postProcess.OutStreams[0].Write([]byte("curl   100000 100000   0 /usr/bin/curl\n"))

	postProcess.OutStreams[1].Write([]byte("COMM  PID    PPID   RET ARGS\n"))
	postProcess.OutStreams[2].Write([]byte("COMM  PID    PPID   RET ARGS\n"))

	postProcess.OutStreams[2].Write([]byte("mkdir  "))

	postProcess.OutStreams[1].Write([]byte("wget   200000 200000   0 /usr/bin/wget\n"))

	postProcess.OutStreams[2].Write([]byte("199679 "))
	postProcess.OutStreams[2].Write([]byte("199678   "))
	postProcess.OutStreams[2].Write([]byte("0 /usr/bin/mkdir /tmp/install.sh.10\n"))

	expected := `
COMM  PID    PPID   RET ARGS
curl   100000 100000   0 /usr/bin/curl
wget   200000 200000   0 /usr/bin/wget
mkdir  199679 199678   0 /usr/bin/mkdir /tmp/install.sh.10
`
	if "\n"+string(mock.output) != expected {
		t.Fatalf("%v != %v", string(mock.output), expected)
	}
}

// Test that the first line is not skiped
func TestSkipFirstLineFalse(t *testing.T) {
	mock := &mockWriter{[]byte{}}
	postProcess := NewPostProcess(&PostProcessConfig{
		Flows:         3,
		OutStream:     mock,
		ErrStream:     mock,
		SkipFirstLine: false,
	})

	postProcess.OutStreams[0].Write([]byte(`{"comm": "cat", "pid": 11}` + "\n"))
	postProcess.OutStreams[0].Write([]byte(`{"comm": "ping", "pid": 22}` + "\n"))

	postProcess.OutStreams[0].Write([]byte(`{"comm": "curl", "pid": 33}` + "\n"))
	postProcess.OutStreams[0].Write([]byte(`{"comm": "nc", "pid": 44}` + "\n"))

	// this prints json in different lines
	postProcess.OutStreams[2].Write([]byte(`{"comm": "rm"`))

	postProcess.OutStreams[1].Write([]byte(`{"comm": "sleep", "pid": 55}` + "\n"))

	postProcess.OutStreams[2].Write([]byte(` , "pid": 77}` + "\n"))

	// first line is not skipped and incompleted ones are assembled together
	expected := `
{"comm": "cat", "pid": 11}
{"comm": "ping", "pid": 22}
{"comm": "curl", "pid": 33}
{"comm": "nc", "pid": 44}
{"comm": "sleep", "pid": 55}
{"comm": "rm" , "pid": 77}
`
	if "\n"+string(mock.output) != expected {
		t.Fatalf("%v != %v", string(mock.output), expected)
	}
}
