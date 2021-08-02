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

package main

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
	postProcess := newPostProcess(2, mock, mock, false)

	postProcess.outStreams[0].Write([]byte("PCOMM  PID    PPID   RET ARGS\n"))
	postProcess.outStreams[1].Write([]byte("PCOMM  PID    PPID   RET ARGS\n"))

	expected := `
PCOMM  PID    PPID   RET ARGS
`
	if "\n"+string(mock.output) != expected {
		t.Fatalf("%v != %v", string(mock.output), expected)
	}
}

// TestPostProcessFirstLineErrStream tests that the first line is always
// printed for errStream
func TestPostProcessFirstLineErrStream(t *testing.T) {
	mock := &mockWriter{[]byte{}}
	postProcess := newPostProcess(2, mock, mock, false)

	postProcess.errStreams[0].Write([]byte("error in node0\n"))
	postProcess.errStreams[1].Write([]byte("error in node1\n"))

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
	postProcess := newPostProcess(1, mock, mock, false)

	postProcess.outStreams[0].Write([]byte("PCOMM  PID    PPID   RET ARGS\n"))

	postProcess.outStreams[0].Write([]byte("wget   "))
	expected = `
PCOMM  PID    PPID   RET ARGS
`
	if "\n"+string(mock.output) != expected {
		t.Fatalf("%v != %v", string(mock.output), expected)
	}

	postProcess.outStreams[0].Write([]byte("200000 200000   0 /usr/bin/wget\n"))

	expected = `
PCOMM  PID    PPID   RET ARGS
wget   200000 200000   0 /usr/bin/wget
`
	if "\n"+string(mock.output) != expected {
		t.Fatalf("%v != %v", string(mock.output), expected)
	}
}

func TestMultipleNodes(t *testing.T) {
	mock := &mockWriter{[]byte{}}
	postProcess := newPostProcess(3, mock, mock, false)

	postProcess.outStreams[0].Write([]byte("PCOMM  PID    PPID   RET ARGS\n"))
	postProcess.outStreams[0].Write([]byte("curl   100000 100000   0 /usr/bin/curl\n"))

	postProcess.outStreams[1].Write([]byte("PCOMM  PID    PPID   RET ARGS\n"))
	postProcess.outStreams[2].Write([]byte("PCOMM  PID    PPID   RET ARGS\n"))

	postProcess.outStreams[2].Write([]byte("mkdir  "))

	postProcess.outStreams[1].Write([]byte("wget   200000 200000   0 /usr/bin/wget\n"))

	postProcess.outStreams[2].Write([]byte("199679 "))
	postProcess.outStreams[2].Write([]byte("199678   "))
	postProcess.outStreams[2].Write([]byte("0 /usr/bin/mkdir /tmp/install.sh.10\n"))

	expected := `
PCOMM  PID    PPID   RET ARGS
curl   100000 100000   0 /usr/bin/curl
wget   200000 200000   0 /usr/bin/wget
mkdir  199679 199678   0 /usr/bin/mkdir /tmp/install.sh.10
`
	if "\n"+string(mock.output) != expected {
		t.Fatalf("%v != %v", string(mock.output), expected)
	}
}

func TestJson(t *testing.T) {
	mock := &mockWriter{[]byte{}}
	postProcess := newPostProcess(3, mock, mock, true)

	postProcess.outStreams[0].Write([]byte(`{"pcomm": "cat", "pid": 11}` + "\n"))
	postProcess.outStreams[0].Write([]byte(`{"pcomm": "ping", "pid": 22}` + "\n"))

	postProcess.outStreams[0].Write([]byte(`{"pcomm": "curl", "pid": 33}` + "\n"))
	postProcess.outStreams[0].Write([]byte(`{"pcomm": "nc", "pid": 44}` + "\n"))

	// this prints json in different lines
	postProcess.outStreams[2].Write([]byte(`{"pcomm": "rm"`))

	postProcess.outStreams[1].Write([]byte(`{"pcomm": "sleep", "pid": 55}` + "\n"))

	postProcess.outStreams[2].Write([]byte(` , "pid": 77}` + "\n"))

	// first line is not skipped and incompleted ones are assembled together
	expected := `
{"pcomm": "cat", "pid": 11}
{"pcomm": "ping", "pid": 22}
{"pcomm": "curl", "pid": 33}
{"pcomm": "nc", "pid": 44}
{"pcomm": "sleep", "pid": 55}
{"pcomm": "rm" , "pid": 77}
`
	if "\n"+string(mock.output) != expected {
		t.Fatalf("%v != %v", string(mock.output), expected)
	}

}
