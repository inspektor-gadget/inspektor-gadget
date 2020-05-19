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
	postProcess := newPostProcess(2, mock, mock)

	postProcess.outStreams[0].Write([]byte("PCOMM  PID    PPID   RET ARGS\n"))
	postProcess.outStreams[1].Write([]byte("PCOMM  PID    PPID   RET ARGS\n"))

	expected := `
NODE PCOMM  PID    PPID   RET ARGS
`
	if "\n"+string(mock.output) != expected {
		t.Fatalf("%v != %v", string(mock.output), expected)
	}
}

// TestPostProcessFirstLineErrStream tests that the first line is always
// printed for errStream
func TestPostProcessFirstLineErrStream(t *testing.T) {
	mock := &mockWriter{[]byte{}}
	postProcess := newPostProcess(2, mock, mock)

	postProcess.errStreams[0].Write([]byte("error in node0\n"))
	postProcess.errStreams[1].Write([]byte("error in node1\n"))

	expected := `
[E0] error in node0
[E1] error in node1
`
	if "\n"+string(mock.output) != expected {
		t.Fatalf("%v != %v", string(mock.output), expected)
	}
}

func TestPostProcessMultipleLines(t *testing.T) {
	var expected string
	mock := &mockWriter{[]byte{}}
	postProcess := newPostProcess(1, mock, mock)

	postProcess.outStreams[0].Write([]byte("PCOMM  PID    PPID   RET ARGS\n"))

	postProcess.outStreams[0].Write([]byte("wget   "))
	expected = `
NODE PCOMM  PID    PPID   RET ARGS
`
	if "\n"+string(mock.output) != expected {
		t.Fatalf("%v != %v", string(mock.output), expected)
	}

	postProcess.outStreams[0].Write([]byte("200000 200000   0 /usr/bin/wget\n"))

	expected = `
NODE PCOMM  PID    PPID   RET ARGS
[ 0] wget   200000 200000   0 /usr/bin/wget
`
	if "\n"+string(mock.output) != expected {
		t.Fatalf("%v != %v", string(mock.output), expected)
	}
}

func TestMultipleNodes(t *testing.T) {
	mock := &mockWriter{[]byte{}}
	postProcess := newPostProcess(3, mock, mock)

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
NODE PCOMM  PID    PPID   RET ARGS
[ 0] curl   100000 100000   0 /usr/bin/curl
[ 1] wget   200000 200000   0 /usr/bin/wget
[ 2] mkdir  199679 199678   0 /usr/bin/mkdir /tmp/install.sh.10
`
	if "\n"+string(mock.output) != expected {
		t.Fatalf("%v != %v", string(mock.output), expected)
	}
}
