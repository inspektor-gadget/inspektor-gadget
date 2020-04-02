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

func TestPostProcessFirstLineTrue(t *testing.T) {
	var firstLinePrinted uint64

	mock := &mockWriter{[]byte{}}
	postProcess := newPostProcess("prefix", mock, true, &firstLinePrinted)

	postProcess.Write([]byte("hi\n"))

	// First line must append "NODE "instead of the prefix
	if string(mock.output) != "NODE hi\n" {
		t.Fatalf("%v != %v", string(mock.output), "NODE hi\n")
	}


	mock.output = []byte{}
	postProcess.Write([]byte("hi\n"))

	// First line already printed, prefix should be appended
	if string(mock.output) != "[prefix] hi\n" {
		t.Fatalf("%v != %v", string(mock.output), "NODE hi\n")
	}
}

func TestPostProcessFirstLineFalse(t *testing.T) {
	var firstLinePrinted uint64

	mock := &mockWriter{[]byte{}}
	postProcess := newPostProcess("prefix", mock, false, &firstLinePrinted)

	postProcess.Write([]byte("hi\n"))

	// First line must append "NODE "instead of the prefix
	if string(mock.output) != "[prefix] hi\n" {
		t.Fatalf("%v != %v", string(mock.output), "[prefix] hi\n")
	}
}

func TestPostProcessMultipleLines(t *testing.T) {
	var firstLinePrinted uint64

	mock := &mockWriter{[]byte{}}
	postProcess := newPostProcess("prefix", mock, false, &firstLinePrinted)

	postProcess.Write([]byte("hi"))
	postProcess.Write([]byte(" world\n"))
	postProcess.Write([]byte("from go\n"))

	expected := "[prefix] hi world\n[prefix] from go\n"
	if string(mock.output) != expected {
		t.Fatalf("%v != %v", string(mock.output), expected)
	}
}
