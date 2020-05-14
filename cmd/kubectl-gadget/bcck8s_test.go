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

func TestMultipleNodes(t *testing.T) {
	var firstLinePrinted uint64

	mock := &mockWriter{[]byte{}}
	postProcessNode1 := newPostProcess(" 1", mock, false, &firstLinePrinted)
	postProcessNode2 := newPostProcess(" 2", mock, false, &firstLinePrinted)
	postProcessNode3 := newPostProcess(" 3", mock, false, &firstLinePrinted)

	postProcessNode1.Write([]byte("PCOMM            PID    PPID   RET ARGS\n"))
	postProcessNode1.Write([]byte("curl               100000 100000   0 /usr/bin/curl\n"))

	postProcessNode2.Write([]byte("PCOMM            PID    PPID   RET ARGS\n"))
	postProcessNode3.Write([]byte("PCOMM            PID    PPID   RET ARGS\n"))

	postProcessNode1.Write([]byte("mkdir            "))

	postProcessNode2.Write([]byte("wget             200000 200000   0 /usr/bin/wget\n"))

	postProcessNode1.Write([]byte("199679 "))
	postProcessNode1.Write([]byte("199678   "))
	postProcessNode1.Write([]byte("0 /usr/bin/mkdir /tmp/install.sh.10\n"))

	expected := `
NODE PCOMM            PID    PPID   RET ARGS
[ 1] curl             100000 100000   0 /usr/bin/curl
[ 2] wget             200000 200000   0 /usr/bin/wget
[ 3] mkdir            199679 199678   0 /usr/bin/mkdir /tmp/install.sh.10`
	if "\n"+string(mock.output) != expected {
		t.Fatalf("%v != %v", string(mock.output), expected)
	}
}
