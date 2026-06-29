package runtimeclient

import "testing"

func TestNormalizeOCIRuntime(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"runc", "runc"},
		{"crun", "crun"},
		{"io.containerd.runc.v2", "runc"},
		{"io.containerd.crun.v2", "crun"},
		{"io.containerd.kata.v2", "kata"},
		{"io.containerd.runsc.v1", "runsc"},
		{"", ""},
		{"unknown", ""},
	}

	for _, tt := range tests {
		got := NormalizeOCIRuntime(tt.input)
		if got != tt.want {
			t.Errorf("NormalizeOCIRuntime(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
