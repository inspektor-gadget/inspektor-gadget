package syscalls

import (
	"fmt"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetSyscallNumberByName(t *testing.T) {
	assert := assert.New(t)
	tests := []struct {
		description string
		name        string
		number      int
		arch        string
		expectedok  bool
	}{
		{
			description: "getting syscalls number from name",
			name:        "open_tree",
			number:      428,
			arch:        "amd64",
			expectedok:  true,
		},
		{
			description: "getting syscall number from name",
			name:        "close_range",
			number:      436,
			arch:        "amd64",
			expectedok:  true,
		},
		{
			description: "getting syscall number from name",
			name:        "accept",
			number:      200,
			arch:        "arm64",
			expectedok:  true,
		},
		{
			description: "getting syscall number from name",
			name:        "futex",
			number:      98,
			arch:        "arm64",
			expectedok:  true,
		},
		{
			description: "empty syscall name",
			name:        "",
			number:      -1,
			expectedok:  false,
			arch:        "arm64",
		},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("%s (%s)", test.description, test.arch), func(t *testing.T) {
			if runtime.GOARCH != test.arch {
				t.Skipf("skipping test for %s, only for %s", runtime.GOARCH, test.arch)
			}
			number, ok := GetSyscallNumberByName(test.name)
			assert.Equal(test.expectedok, ok, "expected ok to be %v, got %v", test.expectedok, ok)
			assert.Equal(test.number, number, "expected number to be %d, got %d", test.number, number)
		})
	}
}

func TestGetSyscallNameByNumber(t *testing.T) {
	assert := assert.New(t)
	tests := []struct {
		description string
		name        string
		number      int
		arch        string
		expectedok  bool
	}{
		{
			description: "getting syscalls name from number",
			name:        "open_tree",
			number:      428,
			arch:        "amd64",
			expectedok:  true,
		},
		{
			description: "getting syscall name from number",
			name:        "close_range",
			number:      436,
			arch:        "amd64",
			expectedok:  true,
		},
		{
			description: "getting syscall name from number",
			name:        "accept",
			number:      200,
			arch:        "arm64",
			expectedok:  true,
		},
		{
			description: "getting syscall name from number",
			name:        "futex",
			number:      98,
			arch:        "arm64",
			expectedok:  true,
		},
		{
			description: "empty syscalls number",
			name:        "",
			number:      -1,
			expectedok:  false,
			arch:        "arm64",
		},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("%s (%s)", test.description, test.arch), func(t *testing.T) {
			if runtime.GOARCH != test.arch {
				t.Skipf("skipping test for %s, only for %s", runtime.GOARCH, test.arch)
			}
			name, ok := GetSyscallNameByNumber(test.number)
			assert.Equal(test.expectedok, ok, "expected ok to be %v, got %v", test.expectedok, ok)
			assert.Equal(test.name, name, "expected number to be %d, got %d", test.name, name)
		})
	}
}
