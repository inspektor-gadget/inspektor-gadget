package syscalls

import (
	"testing"
)

func TestGetSyscallNumberByName(t *testing.T) {
	tests := []struct {
		description string
		name        string
		number      int
		expectedok  bool
	}{
		{
			description: "getting number from name",
			name:        "accept",
			number:      43,
			expectedok:  true,
		},
		{
			description: "not found",
			name:        "invalid-name",
			number:      0,
			expectedok:  false,
		},
		{
			description: "not getting",
			name:        "",
			number:      0,
			expectedok:  false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			number, ok := GetSyscallNumberByName(test.name)
			if number != test.number {
				t.Errorf("expected number %d, got %d", test.number, number)
			}

			if ok != test.expectedok {
				t.Errorf("expected ok %v, got %v", test.expectedok, ok)
			}
		})
	}
}

func TestGetSyscallNameByNumber(t *testing.T) {
	tests := []struct {
		description  string
		number       int
		expectedName string
		expectedOk   bool
	}{
		{
			description:  "getting number from name",
			number:       202,
			expectedName: "futex",
			expectedOk:   true,
		},
		{
			description:  "getting number from name",
			number:       200,
			expectedName: "tkill",
			expectedOk:   true,
		},
		{
			description:  "invalid name",
			number:       0,
			expectedName: "",
			expectedOk:   false,
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			name, ok := GetSyscallNameByNumber(test.number)
			if name != test.expectedName {
				t.Errorf("expected name %q, got %q", test.expectedName, name)
			}

			if ok != test.expectedOk {
				t.Errorf("expected ok %v, got %v", test.expectedOk, ok)
			}
		})
	}
}
