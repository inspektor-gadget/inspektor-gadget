package datasource

import (
	"testing"
)

func TestRegisterAndApplyAnnotationTemplates(t *testing.T) {
	// Reset the callbacks slice before running tests
	annotationTemplateCallbacks = make([]func(string, map[string]string) bool, 0)

	tests := []struct {
		name               string
		callbacks         []func(string, map[string]string) bool
		templateName      string
		annotations       map[string]string
		expectedHandled   bool
	}{
		{
			name: "single callback returns true",
			callbacks: []func(string, map[string]string) bool{
				func(name string, annotations map[string]string) bool {
					return true
				},
			},
			templateName:    "test-template",
			annotations:     map[string]string{"key": "value"},
			expectedHandled: true,
		},
		{
			name: "single callback returns false",
			callbacks: []func(string, map[string]string) bool{
				func(name string, annotations map[string]string) bool {
					return false
				},
			},
			templateName:    "test-template",
			annotations:     map[string]string{"key": "value"},
			expectedHandled: false,
		},
		{
			name: "multiple callbacks, one returns true",
			callbacks: []func(string, map[string]string) bool{
				func(name string, annotations map[string]string) bool {
					return false
				},
				func(name string, annotations map[string]string) bool {
					return true
				},
			},
			templateName:    "test-template",
			annotations:     map[string]string{"key": "value"},
			expectedHandled: true,
		},
		{
			name: "multiple callbacks, all return false",
			callbacks: []func(string, map[string]string) bool{
				func(name string, annotations map[string]string) bool {
					return false
				},
				func(name string, annotations map[string]string) bool {
					return false
				},
			},
			templateName:    "test-template",
			annotations:     map[string]string{"key": "value"},
			expectedHandled: false,
		},
		{
			name:            "no callbacks registered",
			callbacks:       []func(string, map[string]string) bool{},
			templateName:    "test-template",
			annotations:     map[string]string{"key": "value"},
			expectedHandled: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset callbacks before each test
			annotationTemplateCallbacks = make([]func(string, map[string]string) bool, 0)

			// Register callbacks
			for _, cb := range tt.callbacks {
				RegisterAnnotationTemplateCallback(cb)
			}

			// Apply templates and check result
			handled := ApplyAnnotationTemplates(tt.templateName, tt.annotations)
			if handled != tt.expectedHandled {
				t.Errorf("ApplyAnnotationTemplates() = %v, want %v", handled, tt.expectedHandled)
			}
		})
	}
}

func TestConcurrentAccess(t *testing.T) {
	// Reset the callbacks slice
	annotationTemplateCallbacks = make([]func(string, map[string]string) bool, 0)

	// Create a channel to synchronize goroutines
	done := make(chan bool)

	// Run multiple goroutines that register callbacks
	for i := 0; i < 10; i++ {
		go func() {
			RegisterAnnotationTemplateCallback(func(name string, annotations map[string]string) bool {
				return true
			})
			done <- true
		}()
	}

	// Wait for all registrations to complete
	for i := 0; i < 10; i++ {
		<-done
	}

	// Verify that all callbacks were registered
	if len(annotationTemplateCallbacks) != 10 {
		t.Errorf("Expected 10 callbacks, got %d", len(annotationTemplateCallbacks))
	}

	// Test concurrent template applications
	results := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func() {
			results <- ApplyAnnotationTemplates("test", map[string]string{"key": "value"})
		}()
	}

	// All applications should return true since all callbacks return true
	for i := 0; i < 10; i++ {
		if !<-results {
			t.Error("Expected all concurrent applications to return true")
		}
	}
}

func TestEmptyAnnotations(t *testing.T) {
	// Reset callbacks
	annotationTemplateCallbacks = make([]func(string, map[string]string) bool, 0)

	RegisterAnnotationTemplateCallback(func(name string, annotations map[string]string) bool {
		// Callback should handle nil or empty annotations gracefully
		return annotations != nil
	})

	// Test with nil annotations
	if ApplyAnnotationTemplates("test", nil) {
		t.Error("Expected false when applying templates with nil annotations")
	}

	// Test with empty annotations
	if !ApplyAnnotationTemplates("test", map[string]string{}) {
		t.Error("Expected true when applying templates with empty annotations map")
	}
}