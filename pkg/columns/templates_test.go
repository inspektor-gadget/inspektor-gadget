// Copyright 2025 The Inspektor Gadget authors
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

package columns

import (
	"fmt"
	"math/rand"
	"testing"
)

func uniqueTemplateName(t *testing.T, suffix ...string) string {
	name := "test-" + t.Name()
	for _, s := range suffix {
		name += "-" + s
	}
	return fmt.Sprintf("%s-%d", name, rand.Int())
}

func TestRegisterTemplate(t *testing.T) {
	name := uniqueTemplateName(t)
	err := RegisterTemplate(name, "value")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	value, exists := getTemplate(name)
	if !exists {
		t.Fatalf("expected template %q to exist", name)
	}
	if value != "value" {
		t.Fatalf("expected template value 'value', got %q", value)
	}
}

func TestRegisterTemplateWithEmptyName(t *testing.T) {
	err := RegisterTemplate("", "value")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	expectedErr := "no template name given"
	if err.Error() != expectedErr {
		t.Fatalf("expected error %q, got %q", expectedErr, err)
	}
}

func TestRegisterTemplateWithEmptyValue(t *testing.T) {
	name := uniqueTemplateName(t)
	err := RegisterTemplate(name, "")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	expectedErr := fmt.Sprintf("no value given for template %q", name)
	if err.Error() != expectedErr {
		t.Fatalf("expected error %q, got %q", expectedErr, err)
	}
}

func TestRegisterTemplateDuplicate(t *testing.T) {
	name := uniqueTemplateName(t)
	if err := RegisterTemplate(name, "value"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	err := RegisterTemplate(name, "new_value")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	expectedErr := fmt.Sprintf("template with name %q already exists", name)
	if err.Error() != expectedErr {
		t.Fatalf("expected error %q, got %q", expectedErr, err)
	}
}

func TestMustRegisterTemplate(t *testing.T) {
	name := uniqueTemplateName(t)
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("unexpected panic: %v", r)
		}
	}()
	MustRegisterTemplate(name, "value")

	value, exists := getTemplate(name)
	if !exists {
		t.Fatalf("expected template %q to exist", name)
	}
	if value != "value" {
		t.Fatalf("expected template value 'value', got %q", value)
	}
}

func TestMustRegisterTemplatePanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic, but did not panic")
		}
	}()
	MustRegisterTemplate("", "value")
}

func TestGetTemplate(t *testing.T) {
	name := uniqueTemplateName(t)
	if err := RegisterTemplate(name, "value"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	tpl, exists := getTemplate(name)
	if !exists {
		t.Fatalf("expected template %q to exist", name)
	}
	if tpl != "value" {
		t.Fatalf("expected template value 'value', got %q", tpl)
	}
}

func TestGetTemplateNonexistent(t *testing.T) {
	name := uniqueTemplateName(t, "nonexistent")
	tpl, exists := getTemplate(name)
	if exists {
		t.Fatalf("expected template %q to not exist", name)
	}
	if tpl != "" {
		t.Fatalf("expected empty template value, got %q", tpl)
	}
}
