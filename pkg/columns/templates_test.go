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

	"github.com/stretchr/testify/require"
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
	require.NoError(t, err, "expected no error")

	value, exists := getTemplate(name)
	require.True(t, exists, "expected template %q to exist", name)
	require.Equal(t, "value", value)
}

func TestRegisterTemplateWithEmptyName(t *testing.T) {
	err := RegisterTemplate("", "value")
	require.Error(t, err, "expected error")
	expectedErr := "no template name given"
	require.EqualError(t, err, expectedErr)
}

func TestRegisterTemplateWithEmptyValue(t *testing.T) {
	name := uniqueTemplateName(t)
	err := RegisterTemplate(name, "")
	require.Error(t, err, "expected error")
	expectedErr := fmt.Sprintf("no value given for template %q", name)
	require.EqualError(t, err, expectedErr)
}

func TestRegisterTemplateDuplicate(t *testing.T) {
	name := uniqueTemplateName(t)
	err := RegisterTemplate(name, "value")
	require.NoError(t, err, "unexpected error")

	err = RegisterTemplate(name, "new_value")
	require.Error(t, err, "expected error")
	expectedErr := fmt.Sprintf("template with name %q already exists", name)
	require.EqualError(t, err, expectedErr)
}

func TestMustRegisterTemplate(t *testing.T) {
	name := uniqueTemplateName(t)
	require.NotPanics(t, func() {
		MustRegisterTemplate(name, "value")
	}, "unexpected panic")

	value, exists := getTemplate(name)
	require.True(t, exists, "expected template %q to exist", name)
	require.Equal(t, "value", value)
}

func TestMustRegisterTemplatePanics(t *testing.T) {
	require.Panics(t, func() {
		MustRegisterTemplate("", "value")
	}, "expected panic")
}

func TestGetTemplate(t *testing.T) {
	name := uniqueTemplateName(t)
	err := RegisterTemplate(name, "value")
	require.NoError(t, err, "unexpected error")

	tpl, exists := getTemplate(name)
	require.True(t, exists, "expected template %q to exist", name)
	require.Equal(t, "value", tpl)
}

func TestGetTemplateNonexistent(t *testing.T) {
	name := uniqueTemplateName(t, "nonexistent")
	tpl, exists := getTemplate(name)
	require.False(t, exists, "expected template %q to not exist", name)
	require.Equal(t, "", tpl)
}
