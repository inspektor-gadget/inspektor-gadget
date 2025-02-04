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
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// mockMatcher implements ColumnMatcher for testing
type mockMatcher struct {
	tags     []string
	embedded bool
}

func (m mockMatcher) HasTag(tag string) bool {
	for _, t := range m.tags {
		if strings.ToLower(t) == tag {
			return true
		}
	}
	return false
}

func (m mockMatcher) IsEmbedded() bool {
	return m.embedded
}

func (m mockMatcher) HasNoTags() bool {
	return len(m.tags) == 0
}

func TestCaseSensitivity(t *testing.T) {
	filters := []ColumnFilter{
		WithTag("Example"),
		WithTags([]string{"Test", "EXAMPLE"}),
		WithoutTag("IGNORE"),
		WithoutTags([]string{"IGNORE", "AVOID"}),
	}

	testCases := []struct {
		description string
		matcher     ColumnMatcher
		expected    []bool
	}{
		{"matching_lowercase", mockMatcher{tags: []string{"example", "test"}}, []bool{true, true, true, true}},
		{"matching_uppercase", mockMatcher{tags: []string{"EXAMPLE", "TEST"}}, []bool{true, true, true, true}},
		{"non_matching_mixed", mockMatcher{tags: []string{"examplE", "TesT"}}, []bool{true, true, true, true}},
		{"contains_ignored_tag", mockMatcher{tags: []string{"ignore"}}, []bool{false, false, false, false}},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			for i, filter := range filters {
				require.Equal(t, tc.expected[i], filter(tc.matcher))
			}
		})
	}
}

func TestOr(t *testing.T) {
	t.Run("match_any", func(t *testing.T) {
		filter := Or(
			WithTag("a"),
			WithTag("b"),
		)

		testCases := []struct {
			name     string
			matcher  ColumnMatcher
			expected bool
		}{
			{"has a", mockMatcher{tags: []string{"a"}}, true},
			{"has b", mockMatcher{tags: []string{"b"}}, true},
			{"has both", mockMatcher{tags: []string{"a", "b"}}, true},
			{"has none", mockMatcher{tags: []string{"c"}}, false},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				require.Equal(t, tc.expected, filter(tc.matcher))
			})
		}
	})

	t.Run("empty_filters", func(t *testing.T) {
		filter := Or()
		require.False(t, filter(mockMatcher{}))
	})
}

func TestAnd(t *testing.T) {
	t.Run("match_all", func(t *testing.T) {
		filter := And(
			WithTag("a"),
			WithTag("b"),
		)

		testCases := []struct {
			name     string
			matcher  ColumnMatcher
			expected bool
		}{
			{"has both", mockMatcher{tags: []string{"a", "b"}}, true},
			{"missing a", mockMatcher{tags: []string{"b"}}, false},
			{"missing b", mockMatcher{tags: []string{"a"}}, false},
			{"has none", mockMatcher{tags: []string{"c"}}, false},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				require.Equal(t, tc.expected, filter(tc.matcher))
			})
		}
	})

	t.Run("empty_filters", func(t *testing.T) {
		filter := And()
		require.True(t, filter(mockMatcher{}))
	})
}

func TestWithEmbedded(t *testing.T) {
	testCases := []struct {
		name     string
		embedded bool
		matcher  ColumnMatcher
		expected bool
	}{
		{"embedded_match", true, mockMatcher{embedded: true}, true},
		{"embedded_mismatch", true, mockMatcher{embedded: false}, false},
		{"non_embedded_match", false, mockMatcher{embedded: false}, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			filter := WithEmbedded(tc.embedded)
			require.Equal(t, tc.expected, filter(tc.matcher))
		})
	}
}

func TestWithTags(t *testing.T) {
	t.Run("multiple_tags", func(t *testing.T) {
		filter := WithTags([]string{"a", "B"}) // Test case insensitivity
		testCases := []struct {
			name     string
			matcher  ColumnMatcher
			expected bool
		}{
			{"has_all", mockMatcher{tags: []string{"a", "b"}}, true},
			{"has_subset", mockMatcher{tags: []string{"a"}}, false},
			{"has_extra", mockMatcher{tags: []string{"a", "b", "c"}}, true},
			{"has_none", mockMatcher{tags: []string{}}, false},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				require.Equal(t, tc.expected, filter(tc.matcher))
			})
		}
	})

	t.Run("empty_tags", func(t *testing.T) {
		filter := WithTags(nil)
		require.True(t, filter(mockMatcher{}))
	})
}

func TestWithAnyTag(t *testing.T) {
	filter := WithAnyTag([]string{"a", "B"})
	testCases := []struct {
		name     string
		matcher  ColumnMatcher
		expected bool
	}{
		{"has_first", mockMatcher{tags: []string{"a"}}, true},
		{"has_second", mockMatcher{tags: []string{"b"}}, true},
		{"has_both", mockMatcher{tags: []string{"a", "b"}}, true},
		{"has_neither", mockMatcher{tags: []string{"c"}}, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.expected, filter(tc.matcher))
		})
	}
}

func TestWithoutTags(t *testing.T) {
	filter := WithoutTags([]string{"a", "B"})
	testCases := []struct {
		name     string
		matcher  ColumnMatcher
		expected bool
	}{
		{"no_tags", mockMatcher{tags: []string{}}, true},
		{"has_other", mockMatcher{tags: []string{"c"}}, true},
		{"has_one", mockMatcher{tags: []string{"a"}}, false},
		{"has_both", mockMatcher{tags: []string{"a", "b"}}, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.expected, filter(tc.matcher))
		})
	}
}

func TestWithTag(t *testing.T) {
	filter := WithTag("A") // Test case insensitivity
	testCases := []struct {
		name     string
		matcher  ColumnMatcher
		expected bool
	}{
		{"has_tag", mockMatcher{tags: []string{"a"}}, true},
		{"missing_tag", mockMatcher{tags: []string{"b"}}, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.expected, filter(tc.matcher))
		})
	}
}

func TestWithoutTag(t *testing.T) {
	filter := WithoutTag("A")
	testCases := []struct {
		name     string
		matcher  ColumnMatcher
		expected bool
	}{
		{"no_tag", mockMatcher{tags: []string{}}, true},
		{"has_other", mockMatcher{tags: []string{"b"}}, true},
		{"has_tag", mockMatcher{tags: []string{"a"}}, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.expected, filter(tc.matcher))
		})
	}
}

func TestWithoutExceptTag(t *testing.T) {
	filter := WithoutExceptTag("secret", "exception")
	testCases := []struct {
		name     string
		matcher  ColumnMatcher
		expected bool
	}{
		{"no_tags", mockMatcher{tags: []string{}}, true},
		{"has_exception", mockMatcher{tags: []string{"exception"}}, true},
		{"has_both", mockMatcher{tags: []string{"secret", "exception"}}, true},
		{"has_secret_only", mockMatcher{tags: []string{"secret"}}, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.expected, filter(tc.matcher))
		})
	}
}

func TestWithNoTags(t *testing.T) {
	filter := WithNoTags()
	testCases := []struct {
		name     string
		matcher  ColumnMatcher
		expected bool
	}{
		{"no_tags", mockMatcher{tags: []string{}}, true},
		{"has_tags", mockMatcher{tags: []string{"a"}}, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.expected, filter(tc.matcher))
		})
	}
}
