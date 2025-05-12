// Copyright 2022 The Inspektor Gadget authors
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

import "strings"

type ColumnFilter func(matcher ColumnMatcher) bool

// Or combines several ColumnFilter and matches if one filter matches
func Or(filters ...ColumnFilter) ColumnFilter {
	return func(matcher ColumnMatcher) bool {
		for _, f := range filters {
			if f(matcher) {
				return true
			}
		}
		return false
	}
}

// And combines several ColumnFilter and matches if all filters match
func And(filters ...ColumnFilter) ColumnFilter {
	return func(matcher ColumnMatcher) bool {
		for _, f := range filters {
			if !f(matcher) {
				return false
			}
		}
		return true
	}
}

// WithEmbedded checks whether a column matches the embedded criteria
func WithEmbedded(embedded bool) ColumnFilter {
	return func(matcher ColumnMatcher) bool {
		return matcher.IsEmbedded() == embedded
	}
}

// WithTags makes sure that all returned columns contain all the given tags
func WithTags(tags []string) ColumnFilter {
	tags = ToLowerStrings(tags)
	return func(matcher ColumnMatcher) bool {
		for _, tag := range tags {
			if !matcher.HasTag(tag) {
				return false
			}
		}
		return true
	}
}

// WithAnyTag makes sure that all returned columns contain at least one of the given tags
func WithAnyTag(tags []string) ColumnFilter {
	tags = ToLowerStrings(tags)
	return func(matcher ColumnMatcher) bool {
		for _, tag := range tags {
			if matcher.HasTag(tag) {
				return true
			}
		}
		return false
	}
}

// WithoutTags makes sure that all returned columns contain none of the given tags
func WithoutTags(tags []string) ColumnFilter {
	tags = ToLowerStrings(tags)
	return func(matcher ColumnMatcher) bool {
		for _, tag := range tags {
			if matcher.HasTag(tag) {
				return false
			}
		}
		return true
	}
}

// WithTag makes sure that all returned columns contain all the given tag
func WithTag(tag string) ColumnFilter {
	tag = strings.ToLower(tag)
	return func(matcher ColumnMatcher) bool {
		return matcher.HasTag(tag)
	}
}

// WithoutTag makes sure that all returned columns don't contain the given tag
func WithoutTag(tag string) ColumnFilter {
	tag = strings.ToLower(tag)
	return func(matcher ColumnMatcher) bool {
		return !matcher.HasTag(tag)
	}
}

// WithoutExceptTag makes sure that all returned columns don't contain the given
// tag, except when it also includes the exception given
func WithoutExceptTag(tag, exception string) ColumnFilter {
	tag = strings.ToLower(tag)
	return func(matcher ColumnMatcher) bool {
		return !matcher.HasTag(tag) || matcher.HasTag(exception)
	}
}

// WithNoTags makes sure that all returned columns contain no tags
func WithNoTags() ColumnFilter {
	return func(matcher ColumnMatcher) bool {
		return matcher.HasNoTags()
	}
}
