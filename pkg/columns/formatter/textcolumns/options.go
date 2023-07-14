// Copyright 2022-2023 The Inspektor Gadget authors
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

package textcolumns

type HeaderStyle int

const (
	HeaderStyleNormal HeaderStyle = iota
	HeaderStyleUppercase
	HeaderStyleLowercase
)

const (
	DividerSpace = " "
	DividerTab   = "\t"
	DividerDash  = "—"
	DividerNone  = ""
)

type Option func(*Options)

type Options struct {
	AutoScale      bool        // if enabled, the screen size will be used to scale the widths
	ColumnDivider  string      // defines the string that should be used as spacer in between columns (default " ")
	DefaultColumns []string    // defines which columns to show by default; will be set to all visible columns if nil
	HeaderStyle    HeaderStyle // defines how column headers are decorated (e.g. uppercase/lowercase)
	RowDivider     string      // defines the (to be repeated) string that should be used below the header
	StripPrefixes  []string    // defines prefixes to strip from embedded (prefixed) columns
}

func DefaultOptions() *Options {
	return &Options{
		AutoScale:      true,
		ColumnDivider:  DividerSpace,
		DefaultColumns: nil,
		HeaderStyle:    HeaderStyleUppercase,
		RowDivider:     DividerNone,
	}
}

// WithAutoScale sets whether auto-scaling to screen width should be enabled
func WithAutoScale(autosScale bool) Option {
	return func(opts *Options) {
		opts.AutoScale = autosScale
	}
}

// WithColumnDivider sets the string that should be used as divider between columns
func WithColumnDivider(divider string) Option {
	return func(opts *Options) {
		opts.ColumnDivider = divider
	}
}

// WithDefaultColumns sets the columns that should be displayed by default
func WithDefaultColumns(columns []string) Option {
	return func(opts *Options) {
		opts.DefaultColumns = columns
	}
}

// WithHeaderStyle sets the style to be used for the table header
func WithHeaderStyle(headerStyle HeaderStyle) Option {
	return func(opts *Options) {
		opts.HeaderStyle = headerStyle
	}
}

// WithRowDivider sets the string that should be used (repeatedly) to build the divider between header and content
func WithRowDivider(divider string) Option {
	return func(opts *Options) {
		opts.RowDivider = divider
	}
}

// WithStripPrefixes sets prefixes that should be stripped from column names
func WithStripPrefixes(prefixes []string) Option {
	return func(opts *Options) {
		opts.StripPrefixes = prefixes
	}
}
