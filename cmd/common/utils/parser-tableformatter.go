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

package utils

import (
	"fmt"
	"os"
	"strings"

	"github.com/kinvolk/inspektor-gadget/pkg/columns/filter"

	"github.com/kinvolk/inspektor-gadget/pkg/columns"
	"github.com/kinvolk/inspektor-gadget/pkg/columns/formatter/textcolumns"
)

const (
	KubernetesTag       string = "kubernetes"
	ContainerRuntimeTag string = "runtime"
)

type Option func(*GadgetParserOptions)

func WithMetadataTag(metadataTag string) Option {
	return func(opts *GadgetParserOptions) {
		opts.metadataTag = metadataTag
	}
}

func WithFilters(filters []string) Option {
	return func(opts *GadgetParserOptions) {
		opts.filters = filters
	}
}

type GadgetParserOptions struct {
	metadataTag string
	filters     []string
}

// GadgetParser is a parser that helps printing the gadget output in columns
// using the columns and tableformatter packages.
type GadgetParser[T any] struct {
	formatter *textcolumns.TextColumnsFormatter[T]
	filters   []*filter.FilterSpec[T]
}

func NewGadgetParser[T any](outputConfig *OutputConfig, cols *columns.Columns[T], options ...Option) *GadgetParser[T] {
	var opts GadgetParserOptions

	for _, o := range options {
		o(&opts)
	}

	// If no tag is provided, we use only the columns with no specific tag. In
	// other words, the gadget-specific columns. Otherwise, we also include the
	// columns with the requested tag.
	var columnFilter columns.ColumnFilter
	if opts.metadataTag == "" {
		columnFilter = columns.WithNoTags()
	} else {
		columnFilter = columns.Or(columns.WithTag(opts.metadataTag), columns.WithNoTags())
	}

	var formatter *textcolumns.TextColumnsFormatter[T]
	if len(outputConfig.CustomColumns) != 0 {
		validCols, invalidCols := cols.VerifyColumnNames(outputConfig.CustomColumns)
		if len(invalidCols) != 0 {
			fmt.Fprintf(os.Stderr, "Warn: Ignoring invalid columns: %s\n", strings.Join(invalidCols, ", "))
		}

		formatter = textcolumns.NewFormatter(
			cols.GetColumnMap(columnFilter),
			textcolumns.WithDefaultColumns(validCols),
		)
	} else {
		formatter = textcolumns.NewFormatter(cols.GetColumnMap(columnFilter))
	}

	parser := &GadgetParser[T]{
		formatter: formatter,
	}

	// Create filters
	for _, f := range opts.filters {
		fspec, err := filter.GetFilterFromString(cols.GetColumnMap(columnFilter), f)
		if err != nil {
			// TODO: Error on failure
			continue
		}
		parser.filters = append(parser.filters, fspec)
	}

	return parser
}

func (p *GadgetParser[T]) BuildColumnsHeader() string {
	return p.formatter.FormatHeader()
}

func (p *GadgetParser[T]) TransformToColumns(entry *T) string {
	for _, f := range p.filters {
		if !f.Match(entry) {
			// TODO: make sure empty results lead to not printing anything at all
			return ""
		}
	}
	return p.formatter.FormatEntry(entry)
}
