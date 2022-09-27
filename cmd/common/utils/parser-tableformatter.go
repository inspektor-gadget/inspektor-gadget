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
	"strings"

	"github.com/kinvolk/inspektor-gadget/pkg/columns"
	"github.com/kinvolk/inspektor-gadget/pkg/columns/formatter/textcolumns"
	"github.com/kinvolk/inspektor-gadget/pkg/columns/sort"
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

type GadgetParserOptions struct {
	metadataTag string
}

// GadgetParser is a parser that helps printing the gadget output in columns
// using the columns and formatter/textcolumns packages.
type GadgetParser[T any] struct {
	formatter *textcolumns.TextColumnsFormatter[T]
	colsMap   columns.ColumnMap[T]
}

func NewGadgetParser[T any](outputConfig *OutputConfig, cols *columns.Columns[T], options ...Option) (*GadgetParser[T], error) {
	var opts GadgetParserOptions

	for _, o := range options {
		o(&opts)
	}

	// If no tag is provided, we use only the columns with no specific tag. In
	// other words, the gadget-specific columns. Otherwise, we also include the
	// columns with the requested tag.
	var colsMap columns.ColumnMap[T]
	if opts.metadataTag == "" {
		colsMap = cols.GetColumnMap(columns.WithNoTags())
	} else {
		colsMap = cols.GetColumnMap(columns.Or(columns.WithTag(opts.metadataTag), columns.WithNoTags()))
	}

	var formatter *textcolumns.TextColumnsFormatter[T]
	if len(outputConfig.CustomColumns) != 0 {
		validCols, invalidCols := cols.VerifyColumnNames(outputConfig.CustomColumns)
		if len(invalidCols) != 0 {
			return nil, fmt.Errorf("invalid columns: %s", strings.Join(invalidCols, ", "))
		}

		formatter = textcolumns.NewFormatter(
			colsMap,
			textcolumns.WithDefaultColumns(validCols),
		)
	} else {
		formatter = textcolumns.NewFormatter(colsMap)
	}

	return &GadgetParser[T]{
		formatter: formatter,
		colsMap:   colsMap,
	}, nil
}

func NewGadgetParserWithK8sInfo[T any](outputConfig *OutputConfig, columns *columns.Columns[T]) (*GadgetParser[T], error) {
	return NewGadgetParser(outputConfig, columns, WithMetadataTag(KubernetesTag))
}

func NewGadgetParserWithRuntimeInfo[T any](outputConfig *OutputConfig, columns *columns.Columns[T]) (*GadgetParser[T], error) {
	return NewGadgetParser(outputConfig, columns, WithMetadataTag(ContainerRuntimeTag))
}

func (p *GadgetParser[T]) BuildColumnsHeader() string {
	return p.formatter.FormatHeader()
}

func (p *GadgetParser[T]) TransformIntoColumns(entry *T) string {
	return p.formatter.FormatEntry(entry)
}

func (p *GadgetParser[T]) TransformIntoTable(entries []*T) string {
	// Disable auto-scaling as AdjustWidthsToContent will already manage the
	// screen size.
	p.formatter.SetAutoScale(false)
	p.formatter.AdjustWidthsToContent(entries, true, textcolumns.GetTerminalWidth(), true)
	return p.formatter.FormatTable(entries)
}

func (p *GadgetParser[T]) Sort(entries []*T, sortBy []string) {
	sort.SortEntries(p.colsMap, entries, sortBy)
}
