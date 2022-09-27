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
		opts.metadataTags = append(opts.metadataTags, metadataTag)
	}
}

type GadgetParserOptions struct {
	metadataTags []string
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
	var filter columns.ColumnFilter
	if len(opts.metadataTags) == 0 {
		filter = columns.WithNoTags()
	} else {
		filter = columns.WithNoTags()
		for _, tag := range opts.metadataTags {
			filter = columns.Or(filter, columns.WithTag(tag))
		}

	}
	colsMap := cols.GetColumnMap(filter)

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

func NewGadgetParserWithK8sInfo[T any](outputConfig *OutputConfig, cols *columns.Columns[T]) (*GadgetParser[T], error) {
	return NewGadgetParser(outputConfig, cols, WithMetadataTag(KubernetesTag))
}

func NewGadgetParserWithRuntimeInfo[T any](outputConfig *OutputConfig, cols *columns.Columns[T], appendK8sInfo bool) (*GadgetParser[T], error) {
	options := []Option{WithMetadataTag(ContainerRuntimeTag)}

	if appendK8sInfo || len(outputConfig.CustomColumns) != 0 {
		// Include Kubernetes columns but add them by last with prefix "k8s-"
		options = append(options, WithMetadataTag(KubernetesTag))
		for _, c := range cols.GetColumnMap(columns.WithTag(KubernetesTag)) {
			if c.Name == "node" {
				c.Visible = false
				continue
			}

			c.Order = 1000 * c.Order
			cols.RenameColumn(c.Name, "k8s-"+c.Name)
		}
	} else {
		// We anyway need to rename the Kubernetes container column as we want
		// the runtimeContainerName column to be the main one: "container".
		k8sContainerCol, ok := cols.GetColumn("container")
		if !ok {
			panic(`renaming "container" column`)
		}
		cols.RenameColumn(k8sContainerCol.Name, "k8s-"+k8sContainerCol.Name)
	}

	// Make runtimeContainerName the main container column
	runtimeContainerCol, ok := cols.GetColumn("runtimeContainerName")
	if !ok {
		panic(`renaming "runtimeContainerName" column`)
	}
	cols.RenameColumn(runtimeContainerCol.Name, "container")

	return NewGadgetParser(outputConfig, cols, options...)
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
