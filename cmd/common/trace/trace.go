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

package trace

import (
	"github.com/spf13/cobra"

	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

type TraceEvent interface {
	any

	// The Go compiler does not support accessing a struct field x.f where x is
	// of type parameter type even if all types in the type parameter's type set
	// have a field f. We may remove this restriction in Go 1.19. See
	// https://tip.golang.org/doc/go1.18#generics.
	GetBaseEvent() *eventtypes.Event
}

// TraceParser defines the interface that every trace-gadget parser has to
// implement.
type TraceParser[Event any] interface {
	// Transform is called to transform an event to columns.
	TransformIntoColumns(event *Event) string

	// BuildColumnsHeader returns a header to be used when the user requests to
	// present the output in columns.
	BuildColumnsHeader() string
}

func NewCommonTraceCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "trace",
		Short: "Trace and print system events",
	}
}
