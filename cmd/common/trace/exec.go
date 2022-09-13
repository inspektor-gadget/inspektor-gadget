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

	commonutils "github.com/kinvolk/inspektor-gadget/cmd/common/utils"
	execTypes "github.com/kinvolk/inspektor-gadget/pkg/gadgets/trace/exec/types"
)

func newExecParser(outputConfig *commonutils.OutputConfig, options ...commonutils.Option) TraceParser[execTypes.Event] {
	return commonutils.NewGadgetParser(outputConfig, execTypes.MustGetColumns(), options...)
}

func NewExecParserWithK8sInfo(outputConfig *commonutils.OutputConfig) TraceParser[execTypes.Event] {
	return newExecParser(outputConfig, commonutils.WithMetadataTag(commonutils.KubernetesTag))
}

func NewExecParserWithRuntimeInfo(outputConfig *commonutils.OutputConfig) TraceParser[execTypes.Event] {
	return newExecParser(outputConfig, commonutils.WithMetadataTag(commonutils.ContainerRuntimeTag))
}

func NewExecParser(outputConfig *commonutils.OutputConfig) TraceParser[execTypes.Event] {
	return newExecParser(outputConfig)
}

func NewExecCmd(runCmd func(*cobra.Command, []string) error) *cobra.Command {
	return &cobra.Command{
		Use:   "exec",
		Short: "Trace new processes",
		RunE:  runCmd,
	}
}
