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

package containers

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	commonutils "github.com/kinvolk/inspektor-gadget/cmd/common/utils"
	"github.com/kinvolk/inspektor-gadget/cmd/local-gadget/utils"
	containercollection "github.com/kinvolk/inspektor-gadget/pkg/container-collection"
	localgadgetmanager "github.com/kinvolk/inspektor-gadget/pkg/local-gadget-manager"
)

type ContainerFlags struct {
	noTrunc bool
}

type ContainerParser struct {
	commonutils.BaseParser

	containerFlags *ContainerFlags
}

func NewListContainersCmd() *cobra.Command {
	var containerFlags ContainerFlags

	availableColumns := []string{
		"runtime",
		"id",
		"name",
		"pid",
		"mntns",
		"netns",
		"namespace",
		"podname",
		"poduid",
		"cgrouppath",
		"cgroupid",
		"cgroupv1",
		"cgroupv2",
	}

	commonFlags := &utils.CommonFlags{
		OutputConfig: commonutils.OutputConfig{
			// The columns that will be used in case the user does not specify
			// which specific columns they want to print.
			CustomColumns: []string{
				"runtime",
				"id",
				"name",
			},
		},
	}

	cmd := &cobra.Command{
		Use:   "list-containers",
		Short: "List all containers",
		RunE: func(*cobra.Command, []string) error {
			localGadgetManager, err := localgadgetmanager.NewManager(commonFlags.RuntimeConfigs)
			if err != nil {
				return fmt.Errorf("failed to initialize manager: %w", err)
			}
			defer localGadgetManager.Close()

			parser := &ContainerParser{
				BaseParser:     commonutils.NewBaseTabParser(availableColumns, &commonFlags.OutputConfig),
				containerFlags: &containerFlags,
			}

			containers := localGadgetManager.GetContainersBySelector(&containercollection.ContainerSelector{
				Name: commonFlags.Containername,
			})

			parser.SortContainers(containers)

			switch commonFlags.OutputMode {
			case commonutils.OutputModeJSON:
				b, err := json.MarshalIndent(containers, "", "  ")
				if err != nil {
					return commonutils.WrapInErrMarshalOutput(err)
				}

				fmt.Printf("%s\n", b)
			case commonutils.OutputModeColumns:
				fallthrough
			case commonutils.OutputModeCustomColumns:
				w := tabwriter.NewWriter(os.Stdout, 0, 0, 4, ' ', 0)

				fmt.Fprintln(w, parser.BuildColumnsHeader())

				for _, c := range containers {
					fmt.Fprintln(w, parser.TransformContainerToColumns(c))
				}

				w.Flush()
			default:
				return commonutils.WrapInErrOutputModeNotSupported(commonFlags.OutputMode)
			}

			return nil
		},
	}

	cmd.PersistentFlags().BoolVar(
		&containerFlags.noTrunc,
		"no-trunc",
		false,
		"Don't truncate container ID",
	)

	utils.AddCommonFlags(cmd, commonFlags)

	return cmd
}

func (p *ContainerParser) SortContainers(containers []*containercollection.Container) {
	sort.Slice(containers, func(i, j int) bool {
		si, sj := (containers)[i], (containers)[j]
		switch {
		case si.Runtime != sj.Runtime:
			return si.Runtime < sj.Runtime
		case si.Name != sj.Name:
			return si.Name < sj.Name
		default:
			return si.ID < sj.ID
		}
	})
}

func (p *ContainerParser) TransformContainerToColumns(c *containercollection.Container) string {
	var sb strings.Builder

	for _, col := range p.OutputConfig.CustomColumns {
		switch col {
		case "runtime":
			sb.WriteString(fmt.Sprintf("%s", c.Runtime))
		case "id":
			if p.containerFlags.noTrunc {
				sb.WriteString(fmt.Sprintf("%s", c.ID))
			} else {
				sb.WriteString(fmt.Sprintf("%.13s", c.ID))
			}
		case "name":
			sb.WriteString(fmt.Sprintf("%s", c.Name))
		case "pid":
			sb.WriteString(fmt.Sprintf("%d", c.Pid))
		case "mntns":
			sb.WriteString(fmt.Sprintf("%d", c.Mntns))
		case "netns":
			sb.WriteString(fmt.Sprintf("%d", c.Netns))
		case "namespace":
			sb.WriteString(fmt.Sprintf("%s", c.Namespace))
		case "podname":
			sb.WriteString(fmt.Sprintf("%s", c.Podname))
		case "poduid":
			sb.WriteString(fmt.Sprintf("%s", c.PodUID))
		case "cgrouppath":
			sb.WriteString(fmt.Sprintf("%s", c.CgroupPath))
		case "cgroupid":
			sb.WriteString(fmt.Sprintf("%d", c.CgroupID))
		case "cgroupv1":
			sb.WriteString(fmt.Sprintf("%s", c.CgroupV1))
		case "cgroupv2":
			sb.WriteString(fmt.Sprintf("%s", c.CgroupV2))
		default:
			continue
		}
		sb.WriteRune('\t')
	}

	return sb.String()
}
