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

	commonutils "github.com/inspektor-gadget/inspektor-gadget/cmd/common/utils"
	containerutils "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/containerd"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/crio"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/docker"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// CommonFlags contains CLI flags common to several gadgets.
type CommonFlags struct {
	// OutputConfig describes the way output should be printed.
	commonutils.OutputConfig

	// Containername allows to filter containers by name.
	Containername string

	// The name of the container runtimes to be used separated by comma.
	Runtimes string

	// DockerSocketPath is the Docker Engine API Unix socket path.
	DockerSocketPath string

	// ContainerdSocketPath is the containerd CRI Unix socket path.
	ContainerdSocketPath string

	// CrioSocketPath is the CRI-O CRI Unix socket path.
	CrioSocketPath string

	// RuntimeConfigs contains the list of the container runtimes to be used
	// with their specific socket path.
	RuntimeConfigs []*containerutils.RuntimeConfig
}

func AddCommonFlags(command *cobra.Command, commonFlags *CommonFlags) {
	command.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
		// Runtimes Configuration
		parts := strings.Split(commonFlags.Runtimes, ",")

	partsLoop:
		for _, p := range parts {
			runtimeName := strings.TrimSpace(p)
			socketPath := ""

			switch runtimeName {
			case docker.Name:
				socketPath = commonFlags.DockerSocketPath
			case containerd.Name:
				socketPath = commonFlags.ContainerdSocketPath
			case crio.Name:
				socketPath = commonFlags.CrioSocketPath
			default:
				return commonutils.WrapInErrInvalidArg("--runtime / -r",
					fmt.Errorf("runtime %q is not supported", p))
			}

			for _, r := range commonFlags.RuntimeConfigs {
				if r.Name == runtimeName {
					log.Infof("Ignoring duplicated runtime %q from %q",
						runtimeName, commonFlags.Runtimes)
					continue partsLoop
				}
			}

			commonFlags.RuntimeConfigs = append(commonFlags.RuntimeConfigs, &containerutils.RuntimeConfig{
				Name:       runtimeName,
				SocketPath: socketPath,
			})
		}

		// Output Mode
		if err := commonFlags.ParseOutputConfig(); err != nil {
			return err
		}

		return nil
	}

	// do not print usage when there is an error
	command.SilenceUsage = true

	command.PersistentFlags().BoolVarP(
		&commonFlags.Verbose,
		"verbose", "v",
		false,
		"Print debug information",
	)

	command.PersistentFlags().StringVarP(
		&commonFlags.OutputMode,
		"output",
		"o",
		commonutils.OutputModeColumns,
		fmt.Sprintf("Output format (%s).", strings.Join(commonutils.SupportedOutputModes, ", ")),
	)

	command.PersistentFlags().StringVarP(
		&commonFlags.Containername,
		"containername",
		"c",
		"",
		"Show only data from containers with that name",
	)

	command.PersistentFlags().StringVarP(
		&commonFlags.Runtimes,
		"runtimes", "r",
		strings.Join(containerutils.AvailableRuntimes, ","),
		fmt.Sprintf("Container runtimes to be used separated by comma. Supported values are: %s",
			strings.Join(containerutils.AvailableRuntimes, ", ")),
	)

	command.PersistentFlags().StringVarP(
		&commonFlags.DockerSocketPath,
		"docker-socketpath", "",
		docker.DefaultSocketPath,
		"Docker Engine API Unix socket path",
	)

	command.PersistentFlags().StringVarP(
		&commonFlags.ContainerdSocketPath,
		"containerd-socketpath", "",
		containerd.DefaultSocketPath,
		"containerd CRI Unix socket path",
	)

	command.PersistentFlags().StringVarP(
		&commonFlags.CrioSocketPath,
		"crio-socketpath", "",
		crio.DefaultSocketPath,
		"CRI-O CRI Unix socket path",
	)
}
