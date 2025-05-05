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

	"github.com/containerd/containerd/pkg/cri/constants"
	securejoin "github.com/cyphar/filepath-securejoin"

	commonutils "github.com/inspektor-gadget/inspektor-gadget/cmd/common/utils"
	containerutils "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils"
	containerutilsTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// CommonFlags contains CLI flags common to several gadgets.
type CommonFlags struct {
	// OutputConfig describes the way output should be printed.
	commonutils.OutputConfig

	// Saves all runtime socket paths
	commonutils.RuntimesSocketPathConfig

	// Containername allows to filter containers by name.
	Containername string

	// Comma-separated list of container runtimes.
	Runtimes string

	// Host, when set to true, specifies to include all events both from
	// the host and from containers.
	Host bool

	// RuntimeConfigs contains the list of the container runtimes to be used
	// with their specific socket path.
	RuntimeConfigs []*containerutilsTypes.RuntimeConfig

	// Number of seconds that the gadget will run for
	Timeout int

	// ContainerdNamespace is the namespace used by containerd
	ContainerdNamespace string

	// RuntimeProtocol specifies whether to use the CRI API to talk to the runtime.
	// Useful for docker and containerd.
	// CRI-O is always using the CRI API. Podman is always using the internal API.
	// Supported values: internal, cri.
	RuntimeProtocol string
}

func AddCommonFlags(command *cobra.Command, commonFlags *CommonFlags) {
	command.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
		// Runtimes Configuration
		switch commonFlags.RuntimeProtocol {
		case containerutilsTypes.RuntimeProtocolInternal:
		case containerutilsTypes.RuntimeProtocolCRI:
		default:
			return commonutils.WrapInErrInvalidArg("--runtime-protocol",
				fmt.Errorf("runtime protocol %q is not supported", commonFlags.RuntimeProtocol))
		}

		parts := strings.Split(commonFlags.Runtimes, ",")

	partsLoop:
		for _, p := range parts {
			runtimeName := types.String2RuntimeName(strings.TrimSpace(p))
			socketPath := ""
			namespace := ""
			var err error

			switch runtimeName {
			case types.RuntimeNameDocker:
				socketPath, err = securejoin.SecureJoin(host.HostRoot, commonFlags.Docker)
			case types.RuntimeNameContainerd:
				socketPath, err = securejoin.SecureJoin(host.HostRoot, commonFlags.Containerd)
				namespace = commonFlags.ContainerdNamespace
			case types.RuntimeNameCrio:
				socketPath, err = securejoin.SecureJoin(host.HostRoot, commonFlags.Crio)
			case types.RuntimeNamePodman:
				socketPath, err = securejoin.SecureJoin(host.HostRoot, commonFlags.Podman)
			default:
				return commonutils.WrapInErrInvalidArg("--runtime / -r",
					fmt.Errorf("runtime %q is not supported", p))
			}

			if err != nil {
				return fmt.Errorf("securejoining %v to %v socket path: %w", host.HostRoot, runtimeName, err)
			}

			for _, r := range commonFlags.RuntimeConfigs {
				if r.Name == runtimeName {
					log.Infof("Ignoring duplicated runtime %q from %q",
						runtimeName, commonFlags.Runtimes)
					continue partsLoop
				}
			}

			r := &containerutilsTypes.RuntimeConfig{
				Name:            runtimeName,
				SocketPath:      socketPath,
				RuntimeProtocol: commonFlags.RuntimeProtocol,
				Extra: containerutilsTypes.ExtraConfig{
					Namespace: namespace,
				},
			}

			commonFlags.RuntimeConfigs = append(commonFlags.RuntimeConfigs, r)
		}

		// Output Mode
		if err := commonFlags.ParseOutputConfig(); err != nil {
			return err
		}

		return nil
	}

	// do not print usage when there is an error
	command.SilenceUsage = true

	commonutils.AddOutputFlags(command, &commonFlags.OutputConfig)
	commonutils.AddRuntimesSocketPathFlags(command, &commonFlags.RuntimesSocketPathConfig)

	command.PersistentFlags().StringVarP(
		&commonFlags.Containername,
		"containername",
		"c",
		"",
		"Show only data from containers with that name",
	)
	command.PersistentFlags().BoolVarP(
		&commonFlags.Host,
		"host",
		"",
		false,
		"Show data from both the host and containers",
	)

	command.PersistentFlags().StringVarP(
		&commonFlags.Runtimes,
		"runtimes", "r",
		strings.Join(containerutils.AvailableRuntimes, ","),
		fmt.Sprintf("Comma-separated list of container runtimes. Supported values are: %s",
			strings.Join(containerutils.AvailableRuntimes, ", ")),
	)

	command.PersistentFlags().IntVar(
		&commonFlags.Timeout,
		"timeout",
		0,
		"Number of seconds that the gadget will run for",
	)

	command.PersistentFlags().StringVar(
		&commonFlags.ContainerdNamespace,
		"containerd-namespace",
		constants.K8sContainerdNamespace,
		"Namespace used by containerd",
	)

	command.PersistentFlags().StringVar(
		&commonFlags.RuntimeProtocol,
		"runtime-protocol",
		containerutilsTypes.RuntimeProtocolInternal,
		fmt.Sprintf("Container runtime protocol (docker and containerd). Supported values are: %s",
			strings.Join(containerutils.AvailableRuntimeProtocols, ", ")),
	)
}

func HideFlagTimeout(command *cobra.Command) {
	command.PersistentFlags().MarkHidden("timeout")
}
