// Copyright 2023 The Inspektor Gadget authors
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

package main

import (
	"fmt"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"strconv"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	gadgetservice "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime"
)

func newDaemonCommand(runtime runtime.Runtime) *cobra.Command {
	daemonCmd := &cobra.Command{
		Use:          "daemon",
		Short:        "Run Inspektor Gadget as a daemon",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
	}

	var socket string
	var group string

	daemonCmd.PersistentFlags().StringVarP(
		&group,
		"group",
		"G",
		"0",
		"Group name or id that the unix socket should use (if daemon-socket is set to e.g. unix:///path/to.socket)")

	daemonCmd.PersistentFlags().StringVarP(
		&socket,
		"host",
		"H",
		api.DefaultDaemonPath,
		"The socket to listen on for new requests. Can be a unix socket"+
			" (unix:///path/to.socket) or a tcp socket (tcp://127.0.0.1:1234)")

	daemonCmd.RunE = func(cmd *cobra.Command, args []string) error {
		if os.Geteuid() != 0 {
			return fmt.Errorf("%s must be run as root to be able to run eBPF programs", filepath.Base(os.Args[0]))
		}

		socketURL, err := url.Parse(socket)
		if err != nil {
			return fmt.Errorf("invalid daemon-socket address %q: %w", socketURL, err)
		}

		gid := 0
		if tmpGroup, err := user.LookupGroup(group); err == nil {
			gid, err = strconv.Atoi(tmpGroup.Gid)
			if err != nil {
				return fmt.Errorf("unexpected non-numeric group id %q for group %q", tmpGroup.Gid, group)
			}
		} else if tmpGid, err := strconv.Atoi(group); err == nil {
			gid = tmpGid
		} else {
			return fmt.Errorf("group %q not found", group)
		}

		var socketPath string
		socketType := socketURL.Scheme
		switch socketType {
		default:
			return fmt.Errorf("invalid type for daemon-socket %q; please use 'unix' or 'tcp'", socketType)
		case "unix":
			socketPath = socketURL.Path
		case "tcp":
			socketPath = socketURL.Host
		}

		log.Infof("starting Inspektor Gadget daemon at %q", socket)
		service := gadgetservice.NewService(log.StandardLogger())
		return service.Run(gadgetservice.RunConfig{
			SocketType: socketType,
			SocketPath: socketPath,
			SocketGID:  gid,
		})
	}

	return daemonCmd
}
