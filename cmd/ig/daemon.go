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
	"path/filepath"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	gadgetservice "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/persistence"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/persistence/files"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime"
)

const (
	DefaultDaemonPath = "unix:///var/run/ig.socket"
)

func addDaemonCommand(rootCmd *cobra.Command, runtime runtime.Runtime) {
	daemonCmd := &cobra.Command{
		Use:   "daemon",
		Short: "runs Inspektor Gadget as a daemon",
		RunE: func(cmd *cobra.Command, args []string) error {
			return nil
		},
	}

	var socket string
	var gid int

	daemonCmd.PersistentFlags().IntVarP(
		&gid,
		"daemon-group-id",
		"",
		0,
		"Group id that the unix socket should use (if daemon-socket is set to e.g. unix:///path/to.socket)")

	daemonCmd.PersistentFlags().StringVarP(
		&socket,
		"daemon-socket",
		"",
		DefaultDaemonPath,
		"The socket to listen on for new Inspektor Gadget requests. Can be a unix socket"+
			" (unix:///path/to.socket) or a tcp socket (tcp://127.0.0.1:1234)")

	daemonCmd.RunE = func(cmd *cobra.Command, args []string) error {
		if os.Geteuid() != 0 {
			return fmt.Errorf("%s must be run as root to be able to run eBPF programs", filepath.Base(os.Args[0]))
		}

		socketURL, err := url.Parse(socket)
		if err != nil {
			return fmt.Errorf("invalid daemon-socket address %q: %v", socketURL, err)
		}

		var socketPath string
		socketType := socketURL.Scheme
		switch socketType {
		default:
			return fmt.Errorf("invalid typye for daemon-socket %q; please use 'unix' or 'tcp'", socketType)
		case "unix":
			socketPath = socketURL.Path
		case "tcp":
			socketPath = socketURL.Host
		}

		// Create new persistence manager & store
		mgr := persistence.NewManager(runtime, false)
		store, _ := files.New(mgr)
		mgr.SetStore(store)

		log.Infof("starting Inspektor Gadget daemon at %q", socket)
		service := gadgetservice.NewService(log.StandardLogger(), mgr)
		return service.Run(socketType, socketPath, gid)
	}

	rootCmd.AddCommand(daemonCmd)
}
