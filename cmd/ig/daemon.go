// Copyright 2023-2024 The Inspektor Gadget authors
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
	"crypto/tls"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/inspektor-gadget/inspektor-gadget/cmd/common"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/config"
	gadgetservice "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime"
	gadgettls "github.com/inspektor-gadget/inspektor-gadget/pkg/utils/tls"
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
	var eventBufferLength uint64
	var serverKey string
	var serverCert string
	var clientCA string

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

	daemonCmd.PersistentFlags().Uint64VarP(
		&eventBufferLength,
		"events-buffer-length",
		"",
		16384,
		"The events buffer length. A low value could impact horizontal scaling.")

	daemonCmd.PersistentFlags().StringVar(
		&serverKey,
		"tls-key-file",
		"",
		"Path to TLS key file")

	daemonCmd.PersistentFlags().StringVar(
		&serverCert,
		"tls-cert-file",
		"",
		"Path to TLS cert file")

	daemonCmd.PersistentFlags().StringVar(
		&clientCA,
		"tls-client-ca-file",
		"",
		"Path to CA certificate for client validation")

	service := gadgetservice.NewService(log.StandardLogger())

	for _, params := range service.GetOperatorMap() {
		common.AddFlags(daemonCmd, params, nil, runtime)
	}

	daemonCmd.RunE = func(cmd *cobra.Command, args []string) error {
		if os.Geteuid() != 0 {
			return fmt.Errorf("%s must be run as root to be able to run eBPF programs", filepath.Base(os.Args[0]))
		}

		socketType, socketPath, err := api.ParseSocketAddress(socket)
		if err != nil {
			return fmt.Errorf("invalid daemon-socket address: %w", err)
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

		log.Infof("starting Inspektor Gadget daemon at %q", socket)
		service.SetEventBufferLength(eventBufferLength)

		if err = config.Config.ReadInConfig(); err != nil {
			log.Warnf("reading config: %v", err)
		}

		tlsOptionsSet := 0
		for _, tlsOption := range []string{serverKey, serverCert, clientCA} {
			if len(tlsOption) != 0 {
				tlsOptionsSet++
			}
		}

		if tlsOptionsSet > 1 && tlsOptionsSet < 3 {
			return fmt.Errorf(`
missing at least one the TLS related options:
	* tls-key-file: %q
	* tls-cert-file: %q
	* tls-client-ca-file: %q
All these options should be set at the same time to enable TLS connection`,
				serverKey, serverCert, clientCA)
		}

		var options []grpc.ServerOption

		if tlsOptionsSet == 3 {
			cert, err := gadgettls.LoadTLSCert(serverCert, serverKey)
			if err != nil {
				return fmt.Errorf("creating TLS certificate: %w", err)
			}

			ca, err := gadgettls.LoadTLSCA(clientCA)
			if err != nil {
				return fmt.Errorf("creating TLS certificate authority: %w", err)
			}

			tlsConfig := &tls.Config{
				ClientAuth:   tls.RequireAndVerifyClientCert,
				Certificates: []tls.Certificate{cert},
				ClientCAs:    ca,
			}

			options = append(options, grpc.Creds(credentials.NewTLS(tlsConfig)))

			log.Debugf("TLS is enabled using %v, %v and %v", serverKey, serverCert, clientCA)
		} else if !strings.HasPrefix(socketPath, "unix") {
			log.Warnf("no TLS configuration provided, communication between daemon and CLI will not be encrypted")
		}

		return service.Run(gadgetservice.RunConfig{
			SocketType: socketType,
			SocketPath: socketPath,
			SocketGID:  gid,
		}, options...)
	}

	return daemonCmd
}
