// Copyright 2019-2021 The Inspektor Gadget authors
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
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/chzyer/readline"
	"github.com/spf13/cobra"

	"github.com/kinvolk/inspektor-gadget/cmd/kubectl-gadget/utils"
	containerutils "github.com/kinvolk/inspektor-gadget/pkg/container-utils"
	"github.com/kinvolk/inspektor-gadget/pkg/container-utils/containerd"
	"github.com/kinvolk/inspektor-gadget/pkg/container-utils/crio"
	"github.com/kinvolk/inspektor-gadget/pkg/container-utils/docker"
	localgadgetmanager "github.com/kinvolk/inspektor-gadget/pkg/local-gadget-manager"
	log "github.com/sirupsen/logrus"
)

// This variable is used by the "version" command and is set during build.
var version = "undefined"

var (
	runtimeConfigs     []*containerutils.RuntimeConfig
	localGadgetManager *localgadgetmanager.LocalGadgetManager
)

// Common commands between Inline and Root
var (
	versionCmd = &cobra.Command{
		Use:   "version",
		Short: "Show version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println(version)
		},
	}
)

func newRootCmd() *cobra.Command {
	var (
		optionFollow            bool
		optionOutputMode        string
		optionContainerSelector string

		rootCmd = &cobra.Command{
			Use:   "",
			Short: "Collection of gadgets for containers",
		}

		exitCmd = &cobra.Command{
			Use:   "exit",
			Short: "Exit",
			Run: func(cmd *cobra.Command, args []string) {
				os.Exit(0)
			},
		}

		listGadgetsCmd = &cobra.Command{
			Use:   "list-gadgets",
			Short: "List all gadgets",
			Run: func(cmd *cobra.Command, args []string) {
				for _, n := range localGadgetManager.ListGadgets() {
					fmt.Println(n)
				}
			},
		}

		listTracesCmd = &cobra.Command{
			Use:   "list-traces",
			Short: "List all traces",
			Run: func(cmd *cobra.Command, args []string) {
				for _, n := range localGadgetManager.ListTraces() {
					fmt.Println(n)
				}
			},
		}

		listContainersCmd = &cobra.Command{
			Use:   "list-containers",
			Short: "List all containers",
			Run: func(cmd *cobra.Command, args []string) {
				for _, n := range localGadgetManager.ListContainers() {
					fmt.Println(n)
				}
			},
		}

		createCmd = &cobra.Command{
			Use:   "create gadget-name trace-name",
			Short: "Create a new trace",
			Run: func(cmd *cobra.Command, args []string) {
				if len(args) != 2 {
					fmt.Println("missing gadget name or trace name")
					return
				}
				gadget, name := args[0], args[1]
				err := localGadgetManager.AddTracer(gadget, name, optionContainerSelector, optionOutputMode)
				if err != nil {
					fmt.Println(err.Error())
					return
				}

				operations := localGadgetManager.ListOperations(name)
				if len(operations) == 1 {
					err = localGadgetManager.Operation(name, operations[0])
				} else {
					err = localGadgetManager.Operation(name, "start")
				}

				if err != nil {
					fmt.Println(err.Error())
					return
				}
				ret, err := localGadgetManager.Show(name)
				if err != nil {
					fmt.Println(err.Error())
					return
				}
				fmt.Print(ret)
			},
		}

		operationCmd = &cobra.Command{
			Use:   "operation trace-name [operation-name]",
			Short: "Execute an operation on a trace",
			Run: func(cmd *cobra.Command, args []string) {
				if len(args) != 2 {
					fmt.Println("missing name or operation")
					return
				}
				name, opname := args[0], args[1]
				err := localGadgetManager.Operation(name, opname)
				if err != nil {
					fmt.Println(err.Error())
					return
				}
				ret, err := localGadgetManager.Show(name)
				if err != nil {
					fmt.Println(err.Error())
					return
				}
				fmt.Print(ret)
			},
		}

		showCmd = &cobra.Command{
			Use:   "show trace-name",
			Short: "Show the status of a trace",
			Run: func(cmd *cobra.Command, args []string) {
				if len(args) != 1 {
					fmt.Println("missing name")
					return
				}
				name := args[0]
				ret, err := localGadgetManager.Show(name)
				if err != nil {
					fmt.Println(err.Error())
					return
				}
				fmt.Print(ret)
			},
		}

		streamCmd = &cobra.Command{
			Use:   "stream trace-name",
			Short: "Show the stream output of a trace",
			Run: func(cmd *cobra.Command, args []string) {
				if len(args) != 1 {
					fmt.Println("missing name")
					return
				}
				name := args[0]
				var stop chan struct{}
				sigs := make(chan os.Signal, 1)
				if optionFollow {
					stop = make(chan struct{})
					signal.Notify(sigs, syscall.SIGINT)
				}
				ch, err := localGadgetManager.Stream(name, stop)
				if err != nil {
					fmt.Printf("Error: %s\n", err)
					return
				}
			Loop:
				for {
					select {
					case line, ok := <-ch:
						if !ok {
							break Loop
						}
						fmt.Println(line)
					case <-sigs:
						signal.Stop(sigs)
						stop <- struct{}{}
					}
				}
				return
			},
		}

		deleteCmd = &cobra.Command{
			Use:   "delete trace-name",
			Short: "Delete a trace",
			Run: func(cmd *cobra.Command, args []string) {
				if len(args) != 1 {
					fmt.Println("missing name")
					return
				}
				name := args[0]
				err := localGadgetManager.Delete(name)
				if err != nil {
					fmt.Println(err.Error())
				}
			},
		}

		dumpCmd = &cobra.Command{
			Use:   "dump",
			Short: "Dump internal data",
			Run: func(cmd *cobra.Command, args []string) {
				fmt.Println(localGadgetManager.Dump())
			},
		}

		completionCmd = &cobra.Command{
			Use:    "completion",
			Hidden: true,
		}
	)

	cobra.EnableCommandSorting = false
	rootCmd.AddCommand(
		completionCmd,
		listGadgetsCmd,
		listContainersCmd,
		listTracesCmd,
		createCmd,
		operationCmd,
		showCmd,
		streamCmd,
		deleteCmd,
		dumpCmd,
		versionCmd,
		exitCmd,
	)

	streamCmd.Flags().BoolVarP(
		&optionFollow,
		"follow", "f",
		false,
		"output appended data as the stream grows")

	createCmd.Flags().StringVarP(
		&optionOutputMode,
		"output-mode", "",
		"",
		"output mode")

	createCmd.Flags().StringVarP(
		&optionContainerSelector,
		"container-selector", "c",
		"",
		"container name")

	return rootCmd
}

func runLocalGadget(cmd *cobra.Command, args []string) error {
	var err error

	localGadgetManager, err = localgadgetmanager.NewManager(runtimeConfigs)
	if err != nil {
		return fmt.Errorf("failed to initialize manager: %w", err)
	}

	homedir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get user's home directory: %w", err)
	}

	completer := readline.NewPrefixCompleter(
		readline.PcItem("list-gadgets"),
		readline.PcItem("list-containers"),
		readline.PcItem("list-traces"),
		readline.PcItem("create",
			readline.PcItemDynamic(func(string) []string {
				return localGadgetManager.ListGadgets()
			},
				readline.PcItemDynamic(func(string) []string {
					n := len(localGadgetManager.ListTraces())
					return []string{fmt.Sprintf("trace%d", n+1)}
				},
					readline.PcItem("--container-selector",
						readline.PcItemDynamic(func(string) []string {
							return localGadgetManager.ListContainers()
						}),
					),
					readline.PcItem("--output-mode",
						readline.PcItemDynamic(func(line string) []string {
							fields := strings.Fields(line)
							if len(fields) < 2 {
								return []string{}
							}
							// TODO: this might select the wrong field if flags are placed elsewhere
							gadget := fields[1]
							outputModesSupported, err := localGadgetManager.GadgetOutputModesSupported(gadget)
							if err != nil {
								return nil
							}
							return outputModesSupported
						}),
					),
				),
			),
		),
		readline.PcItem("operation",
			readline.PcItemDynamic(func(string) []string {
				return localGadgetManager.ListTraces()
			},
				readline.PcItemDynamic(func(line string) []string {
					fields := strings.Fields(line)
					if len(fields) < 2 {
						return []string{}
					}
					// TODO: this might select the wrong field if flags are placed elsewhere
					traceName := fields[1]
					return localGadgetManager.ListOperations(traceName)
				}),
			),
		),
		readline.PcItem("show",
			readline.PcItemDynamic(func(string) []string {
				return localGadgetManager.ListTraces()
			}),
		),
		readline.PcItem("stream",
			readline.PcItemDynamic(func(string) []string {
				return localGadgetManager.ListTraces()
			},
				readline.PcItem("--follow"),
			),
		),
		readline.PcItem("delete",
			readline.PcItemDynamic(func(string) []string {
				return localGadgetManager.ListTraces()
			}),
		),
		readline.PcItem("dump"),
		readline.PcItem("version"),
		readline.PcItem("exit"),
		readline.PcItem("help"),
	)

	l, err := readline.NewEx(&readline.Config{
		Prompt:          "\033[31m»\033[0m ",
		HistoryFile:     filepath.Join(homedir, ".local-gadget.history"),
		AutoComplete:    completer,
		InterruptPrompt: "^C",
		EOFPrompt:       "exit",
	})
	if err != nil {
		return fmt.Errorf("failed to initialize reader: %w", err)
	}
	defer l.Close()

	for {
		input, err := l.Readline()
		if errors.Is(err, readline.ErrInterrupt) {
			if len(input) == 0 {
				break
			}
			continue
		} else if errors.Is(err, io.EOF) {
			break
		}

		input = strings.TrimSpace(input)
		if input == "" {
			continue
		}

		if err = execInput(input); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
	}

	return nil
}

func main() {
	var (
		verbose              bool
		runtimes             string
		dockerSocketPath     string
		containerdSocketPath string
		crioSocketPath       string
	)

	localGadgetCmd := &cobra.Command{
		Use:          "local-gadget",
		Short:        "Collection of gadgets for containers",
		SilenceUsage: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if verbose {
				log.StandardLogger().SetLevel(log.DebugLevel)
			}

			parts := strings.Split(runtimes, ",")

		partsLoop:
			for _, p := range parts {
				runtimeName := strings.TrimSpace(p)
				socketPath := ""

				switch runtimeName {
				case docker.Name:
					socketPath = dockerSocketPath
				case containerd.Name:
					socketPath = containerdSocketPath
				case crio.Name:
					socketPath = crioSocketPath
				default:
					return utils.WrapInErrInvalidArg("--runtime / -r",
						fmt.Errorf("runtime %q is not supported", p))
				}

				for _, r := range runtimeConfigs {
					if r.Name == runtimeName {
						log.Infof("Ignoring duplicated runtime %q from %q",
							runtimeName, runtimes)
						continue partsLoop
					}
				}

				runtimeConfigs = append(runtimeConfigs, &containerutils.RuntimeConfig{
					Name:       runtimeName,
					SocketPath: socketPath,
				})
			}

			return nil
		},
		RunE: runLocalGadget,
	}

	localGadgetCmd.PersistentFlags().BoolVarP(
		&verbose,
		"verbose", "v",
		false,
		"Print debug information",
	)

	localGadgetCmd.Flags().StringVarP(
		&runtimes,
		"runtimes", "r",
		strings.Join(containerutils.AvailableRuntimes, ","),
		fmt.Sprintf("Container runtimes to be used separated by comma. Supported values are: %s",
			strings.Join(containerutils.AvailableRuntimes, ", ")),
	)

	localGadgetCmd.PersistentFlags().StringVarP(
		&dockerSocketPath,
		"docker-socketpath", "",
		docker.DefaultSocketPath,
		"Docker Engine API Unix socket path",
	)

	localGadgetCmd.PersistentFlags().StringVarP(
		&containerdSocketPath,
		"containerd-socketpath", "",
		containerd.DefaultSocketPath,
		"Containerd CRI Unix socket path",
	)

	localGadgetCmd.PersistentFlags().StringVarP(
		&crioSocketPath,
		"crio-socketpath", "",
		crio.DefaultSocketPath,
		"CRI-O CRI Unix socket path",
	)

	localGadgetCmd.AddCommand(
		versionCmd,
	)

	if err := localGadgetCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func execInput(input string) error {
	rootCmd := newRootCmd()

	args := strings.Split(input, " ")
	rootCmd.SetArgs(args)

	err := rootCmd.Execute()
	return err
}
