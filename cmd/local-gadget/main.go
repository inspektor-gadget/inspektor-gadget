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
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/chzyer/readline"
	"github.com/spf13/cobra"

	"github.com/kinvolk/inspektor-gadget/pkg/local-gadget-manager"
)

// This variable is used by the "version" command and is set during build.
var version = "undefined"

var localGadgetManager *localgadgetmanager.LocalGadgetManager

func newRootCmd() *cobra.Command {
	var (
		optionFollow = false

		rootCmd = &cobra.Command{
			Use:   "",
			Short: "Collection of gadgets for containers",
		}

		versionCmd = &cobra.Command{
			Use:   "version",
			Short: "Show version",
			Run: func(cmd *cobra.Command, args []string) {
				fmt.Println(version)
			},
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
			Short: "List all traces",
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

		traceCmd = &cobra.Command{
			Use:   "trace gadget-name trace-name [ container-filter ]",
			Short: "Create a new trace",
			RunE: func(cmd *cobra.Command, args []string) error {
				if len(args) < 2 {
					return fmt.Errorf("missing gadget name or trace name")
				}
				if len(args) > 3 {
					return fmt.Errorf("too many arguments")
				}
				gadget, name, containerFilter := args[0], args[1], ""
				if len(args) > 2 {
					containerFilter = args[2]
				}
				return localGadgetManager.AddTracer(gadget, name, containerFilter)
			},
		}

		operationCmd = &cobra.Command{
			Use:   "operation trace-name [ start | stop ]",
			Short: "Execute an operation on a trace",
			RunE: func(cmd *cobra.Command, args []string) error {
				if len(args) != 2 {
					return fmt.Errorf("missing name or operation")
				}
				name, opname := args[0], args[1]
				return localGadgetManager.Operation(name, opname)
			},
		}

		showCmd = &cobra.Command{
			Use:   "show trace-name",
			Short: "Show the status of a trace",
			RunE: func(cmd *cobra.Command, args []string) error {
				if len(args) != 1 {
					return fmt.Errorf("missing name")
				}
				name := args[0]
				return localGadgetManager.Show(name)
			},
		}

		streamCmd = &cobra.Command{
			Use:   "stream trace-name",
			Short: "Show the stream output of a trace",
			RunE: func(cmd *cobra.Command, args []string) error {
				if len(args) != 1 {
					return fmt.Errorf("missing name")
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
					return nil
				}
			Loop:
				for {
					select {
					case line, ok := <-ch:
						if !ok {
							break Loop
						}
						fmt.Printf("%s\n", line)
					case <-sigs:
						signal.Stop(sigs)
						stop <- struct{}{}
					}
				}
				return nil
			},
		}

		deleteCmd = &cobra.Command{
			Use:   "delete trace-name",
			Short: "Delete a trace",
			RunE: func(cmd *cobra.Command, args []string) error {
				if len(args) != 1 {
					return fmt.Errorf("missing name")
				}
				name := args[0]
				return localGadgetManager.Delete(name)
			},
		}

		dumpCmd = &cobra.Command{
			Use:   "dump",
			Short: "Dump internal data",
			Run: func(cmd *cobra.Command, args []string) {
				fmt.Printf("%s\n", localGadgetManager.Dump())
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
		traceCmd,
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

	return rootCmd
}

func main() {
	var err error
	localGadgetManager, err = localgadgetmanager.NewManager()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	homedir, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	var completer = readline.NewPrefixCompleter(
		readline.PcItem("list-gadgets"),
		readline.PcItem("list-containers"),
		readline.PcItem("list-traces"),
		readline.PcItem("trace",
			readline.PcItemDynamic(func(string) []string {
				return localGadgetManager.ListGadgets()
			}),
		),
		readline.PcItem("operation",
			readline.PcItemDynamic(func(string) []string {
				return localGadgetManager.ListTraces()
			},
				readline.PcItemDynamic(func(line string) []string {
					fields := strings.Fields(line)
					if len(fields) == 0 {
						return []string{}
					}
					return localGadgetManager.ListOperations(fields[len(fields)-1])
				}),
			),
		),
		readline.PcItem("show"),
		readline.PcItem("stream",
			readline.PcItemDynamic(func(string) []string {
				return localGadgetManager.ListTraces()
			}),
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
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	for {
		input, err := l.Readline()
		if err == readline.ErrInterrupt {
			if len(input) == 0 {
				break
			} else {
				continue
			}
		} else if err == io.EOF {
			break
		}

		if strings.TrimSpace(input) == "" {
			continue
		}

		input = strings.TrimSpace(input)
		if err = execInput(input); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
	}
}

func execInput(input string) error {
	rootCmd := newRootCmd()

	args := strings.Split(input, " ")
	rootCmd.SetArgs(args)

	err := rootCmd.Execute()
	return err
}
