// Copyright 2025 The Inspektor Gadget authors
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
	"os"
	"os/signal"
	"strings"

	"github.com/spf13/cobra"
)

var (
	events          string
	eventsPerSecond int
)

func main() {
	rootCmd := &cobra.Command{
		Use:          "bench",
		Long:         "benchmark tool for IG",
		SilenceUsage: true,
	}

	rootCmd.PersistentFlags().StringVar(&events, "events", "", "Comma-separated list of event generators with their configuration (example: dns:server=1.1.1.1,tcp:server=localhost:8080,exec)")
	rootCmd.PersistentFlags().IntVar(&eventsPerSecond, "events-per-second", 0, "Maximum requests per second (0 for unlimited)")

	rootCmd.RunE = func(cmd *cobra.Command, args []string) error {
		return handleEvents(events)
	}

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func handleEvents(events string) error {
	if events == "" {
		return nil // No events to handle
	}

	eventsParts := strings.Split(events, ",")
	if len(eventsParts) == 0 {
		return nil // No valid events specified
	}

	generators := make([]Generator, 0, len(eventsParts))

	for _, event := range eventsParts {
		eventParts := strings.SplitN(event, ":", 2)
		eventName := eventParts[0]

		genFactory, found := getGenerator(eventName)
		if !found {
			return fmt.Errorf("unknown event: %s", eventName)
		}

		genConfig := ""
		if len(eventParts) > 1 {
			genConfig = eventParts[1]
		}
		gen, err := genFactory(genConfig)
		if err != nil {
			return fmt.Errorf("creating generator for event %s: %w", eventName, err)
		}
		if err := gen.Start(); err != nil {
			return fmt.Errorf("starting generator for event %s: %w", eventName, err)
		}

		generators = append(generators, gen)
	}

	fmt.Printf("Handling events: %s\n", events)

	// wait for ctrl + c
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt)
	<-signalChan

	fmt.Printf("shutting down gracefully...\n")

	var errs []error

	for _, gen := range generators {
		if err := gen.Stop(); err != nil {
			errs = append(errs, fmt.Errorf("stopping generator: %w", err))
		}
	}

	return errors.Join(errs...)
}
