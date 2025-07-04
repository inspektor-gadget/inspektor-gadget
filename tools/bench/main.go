package main

import (
	"fmt"
	"log"
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

	// Add events flag to root command
	rootCmd.PersistentFlags().StringVar(&events, "events", "", "Events configuration")

	// Add maxRPS flag to client command
	rootCmd.PersistentFlags().IntVar(&eventsPerSecond, "events-per-second", 0, "Maximum requests per second (0 for unlimited)")

	rootCmd.RunE = func(cmd *cobra.Command, args []string) error {
		return handleEvents(events)
	}

	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
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

	for _, event := range eventsParts {
		eventParts := strings.SplitN(event, ":", 2)
		eventName := eventParts[0]

		genFactory, found := GetGenerator(eventName)
		if !found {
			return fmt.Errorf("unknown event: %s", eventName)
		}

		genConfig := ""
		if len(eventParts) > 1 {
			genConfig = eventParts[1]
		}
		gen, err := genFactory(genConfig)
		if err != nil {
			return fmt.Errorf("failed to create generator for event %s: %w", eventName, err)
		}
		if err := gen.Start(); err != nil {
			return fmt.Errorf("failed to start generator for event %s: %w", eventName, err)
		}
		defer gen.Stop()
	}

	fmt.Printf("Handling events: %s\n", events)

	// wait for ctrl + c
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt)
	<-signalChan // Wait for interrupt signal

	fmt.Printf("shutting down gracefully...\n")

	return nil
}
