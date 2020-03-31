package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

// This variable is used by the "version" command and is set during build.
var version = "undefined"

func init() {
	rootCmd.AddCommand(versionCmd)
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show version",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println(version)
	},
}
