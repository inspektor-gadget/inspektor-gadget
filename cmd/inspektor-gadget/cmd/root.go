package cmd

import (
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var rootCmd = &cobra.Command{
	Use:   "inspektor-gadget",
	Short: "Collection of gadgets for Kubernetes developers",
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(cobraInit)

	// add kubeconfig flag
	rootCmd.PersistentFlags().String(
		"kubeconfig",
		os.ExpandEnv("$HOME/.kube/config"),
		"Path to kubeconfig file")
	viper.BindPFlag("kubeconfig", rootCmd.PersistentFlags().Lookup("kubeconfig"))
}

func cobraInit() {
	viper.AutomaticEnv()
}
