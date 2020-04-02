package main

import (
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var rootCmd = &cobra.Command{
	Use:   "kubectl-gadget",
	Short: "Collection of gadgets for Kubernetes developers",
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

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
