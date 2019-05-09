package cmd

import (
	"fmt"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"

	"github.com/kinvolk/inspektor-gadget/pkg/k8sutil"
)

var execsnoopCmd = &cobra.Command{
	Use:               "execsnoop",
	Short:             "Trace new processes",
	Run:               bccCmd("execsnoop"),
	PersistentPreRunE: doesKubeconfigExist,
}
var opensnoopCmd = &cobra.Command{
	Use:               "opensnoop",
	Short:             "Trace files",
	Run:               bccCmd("opensnoop"),
	PersistentPreRunE: doesKubeconfigExist,
}

func init() {
	execsnoopCmd.PersistentFlags().String(
		"label",
		"",
		"Kubernetes label selector")
	viper.BindPFlag("label", execsnoopCmd.PersistentFlags().Lookup("label"))

	execsnoopCmd.PersistentFlags().String(
		"node",
		"",
		"Kubernetes node selector")
	viper.BindPFlag("node", execsnoopCmd.PersistentFlags().Lookup("node"))

	rootCmd.AddCommand(execsnoopCmd)

	opensnoopCmd.PersistentFlags().String(
		"label",
		"",
		"Kubernetes label selector")
	viper.BindPFlag("label", opensnoopCmd.PersistentFlags().Lookup("label"))

	opensnoopCmd.PersistentFlags().String(
		"node",
		"",
		"Kubernetes node selector")
	viper.BindPFlag("node", opensnoopCmd.PersistentFlags().Lookup("node"))

	rootCmd.AddCommand(opensnoopCmd)
}

func bccCmd(subprog string) func(*cobra.Command, []string) {
	return func(cmd *cobra.Command, args []string) {
		contextLogger := log.WithFields(log.Fields{
			"command": "inspektor-gadget straceback list",
			"args":    args,
		})

		client, err := k8sutil.NewClientset(viper.GetString("kubeconfig"))
		if err != nil {
			contextLogger.Fatalf("Error in creating setting up Kubernetes client: %q", err)
		}

		var listOptions = metaV1.ListOptions{
			LabelSelector: labels.Everything().String(),
			FieldSelector: fields.Everything().String(),
		}

		nodes, err := client.CoreV1().Nodes().List(listOptions)
		if err != nil {
			contextLogger.Fatalf("Error in listing nodes: %q", err)
		}

		for _, node := range nodes.Items {
			if viper.GetString("node") != "" && node.Name != viper.GetString("node") {
				continue
			}
			err := execPodQuickStart(client, node.Name, fmt.Sprintf("timeout --preserve-status 10 /opt/bcck8s/%s-edge --label %q || true", subprog, viper.GetString("label")))
			if err != "" {
				fmt.Printf("Error in running command: %q\n", err)
			}
		}
		select {}
	}
}
