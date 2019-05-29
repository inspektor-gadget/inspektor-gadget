package cmd

import (
	"fmt"
	"path/filepath"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"

	"github.com/kinvolk/inspektor-gadget/pkg/k8sutil"
)

var installCmd = &cobra.Command{
	Use:               "install",
	Short:             "Install or reinstall Inspektor Gadget on the worker nodes",
	PersistentPreRunE: doesKubeconfigExist,
	Run:               runInstall,
}

func init() {
	installCmd.PersistentFlags().String(
		"update-from-path",
		"",
		"if set, update files from the local path to a inspektor-gadget git repository")
	viper.BindPFlag("update-from-path", installCmd.PersistentFlags().Lookup("update-from-path"))

	rootCmd.AddCommand(installCmd)
}

func runInstall(cmd *cobra.Command, args []string) {
	contextLogger := log.WithFields(log.Fields{
		"command": "inspektor-gadget install",
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

	updateFromPath := viper.GetString("update-from-path")
	for _, node := range nodes.Items {
		fmt.Printf("node %s:\n", node.Name)
		if updateFromPath != "" {
			output := cpPodQuick(client, node.Name, filepath.Join(updateFromPath, "gadget-ds/files/bcck8s"), "/opt/")
			if output != "" {
				fmt.Printf("%s\n", output)
				return
			}
			output = cpPodQuick(client, node.Name, filepath.Join(updateFromPath, "gadget-ds/files/runc-hook-prestart.sh"), "/bin/")
			if output != "" {
				fmt.Printf("%s\n", output)
				return
			}
			output = cpPodQuick(client, node.Name, filepath.Join(updateFromPath, "gadget-ds/files/runc-hook-prestart-create-maps.sh"), "/bin/")
			if output != "" {
				fmt.Printf("%s\n", output)
				return
			}
			output = cpPodQuick(client, node.Name, filepath.Join(updateFromPath, "gadget-ds/files/gadget-node-install.sh"), "/bin/")
			if output != "" {
				fmt.Printf("%s\n", output)
				return
			}
			output = cpPodQuick(client, node.Name, filepath.Join(updateFromPath, "gadget-ds/files/gadget-node-health-check.sh"), "/bin/")
			if output != "" {
				fmt.Printf("%s\n", output)
				return
			}
		}

		output := execPodSimple(client, node.Name, `/bin/gadget-node-install.sh`)
		fmt.Printf("installation:\n%s\n", output)
	}
}
