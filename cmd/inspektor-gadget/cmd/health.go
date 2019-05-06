package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"text/tabwriter"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"

	"github.com/kinvolk/inspektor-gadget/pkg/k8sutil"
)

var healthCmd = &cobra.Command{
	Use:               "health",
	Short:             "Check the gadget installation on a Kubernetes cluster",
	Run:               runHealth,
	PersistentPreRunE: doesKubeconfigExist,
}

func init() {
	rootCmd.AddCommand(healthCmd)
}

func runHealth(cmd *cobra.Command, args []string) {
	contextLogger := log.WithFields(log.Fields{
		"command": "inspektor-gadget health",
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

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 4, ' ', 0)
	fmt.Fprintln(w, "NODE\tSTATUS\t")

	for _, node := range nodes.Items {
		line := fmt.Sprintf("%s\t%s\t", node.Name, execPodQuick(client, node.Name, "/bin/gadget-node-health-check.sh"))
		fmt.Fprintln(w, line)
	}
	w.Flush()
}

func execPodQuick(client *kubernetes.Clientset, node string, podCmd string) string {
	var listOptions = metaV1.ListOptions{
		LabelSelector: "k8s-app=gadget",
		FieldSelector: "spec.nodeName=" + node + ",status.phase=Running",
	}
	pods, err := client.CoreV1().Pods("kube-system").List(listOptions)
	if err != nil {
		return fmt.Sprintf("%s", err)
	}
	if len(pods.Items) == 0 {
		return "not-found"
	}
	if len(pods.Items) != 1 {
		return "too-many"
	}
	podName := pods.Items[0].Name

	kubectlCmd := fmt.Sprintf("kubectl ")
	if viper.GetString("kubeconfig") != "" {
		kubectlCmd += "--kubeconfig=" + viper.GetString("kubeconfig")
	}
	kubectlCmd += fmt.Sprintf(" exec -n kube-system %s -- %s", podName, podCmd)

	cmd := exec.Command("/bin/sh", "-c", kubectlCmd)
	stdoutStderr, err := cmd.CombinedOutput()
	if err != nil {
		if len(stdoutStderr) != 0 {
			return fmt.Sprintf("%s\n%s", err, stdoutStderr)
		} else {
			return fmt.Sprintf("%s", err)
		}
	}

	return fmt.Sprintf("%s", string(stdoutStderr))
}

func execPodQuickStart(client *kubernetes.Clientset, node string, podCmd string) string {
	var listOptions = metaV1.ListOptions{
		LabelSelector: "k8s-app=gadget",
		FieldSelector: "spec.nodeName=" + node + ",status.phase=Running",
	}
	pods, err := client.CoreV1().Pods("kube-system").List(listOptions)
	if err != nil {
		return fmt.Sprintf("%s", err)
	}
	if len(pods.Items) == 0 {
		return "not-found"
	}
	if len(pods.Items) != 1 {
		return "too-many"
	}
	podName := pods.Items[0].Name

	kubectlCmd := fmt.Sprintf("kubectl ")
	if viper.GetString("kubeconfig") != "" {
		kubectlCmd += "--kubeconfig=" + viper.GetString("kubeconfig")
	}
	kubectlCmd += fmt.Sprintf(" exec -n kube-system %s -- %s", podName, podCmd)

	cmd := exec.Command("/bin/sh", "-c", kubectlCmd)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Start()
	if err != nil {
		return fmt.Sprintf("%s", err)
	}

	return ""
}

func cpPodQuick(client *kubernetes.Clientset, node string, srcPath, destPath string) string {
	var listOptions = metaV1.ListOptions{
		LabelSelector: "k8s-app=gadget",
		FieldSelector: "spec.nodeName=" + node + ",status.phase=Running",
	}
	pods, err := client.CoreV1().Pods("kube-system").List(listOptions)
	if err != nil {
		return fmt.Sprintf("%s", err)
	}
	if len(pods.Items) == 0 {
		return "not-found"
	}
	if len(pods.Items) != 1 {
		return "too-many"
	}
	podName := pods.Items[0].Name

	kubectlCmd := fmt.Sprintf("kubectl ")
	if viper.GetString("kubeconfig") != "" {
		kubectlCmd += "--kubeconfig=" + viper.GetString("kubeconfig")
	}
	kubectlCmd += fmt.Sprintf(" cp %s kube-system/%s:%s", srcPath, podName, destPath)

	cmd := exec.Command("/bin/sh", "-c", kubectlCmd)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Start()
	if err != nil {
		return fmt.Sprintf("%s", err)
	}

	return ""
}
