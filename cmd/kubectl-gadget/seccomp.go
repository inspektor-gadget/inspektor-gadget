package main

import (
	"encoding/json"
	"fmt"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/seccomp/types"
	"github.com/kinvolk/inspektor-gadget/pkg/k8sutil"
)

var seccompCmd = &cobra.Command{
	Use:   "seccomp",
	Short: "Generate seccomp policies",
}

var seccompStartCmd = &cobra.Command{
	Use:   "start",
	Short: "start observation",
	Run:   runSeccompStart,
}

var seccompStopCmd = &cobra.Command{
	Use:   "stop",
	Short: "stop observation",
	Run:   runSeccompStop,
}

var seccompQueryCmd = &cobra.Command{
	Use:   "query",
	Short: "query observation",
	Run:   runSeccompQuery,
}

var (
	nodeSeccompParam          string
	namespaceSeccompParam     string
	podnameSeccompParam       string
	containerNameSeccompParam string
	listSeccompParam          bool
)

func init() {
	rootCmd.AddCommand(seccompCmd)

	seccompQueryCmd.PersistentFlags().StringVar(
		&nodeSeccompParam,
		"node",
		"",
		fmt.Sprintf("Show only seccomp policies from pods running in that node"),
	)
	seccompQueryCmd.PersistentFlags().StringVar(
		&namespaceSeccompParam,
		"namespace",
		"",
		fmt.Sprintf("Show only seccomp policies from pods running in that namespace"),
	)
	seccompQueryCmd.PersistentFlags().StringVar(
		&podnameSeccompParam,
		"podname",
		"",
		fmt.Sprintf("Show only seccomp policies from pods with that pod name"),
	)
	seccompQueryCmd.PersistentFlags().StringVar(
		&containerNameSeccompParam,
		"containername",
		"",
		fmt.Sprintf("Show only seccomp policies from pods with that container name"),
	)

	seccompQueryCmd.PersistentFlags().BoolVar(
		&listSeccompParam,
		"list",
		false,
		fmt.Sprintf("Show a list of seccomp policies for all matching containers"),
	)

	seccompCmd.AddCommand(seccompStartCmd)
	seccompCmd.AddCommand(seccompStopCmd)
	seccompCmd.AddCommand(seccompQueryCmd)
}

func execAllNodes(command string, args []string, call string) (ret map[string]string) {
	contextLogger := log.WithFields(log.Fields{
		"command": command,
		"args":    args,
	})

	if len(args) != 0 {
		contextLogger.Fatalf("Too many parameters")
	}

	client, err := k8sutil.NewClientsetFromConfigFlags(KubernetesConfigFlags)
	if err != nil {
		contextLogger.Fatalf("Error in creating setting up Kubernetes client: %q", err)
	}

	var listOptions = metaV1.ListOptions{
		LabelSelector: labels.Everything().String(),
		FieldSelector: fields.Everything().String(),
	}
	nodes, err := client.CoreV1().Nodes().List(listOptions)
	if err != nil {
		contextLogger.Fatalf("Error listing nodes: %q", err)
	}

	ret = make(map[string]string)
	nodeCount := 0
	for _, node := range nodes.Items {
		if nodeSeccompParam != "" && node.Name != nodeSeccompParam {
			continue
		}
		nodeCount++
		cmd := fmt.Sprintf("gadgettracermanager -call %s -tracerid seccomp", call)
		out := execPodSimple(client, node.Name, cmd)
		ret[node.Name] = out
	}
	if nodeSeccompParam != "" && nodeCount == 0 {
		contextLogger.Fatalf("No such node: %s", nodeSeccompParam)
	}
	return
}

func runSeccompStart(cmd *cobra.Command, args []string) {
	ret := execAllNodes("kubectl-gadget seccomp start", args, "add-tracer")
	for nodeName, output := range ret {
		fmt.Printf("%s: %s\n", nodeName, output)
	}
}

func runSeccompStop(cmd *cobra.Command, args []string) {
	ret := execAllNodes("kubectl-gadget seccomp stop", args, "remove-tracer")
	for nodeName, output := range ret {
		fmt.Printf("%s: %s\n", nodeName, output)
	}
}

func runSeccompQuery(cmd *cobra.Command, args []string) {
	contextLogger := log.WithFields(log.Fields{
		"command": "kubectl-gadget seccomp query",
		"args":    args,
	})

	ret := execAllNodes("kubectl-gadget seccomp query", args, "query-tracer")
	containers := []types.Container{}
	for nodeName, outputStr := range ret {
		resp := &types.SeccompAdvisorQueryResponse{}
		err := json.Unmarshal([]byte(outputStr), resp)
		if err != nil {
			fmt.Printf("%s: %s: %s\n", nodeName, err, outputStr)
		} else {
			for _, c := range resp.Containers {
				if namespaceSeccompParam != "" && namespaceSeccompParam != c.Namespace {
					continue
				}
				if podnameSeccompParam != "" && podnameSeccompParam != c.Podname {
					continue
				}
				if containerNameSeccompParam != "" && containerNameSeccompParam != c.ContainerName {
					continue
				}
				containers = append(containers, c)
			}
		}
	}
	var b []byte
	var err error
	if listSeccompParam {
		b, err = json.MarshalIndent(containers, "", "    ")
	} else {
		if len(containers) == 0 {
			contextLogger.Fatalf("No container matching the criterias")
		} else if len(containers) > 1 {
			contextLogger.Fatalf("Several containers matching the criterias. Try with --list?")
		} else {
			b, err = json.MarshalIndent(containers[0].SeccompPolicy, "", "    ")
		}

	}
	if err != nil {
		fmt.Printf("%s\n", err)
	} else {
		fmt.Printf("%s\n", string(b))
	}
}
