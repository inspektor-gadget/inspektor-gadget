package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"

	"github.com/kinvolk/inspektor-gadget/pkg/k8sutil"
)

var pingCmd = &cobra.Command{
	Use:   "ping",
	Short: "Trace a ping from a pod",
	Run:   runTracepkt,
}

func init() {
	rootCmd.AddCommand(pingCmd)
}

type pingCollector struct {
	m      *sync.Mutex
	writer *bufio.Writer
	node   string
}

type pingEvent struct {
	// Content flags
	Kind  string `json:"kind"`
	Flags int    `json:"flags"`

	// Routing information
	IfName string `json:"ifname"`
	Netns  uint64 `json:"netns"`

	// Packet type (IPv4 or IPv6) and address
	IpVersion uint64 `json:"ip_version"`
	IcmpType  uint64 `json:"icmptype"`
	Direction string `json:"direction"`
	IcmpId    uint64 `json:"icmpid"`
	IcmpSeq   uint64 `json:"icmpseq"`
	IcmpPad   uint64 `json:"icmppad"`
	Saddr     string `json:"saddr"`
	Daddr     string `json:"daddr"`

	// Iptables trace
	Hook      string `json:"hook"`
	Verdict   string `json:"verdict"`
	TableName string `json:"tablename"`

	// Iptables step trace
	IfNameIn              string `json:"ifname_in"`
	IfNameOut             string `json:"ifname_out"`
	IptablesStepTableName string `json:"iptables_step_tablename"`
	IptablesStepChainName string `json:"iptables_step_chainname"`
	IptablesStepComment   string `json:"iptables_step_comment"`
	IptablesStepRuleNum   uint64 `json:"iptables_step_rulenum"`
}

func (t pingCollector) Write(p []byte) (n int, err error) {
	t.m.Lock()
	defer t.m.Unlock()

	event := pingEvent{}
	text := strings.TrimSpace(string(p))
	if len(text) != 0 {
		err := json.Unmarshal([]byte(text), &event)
		if err == nil && event.Kind != "" {
			fmt.Printf("Node %s ready.\n", t.node)
		}
	}

	n, err = t.writer.Write(p)
	if err != nil {
		return
	}
	err = t.writer.Flush()
	return
}

func runTracepkt(cmd *cobra.Command, args []string) {
	contextLogger := log.WithFields(log.Fields{
		"command": "inspektor-gadget ping",
		"args":    args,
	})

	if len(args) != 2 {
		contextLogger.Fatalf("Invalid arguments: %v", args)
	}

	var w *bufio.Writer
	w = bufio.NewWriter(os.Stdout)

	client, err := k8sutil.NewClientset(viper.GetString("kubeconfig"))
	if err != nil {
		contextLogger.Fatalf("Error setting up Kubernetes client: %q", err)
	}

	var listOptions = metaV1.ListOptions{
		LabelSelector: labels.Everything().String(),
		FieldSelector: fields.Everything().String(),
	}
	nodes, err := client.CoreV1().Nodes().List(listOptions)
	if err != nil {
		contextLogger.Fatalf("Error listing nodes: %q", err)
	}

	podSource := args[0]
	ipDest := args[1]

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	failure := make(chan string)

	var m sync.Mutex
	for _, node := range nodes.Items {
		go func(nodeName string) {
			collector := pingCollector{&m, w, nodeName}
			cmd := fmt.Sprintf("exec /opt/bcck8s/bcc-wrapper.sh --tracerid networkpolicyadvisor --nomanager --probecleanup --gadget /opt/tracepkt.py -- %s %s",
				podSource, ipDest)
			err := execPod(client, nodeName, cmd, collector, os.Stderr)
			if fmt.Sprintf("%s", err) != "command terminated with exit code 137" {
				failure <- fmt.Sprintf("Error running command: %q\n", err)
			}
		}(node.Name)
	}

	select {
	case <-sigs:
		fmt.Printf("\nStopping...\n")
	case e := <-failure:
		fmt.Printf("Error detected: %q\n", e)
	}

	for _, node := range nodes.Items {
		_, _, err := execPodCapture(client, node.Name,
			fmt.Sprintf("exec /opt/bcck8s/bcc-wrapper.sh --tracerid networkpolicyadvisor --stop"))
		if err != nil {
			fmt.Printf("Error running command: %q\n", err)
		}
	}
}
