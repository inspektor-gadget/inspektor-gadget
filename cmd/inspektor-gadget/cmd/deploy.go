package cmd

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var deployCmd = &cobra.Command{
	Use:               "deploy",
	Short:             "Deploy Inspektor Gadget on the worker nodes",
	PersistentPreRunE: doesKubeconfigExist,
	RunE:              runDeploy,
}

// This is set during build.
var gadgetimage = "undefined"

func init() {
	deployCmd.PersistentFlags().String(
		"image",
		gadgetimage,
		"container image")
	deployCmd.PersistentFlags().String(
		"opts",
		"",
		"experimental options")
	viper.BindPFlag("image", deployCmd.PersistentFlags().Lookup("image"))
	viper.BindPFlag("opts", deployCmd.PersistentFlags().Lookup("opts"))

	rootCmd.AddCommand(deployCmd)
}

const deployYaml string = `
apiVersion: v1
kind: ServiceAccount
metadata:
  name: gadget
  namespace: kube-system
---
kind: ClusterRoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: gadget
subjects:
- kind: ServiceAccount
  name: gadget
  namespace: kube-system
roleRef:
  kind: ClusterRole
  name: cluster-admin
  apiGroup: rbac.authorization.k8s.io
---
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: gadget
  namespace: kube-system
  labels:
    k8s-app: gadget
spec:
  selector:
    matchLabels:
      k8s-app: gadget
  template:
    metadata:
      labels:
        k8s-app: gadget
    spec:
      serviceAccount: gadget
      hostPID: true
      hostNetwork: true
      containers:
      - name: gadget
        image: @IMAGE@
        imagePullPolicy: Always
        command: [ "/entrypoint.sh" ]
        env:
          - name: TRACELOOP_NODE_NAME
            valueFrom:
              fieldRef:
                fieldPath: spec.nodeName
          - name: TRACELOOP_POD_NAME
            valueFrom:
              fieldRef:
                fieldPath: metadata.name
          - name: TRACELOOP_POD_NAMESPACE
            valueFrom:
              fieldRef:
                fieldPath: metadata.namespace
          - name: TRACELOOP_IMAGE
            value: @IMAGE@
          - name: INSPEKTOR_GADGET_VERSION
            value: @VERSION@
          - name: INSPEKTOR_GADGET_OPTIONS
            value: "@OPTIONS@"
        securityContext:
          privileged: true
        volumeMounts:
        - name: host
          mountPath: /host
        - name: run
          mountPath: /run
          mountPropagation: Bidirectional
        - name: modules
          mountPath: /lib/modules
        - name: debugfs
          mountPath: /sys/kernel/debug
        - name: cgroup
          mountPath: /sys/fs/cgroup
        - name: bpffs
          mountPath: /sys/fs/bpf
        - name: localtime
          mountPath: /etc/localtime
      tolerations:
      - effect: NoSchedule
        operator: Exists
      - effect: NoExecute
        operator: Exists
      volumes:
      - name: host
        hostPath:
          path: /
      - name: run
        hostPath:
          path: /run
      - name: cgroup
        hostPath:
          path: /sys/fs/cgroup
      - name: modules
        hostPath:
          path: /lib/modules
      - name: bpffs
        hostPath:
          path: /sys/fs/bpf
      - name: debugfs
        hostPath:
          path: /sys/kernel/debug
      - name: localtime
        hostPath:
          path: /etc/localtime
`

func runDeploy(cmd *cobra.Command, args []string) error {
	image := viper.GetString("image")
	opts := viper.GetString("opts")

	output := deployYaml
	output = strings.Replace(output, "@IMAGE@", image, -1)
	output = strings.Replace(output, "@VERSION@", version, -1)
	output = strings.Replace(output, "@OPTIONS@", opts, -1)
	fmt.Printf("%s", output)

	return nil
}
