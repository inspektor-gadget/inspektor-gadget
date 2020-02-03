package main

import (
	"fmt"
	"os"
	"text/template"

	"github.com/spf13/cobra"
)

var deployCmd = &cobra.Command{
	Use:               "deploy",
	Short:             "Deploy Inspektor Gadget on the worker nodes",
	PersistentPreRunE: doesKubeconfigExist,
	RunE:              runDeploy,
}

// This is set during build.
var gadgetimage = "undefined"

var (
	image     string
	traceloop bool
	runcHooks string
)

func init() {
	deployCmd.PersistentFlags().StringVarP(
		&image,
		"image", "",
		gadgetimage,
		"container image")
	deployCmd.PersistentFlags().BoolVarP(
		&traceloop,
		"traceloop", "",
		true,
		"enable the traceloop gadget")
	deployCmd.PersistentFlags().StringVarP(
		&runcHooks,
		"runc-hooks", "",
		"auto",
		"how to attach runc hooks (auto, ldpreload)")

	rootCmd.AddCommand(deployCmd)
}

const deployYamlTmpl string = `
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
      annotations:
        inspektor-gadget.kinvolk.io/option-traceloop: "{{.Traceloop}}"
        inspektor-gadget.kinvolk.io/option-runc-hooks: "{{.RuncHooks}}"
    spec:
      serviceAccount: gadget
      hostPID: true
      hostNetwork: true
      containers:
      - name: gadget
        image: {{.Image}}
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
            value: {{.Image}}
          - name: INSPEKTOR_GADGET_VERSION
            value: {{.Version}}
          - name: INSPEKTOR_GADGET_OPTION_TRACELOOP
            value: "{{.Traceloop}}"
          - name: INSPEKTOR_GADGET_OPTION_RUNC_HOOKS
            value: "{{.RuncHooks}}"
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

type parameters struct {
	Image     string
	Version   string
	Traceloop bool
	RuncHooks string
}

func runDeploy(cmd *cobra.Command, args []string) error {
	if runcHooks != "auto" && runcHooks != "ldpreload" {
		return fmt.Errorf("invalid argument %q for --runc-hooks=[auto,ldpreload]", runcHooks)
	}

	t, err := template.New("deploy.yaml").Parse(deployYamlTmpl)
	if err != nil {
		return fmt.Errorf("failed to parse template %w", err)
	}

	p := parameters{
		image,
		version,
		traceloop,
		runcHooks,
	}

	err = t.Execute(os.Stdout, p)
	if err != nil {
		return fmt.Errorf("failed to generate deploy template %w", err)
	}

	return nil
}
