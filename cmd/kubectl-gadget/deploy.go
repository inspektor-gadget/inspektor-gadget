// Copyright 2019-2021 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"fmt"
	"os"
	"text/template"

	"github.com/spf13/cobra"

	"github.com/kinvolk/inspektor-gadget/pkg/resources"
)

var deployCmd = &cobra.Command{
	Use:   "deploy",
	Short: "Deploy Inspektor Gadget on the worker nodes",
	RunE:  runDeploy,
}

// This is set during build.
var gadgetimage = "undefined"

var (
	image             string
	traceloop         bool
	traceloopLoglevel string
	hookMode          string
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
		&traceloopLoglevel,
		"traceloop-loglevel", "",
		"info,json",
		"loglevel (trace, debug, info, warn, error, fatal, panic, json, color, nocolor)")
	deployCmd.PersistentFlags().StringVarP(
		&hookMode,
		"hook-mode", "",
		"auto",
		"how to get containers start/stop notifications (auto, crio, ldpreload, podinformer, nri)")

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
        inspektor-gadget.kinvolk.io/option-hook-mode: "{{.HookMode}}"
    spec:
      serviceAccount: gadget
      hostPID: true
      hostNetwork: true
      containers:
      - name: gadget
        image: {{.Image}}
        imagePullPolicy: Always
        command: [ "/entrypoint.sh" ]
        lifecycle:
          preStop:
            exec:
              command:
                - "/cleanup.sh"
        livenessProbe:
          initialDelaySeconds: 10
          periodSeconds: 5
          exec:
            command:
              - /bin/gadgettracermanager
              - -liveness
        env:
          - name: NODE_NAME
            valueFrom:
              fieldRef:
                fieldPath: spec.nodeName
          - name: GADGET_POD_UID
            valueFrom:
              fieldRef:
                fieldPath: metadata.uid
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
          - name: INSPEKTOR_GADGET_OPTION_TRACELOOP_LOGLEVEL
            value: "{{.TraceloopLoglevel}}"
          - name: INSPEKTOR_GADGET_OPTION_HOOK_MODE
            value: "{{.HookMode}}"
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
	Image             string
	Version           string
	Traceloop         bool
	TraceloopLoglevel string
	HookMode          string
}

func runDeploy(cmd *cobra.Command, args []string) error {
	if hookMode != "auto" &&
		hookMode != "crio" &&
		hookMode != "ldpreload" &&
		hookMode != "podinformer" &&
		hookMode != "nri" {
		return fmt.Errorf("invalid argument %q for --hook-mode=[auto,crio,ldpreload,podinformer,nri]", hookMode)
	}

	t, err := template.New("deploy.yaml").Parse(deployYamlTmpl)
	if err != nil {
		return fmt.Errorf("failed to parse template %w", err)
	}

	p := parameters{
		image,
		version,
		traceloop,
		traceloopLoglevel,
		hookMode,
	}

	fmt.Printf("%s\n---\n", resources.TracesCustomResource)
	err = t.Execute(os.Stdout, p)
	if err != nil {
		return fmt.Errorf("failed to generate deploy template %w", err)
	}

	return nil
}
