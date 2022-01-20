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
	Short: "Deploy Inspektor Gadget on the cluster",
	RunE:  runDeploy,
}

// This is set during build.
var gadgetimage = "undefined"

var (
	image               string
	imagePullPolicy     string
	hookMode            string
	livenessProbe       bool
	DefaultToolMode     string
	fallbackPodInformer bool
)

func init() {
	deployCmd.PersistentFlags().StringVarP(
		&image,
		"image", "",
		gadgetimage,
		"container image")
	deployCmd.PersistentFlags().StringVarP(
		&imagePullPolicy,
		"image-pull-policy", "",
		"Always",
		"pull policy for the container image")
	deployCmd.PersistentFlags().StringVarP(
		&hookMode,
		"hook-mode", "",
		"auto",
		"how to get containers start/stop notifications (auto, crio, podinformer, nri, fanotify)")
	deployCmd.PersistentFlags().BoolVarP(
		&livenessProbe,
		"liveness-probe", "",
		true,
		"enable liveness probes")
	deployCmd.PersistentFlags().StringVarP(
		&DefaultToolMode,
		"default-tool-mode", "",
		"standard",
		"default kind of tools to use (auto, core, standard)")
	deployCmd.PersistentFlags().BoolVarP(
		&fallbackPodInformer,
		"fallback-podinformer", "",
		true,
		"Use pod informer as a fallback for the main hook")
	rootCmd.AddCommand(deployCmd)
}

const deployYamlTmpl string = `
apiVersion: v1
kind: Namespace
metadata:
  name: gadget
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: gadget
  namespace: gadget
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: gadget
  name: gadget-role
rules:
- apiGroups: [""]
  resources: ["pods"]
  # update is needed by traceloop gadget.
  verbs: ["update"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: gadget-role-binding
  namespace: gadget
subjects:
- kind: ServiceAccount
  name: gadget
roleRef:
  kind: Role
  name: gadget-role
  apiGroup: rbac.authorization.k8s.io
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: gadget-cluster-role
rules:
- apiGroups: [""]
  resources: ["namespaces", "nodes", "pods"]
  verbs: ["get", "watch", "list"]
- apiGroups: [""]
  resources: ["services"]
  # list services is needed by network-policy gadget.
  verbs: ["list"]
- apiGroups: ["gadget.kinvolk.io"]
  resources: ["traces", "traces/status"]
  # For traces, we need all rights on them as we define this resource.
  verbs: ["delete", "deletecollection", "get", "list", "patch", "create", "update", "watch"]
- apiGroups: ["*"]
  resources: ["deployments", "replicasets", "statefulsets", "daemonsets", "jobs", "cronjobs", "replicationcontrollers"]
  # Required to retrieve the owner references used by the seccomp gadget.
  verbs: ["get"]
- apiGroups: ["security-profiles-operator.x-k8s.io"]
  resources: ["seccompprofiles"]
  # Required for integration with the Kubernetes Security Profiles Operator
  verbs: ["list", "watch", "create"]
---
kind: ClusterRoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: gadget-cluster-role-binding
subjects:
- kind: ServiceAccount
  name: gadget
  namespace: gadget
roleRef:
  kind: ClusterRole
  name: gadget-cluster-role
  apiGroup: rbac.authorization.k8s.io
---
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: gadget
  namespace: gadget
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
        # We need to set gadget container as unconfined so it is able to write
        # /sys/fs/bpf as well as /sys/kernel/debug/tracing.
        # Otherwise, we can have error like:
        # "failed to create server failed to create folder for pinning bpf maps: mkdir /sys/fs/bpf/gadget: permission denied"
        # (For reference, see: https://github.com/kinvolk/inspektor-gadget/runs/3966318270?check_suite_focus=true#step:20:221)
        container.apparmor.security.beta.kubernetes.io/gadget: "unconfined"
        inspektor-gadget.kinvolk.io/option-hook-mode: "{{.HookMode}}"
    spec:
      serviceAccount: gadget
      hostPID: true
      hostNetwork: true
      containers:
      - name: gadget
        image: {{.Image}}
        imagePullPolicy: {{.ImagePullPolicy}}
        command: [ "/entrypoint.sh" ]
        lifecycle:
          preStop:
            exec:
              command:
                - "/cleanup.sh"
{{if .LivenessProbe}}
        livenessProbe:
          initialDelaySeconds: 10
          periodSeconds: 5
          exec:
            command:
              - /bin/gadgettracermanager
              - -liveness
{{end}}
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
          - name: GADGET_IMAGE
            value: {{.Image}}
          - name: INSPEKTOR_GADGET_VERSION
            value: {{.Version}}
          - name: INSPEKTOR_GADGET_OPTION_HOOK_MODE
            value: "{{.HookMode}}"
          - name: INSPEKTOR_GADGET_OPTION_DEFAULT_TOOL_MODE
            value: "{{.DefaultToolMode}}"
          - name: INSPEKTOR_GADGET_OPTION_FALLBACK_POD_INFORMER
            value: "{{.FallbackPodInformer}}"
        securityContext:
          capabilities:
            add:
              # We need CAP_NET_ADMIN to be able to create BPF link.
              # Indeed, link_create is called with prog->type which equals
              # BPF_PROG_TYPE_CGROUP_SKB.
              # This value is then checked in
              # bpf_prog_attach_check_attach_type() which also checks if we have
              # CAP_NET_ADMIN:
              # https://elixir.bootlin.com/linux/v5.14.14/source/kernel/bpf/syscall.c#L4099
              # https://elixir.bootlin.com/linux/v5.14.14/source/kernel/bpf/syscall.c#L2967
              - NET_ADMIN

              # We need CAP_SYS_ADMIN to use Python-BCC gadgets because bcc
              # internally calls bpf_get_map_fd_by_id() which contains the
              # following snippet:
              # if (!capable(CAP_SYS_ADMIN))
              # 	return -EPERM;
              # (https://elixir.bootlin.com/linux/v5.10.73/source/kernel/bpf/syscall.c#L3254)
              #
              # Details about this are given in:
              # > The important design decision is to allow ID->FD transition for
              # CAP_SYS_ADMIN only. What it means that user processes can run
              # with CAP_BPF and CAP_NET_ADMIN and they will not be able to affect each
              # other unless they pass FDs via scm_rights or via pinning in bpffs.
              # ID->FD is a mechanism for human override and introspection.
              # An admin can do 'sudo bpftool prog ...'. It's possible to enforce via LSM that
              # only bpftool binary does bpf syscall with CAP_SYS_ADMIN and the rest of user
              # space processes do bpf syscall with CAP_BPF isolating bpf objects (progs, maps,
              # links) that are owned by such processes from each other.
              # (https://lwn.net/Articles/820560/)
              #
              # Note that even with a kernel providing CAP_BPF, the above
              # statement is still true.
              - SYS_ADMIN

              # We need this capability to get addresses from /proc/kallsyms.
              # Without it, addresses displayed when reading this file will be
              # 0.
              # Thus, bcc_procutils_each_ksym will never call callback, so KSyms
              # syms_ vector will be empty and it will return false.
              # As a consequence, no prefix will be found in
              # get_syscall_prefix(), so a default prefix (_sys) will be
              # returned.
              # Sadly, this default prefix is not used by the running kernel,
              # which instead uses: __x64_sys_
              - SYSLOG

              # traceloop gadget uses strace which in turns use ptrace()
              # syscall.
              # Within kernel code, ptrace() calls ptrace_attach() which in
              # turns calls __ptrace_may_access() which calls ptrace_has_cap()
              # where CAP_SYS_PTRACE is finally checked:
              # https://elixir.bootlin.com/linux/v5.14.14/source/kernel/ptrace.c#L284
              - SYS_PTRACE

              # Needed by setrlimit in gadgettracermanager.
              - SYS_RESOURCE

              # Needed for gadgets that don't dumb the memory rlimit.
              # (Currently only applies to BCC python-based gadgets)
              - IPC_LOCK
        volumeMounts:
        - name: host
          mountPath: /host
        - name: run
          mountPath: /run
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
	Image               string
	ImagePullPolicy     string
	Version             string
	HookMode            string
	LivenessProbe       bool
	DefaultToolMode     string
	FallbackPodInformer bool
}

func runDeploy(cmd *cobra.Command, args []string) error {
	if hookMode != "auto" &&
		hookMode != "crio" &&
		hookMode != "podinformer" &&
		hookMode != "nri" &&
		hookMode != "fanotify" {
		return fmt.Errorf("invalid argument %q for --hook-mode=[auto,crio,podinformer,nri,fanotify]", hookMode)
	}

	if DefaultToolMode != "auto" && DefaultToolMode != "core" && DefaultToolMode != "standard" {
		return fmt.Errorf("invalid argument %q for --tools-mode=[auto,core,standard]", DefaultToolMode)
	}

	t, err := template.New("deploy.yaml").Parse(deployYamlTmpl)
	if err != nil {
		return fmt.Errorf("failed to parse template %w", err)
	}

	p := parameters{
		image,
		imagePullPolicy,
		version,
		hookMode,
		livenessProbe,
		DefaultToolMode,
		fallbackPodInformer,
	}

	fmt.Printf("%s\n---\n", resources.TracesCustomResource)
	err = t.Execute(os.Stdout, p)
	if err != nil {
		return fmt.Errorf("failed to generate deploy template %w", err)
	}

	return nil
}
