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
	"context"
	"fmt"

	"github.com/kinvolk/inspektor-gadget/cmd/kubectl-gadget/utils"
	"github.com/kinvolk/inspektor-gadget/pkg/k8sutil"
	"github.com/kinvolk/inspektor-gadget/pkg/resources"
	"github.com/spf13/cobra"

	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
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
		"pull policy for the container image (Always, Never, IfNotPresent)")
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
	deployCmd.PersistentFlags().BoolVarP(
		&fallbackPodInformer,
		"fallback-podinformer", "",
		true,
		"Use pod informer as a fallback for the main hook")
	rootCmd.AddCommand(deployCmd)
}

const (
	gadgetClusterRoleBindingName = "gadget-cluster-role-binding"
	gadgetClusterRoleName        = "gadget-cluster-role"
	gadgetDaemonSetName          = "gadget"
	gadgetRoleBindingName        = "gadget-role-binding"
	gadgetRoleName               = "gadget-role"
	gadgetServiceAccountName     = "gadget"
)

type parameters struct {
	Image               string
	ImagePullPolicy     string
	Version             string
	HookMode            string
	LivenessProbe       bool
	FallbackPodInformer bool
}

func createGadgetNamespace(k8sClient *kubernetes.Clientset, namespace string) error {
	nsSpec := &v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: gadgetNamespace,
		},
	}
	_, err := k8sClient.CoreV1().Namespaces().Create(context.TODO(), nsSpec, metav1.CreateOptions{})
	return err
}

func createGadgetServiceAccount(k8sClient *kubernetes.Clientset, namespaceName, serviceAccountName string) error {
	serviceAccountSpec := &v1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name: serviceAccountName,
		},
	}
	_, err := k8sClient.CoreV1().ServiceAccounts(namespaceName).Create(context.TODO(), serviceAccountSpec, metav1.CreateOptions{})
	return err
}

func createGadgetRole(k8sClient *kubernetes.Clientset, namespaceName, roleName string) error {
	roleSpec := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name: roleName,
		},
		Rules: []rbacv1.PolicyRule{
			rbacv1.PolicyRule{
				// update is needed by traceloop gadget
				Verbs:     []string{"update"},
				APIGroups: []string{""},
				Resources: []string{"pods"},
			},
		},
	}
	_, err := k8sClient.RbacV1().Roles(namespaceName).Create(context.TODO(), roleSpec, metav1.CreateOptions{})
	return err
}

func createGadgetRoleBinding(k8sClient *kubernetes.Clientset, namespaceName, roleBindingName string) error {
	roleBindingSpec := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: roleBindingName,
		},
		Subjects: []rbacv1.Subject{
			rbacv1.Subject{
				Kind: "ServiceAccount",
				Name: "gadget",
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     gadgetRoleName,
		},
	}
	_, err := k8sClient.RbacV1().RoleBindings(namespaceName).Create(context.TODO(), roleBindingSpec, metav1.CreateOptions{})
	return err
}

func createGadgetClusterRole(k8sClient *kubernetes.Clientset, clusterRoleName string) error {
	clusterRoleSpec := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: clusterRoleName,
		},
		Rules: []rbacv1.PolicyRule{
			rbacv1.PolicyRule{
				Verbs:     []string{"get", "watch", "list"},
				APIGroups: []string{""},
				Resources: []string{"namespaces", "nodes", "pods"},
			},
			rbacv1.PolicyRule{
				// list services is needed by network-policy gadget.
				Verbs:     []string{"list"},
				APIGroups: []string{""},
				Resources: []string{"services"},
			},
			rbacv1.PolicyRule{
				// For traces, we need all rights on them as we define this resource.
				Verbs:     []string{"delete", "deletecollection", "get", "list", "patch", "create", "update", "watch"},
				APIGroups: []string{"gadget.kinvolk.io"},
				Resources: []string{"traces", "traces/status"},
			},
			rbacv1.PolicyRule{
				// Required to retrieve the owner references used by the seccomp gadget.
				Verbs:     []string{"get"},
				APIGroups: []string{"*"},
				Resources: []string{"deployments", "replicasets", "statefulsets", "daemonsets", "jobs", "cronjobs", "replicationcontrollers"},
			},
			rbacv1.PolicyRule{
				// Required for integration with the Kubernetes SPO.
				Verbs:     []string{"list", "watch", "create"},
				APIGroups: []string{"security-profiles-operator.x-k8s.io"},
				Resources: []string{"seccompprofiles"},
			},
			rbacv1.PolicyRule{
				// It is necessary to use the 'privileged' security context constraints
				// to be able mount host directories as volumes, use the host
				// networking, among others.
				// This will be used only when running on OpenShift:
				// https://docs.openshift.com/container-platform/4.9/authentication/managing-security-context-constraints.html#default-sccs_configuring-internal-oauth
				Verbs:         []string{"use"},
				APIGroups:     []string{"security.openshift.io"},
				Resources:     []string{"securitycontextconstraints"},
				ResourceNames: []string{"privileged"},
			},
		},
	}
	_, err := k8sClient.RbacV1().ClusterRoles().Create(context.TODO(), clusterRoleSpec, metav1.CreateOptions{})
	return err
}

func createGadgetClusterRoleBinding(k8sClient *kubernetes.Clientset, clusterRoleBindingName string) error {
	clusterRoleBindingSpec := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: clusterRoleBindingName},
		Subjects: []rbacv1.Subject{
			rbacv1.Subject{
				Kind:      "ServiceAccount",
				Name:      "gadget",
				Namespace: gadgetNamespace,
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     gadgetClusterRoleName,
		},
	}
	_, err := k8sClient.RbacV1().ClusterRoleBindings().Create(context.TODO(), clusterRoleBindingSpec, metav1.CreateOptions{})
	return err
}

func createGadgetDaemonSet(k8sClient *kubernetes.Clientset, daemonSetName, namespaceName, hookMode, image string, pullPolicy v1.PullPolicy, livenessProbe, fallbackPodInformer bool) error {
	var probe *v1.Probe = nil
	if livenessProbe {
		probe = &v1.Probe{
			// Handler in v0.22.3, ProbeHandler v0.24.0.
			Handler: v1.Handler{
				Exec: &v1.ExecAction{
					Command: []string{
						"/bin/gadgettracermanager",
						"-liveness",
					},
				},
			},
			InitialDelaySeconds: 60,
			PeriodSeconds:       5,
		}
	}

	envFallbackPodInformer := ""
	if fallbackPodInformer {
		envFallbackPodInformer = "true"
	}

	daemonSetSpec := &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      daemonSetName,
			Namespace: namespaceName,
			Labels:    map[string]string{"k8s-app": "gadget"},
		},
		Spec: appsv1.DaemonSetSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"k8s-app": "gadget"},
			},
			Template: v1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels:      map[string]string{"k8s-app": "gadget"},
					Annotations: map[string]string{
						// We need to set gadget container as unconfined so it is able to
						// write /sys/fs/bpf as well as /sys/kernel/debug/tracing.
						// Otherwise, we can have error like:
						// "failed to create server failed to create folder for pinning bpf maps: mkdir /sys/fs/bpf/gadget: permission denied"
						// (For reference, see: https://github.com/kinvolk/inspektor-gadget/runs/3966318270?check_suite_focus=true#step:20:221)
						"container.apparmor.security.beta.kubernetes.io/gadget": "unconfined",
						"inspektor-gadget.kinvolk.io/option-hook-mode":          hookMode,
					},
				},
				Spec: v1.PodSpec{
					ServiceAccountName: "gadget",
					HostPID:            true,
					HostNetwork:        true,
					Containers:         []v1.Container{
						v1.Container{
							Name:                     "gadget",
							TerminationMessagePolicy: v1.TerminationMessageFallbackToLogsOnError,
							Image:                    image,
							ImagePullPolicy:          pullPolicy,
							Command:                  []string{"/entrypoint.sh"},
							Lifecycle:                &v1.Lifecycle{
								// Handler in v0.22.3, LifecycleHandler in v0.24.0.
								PreStop: &v1.Handler{
									Exec: &v1.ExecAction{
										Command: []string{"/cleanup.sh"},
									},
								},
							},
							LivenessProbe: probe,
							Env:           []v1.EnvVar{
								v1.EnvVar{
									Name:      "NODE_NAME",
									ValueFrom: &v1.EnvVarSource{
										FieldRef: &v1.ObjectFieldSelector{
											FieldPath: "spec.nodeName",
										},
									},
								},
								v1.EnvVar{
									Name:      "GADGET_POD_UID",
									ValueFrom: &v1.EnvVarSource{
										FieldRef: &v1.ObjectFieldSelector{
											FieldPath: "metadata.uid",
										},
									},
								},
								v1.EnvVar{
									Name:      "TRACELOOP_NODE_NAME",
									ValueFrom: &v1.EnvVarSource{
										FieldRef: &v1.ObjectFieldSelector{
											FieldPath: "spec.nodeName",
										},
									},
								},
								v1.EnvVar{
									Name:      "TRACELOOP_POD_NAME",
									ValueFrom: &v1.EnvVarSource{
										FieldRef: &v1.ObjectFieldSelector{
											FieldPath: "metadata.name",
										},
									},
								},
								v1.EnvVar{
									Name:      "TRACELOOP_POD_NAMESPACE",
									ValueFrom: &v1.EnvVarSource{
										FieldRef: &v1.ObjectFieldSelector{
											FieldPath: "metadata.namespace",
										},
									},
								},
								v1.EnvVar{
									Name:  "GADGET_IMAGE",
									Value: image,
								},
								v1.EnvVar{
									Name:  "INSPEKTOR_GADGET_VERSION",
									Value: version,
								},
								v1.EnvVar{
									Name:  "INSPEKTOR_GADGET_OPTION_HOOK_MODE",
									Value: hookMode,
								},
								v1.EnvVar{
									Name:  "INSPEKTOR_GADGET_OPTION_FALLBACK_POD_INFORMER",
									Value: envFallbackPodInformer,
								},
							},
							SecurityContext: &v1.SecurityContext{
								Capabilities: &v1.Capabilities{
									Add: []v1.Capability{
										// We need CAP_NET_ADMIN to be able to create BPF link.
										// Indeed, link_create is called with prog->type which equals
										// BPF_PROG_TYPE_CGROUP_SKB.
										// This value is then checked in
										// bpf_prog_attach_check_attach_type() which also checks if we
										// have CAP_NET_ADMIN:
										// https://elixir.bootlin.com/linux/v5.14.14/source/kernel/bpf/syscall.c#L4099
										// https://elixir.bootlin.com/linux/v5.14.14/source/kernel/bpf/syscall.c#L2967
										"NET_ADMIN",
										// We need CAP_SYS_ADMIN to use Python-BCC gadgets because bcc
										// internally calls bpf_get_map_fd_by_id() which contains the
										// following snippet:
										// if (!capable(CAP_SYS_ADMIN))
										// 	return -EPERM;
										// (https://elixir.bootlin.com/linux/v5.10.73/source/kernel/bpf/syscall.c#L3254)
										//
										// Details about this are given in:
										// > The important design decision is to allow ID->FD transition
										// for CAP_SYS_ADMIN only. What it means that user processes can
										// run with CAP_BPF and CAP_NET_ADMIN and they will not be able
										// to affect each other unless they pass FDs via scm_rights or
										// via pinning in bpffs.
										// ID->FD is a mechanism for human override and introspection.
										// An admin can do 'sudo bpftool prog ...'. It's possible to
										// enforce via LSM that only bpftool binary does bpf syscall
										// with CAP_SYS_ADMIN and the rest of user space processes do
										// bpf syscall with CAP_BPF isolating bpf objects (progs, maps,
										// links) that are owned by such processes from each other.
										// (https://lwn.net/Articles/820560/)
										//
										// Note that even with a kernel providing CAP_BPF, the above
										// statement is still true.
										"SYS_ADMIN",
										// We need this capability to get addresses from /proc/kallsyms.
										// Without it, addresses displayed when reading this file will
										// be 0.
										// Thus, bcc_procutils_each_ksym will never call callback, so
										// KSyms syms_ vector will be empty and it will return false.
										// As a consequence, no prefix will be found in
										// get_syscall_prefix(), so a default prefix (_sys) will be
										// returned.
										// Sadly, this default prefix is not used by the running kernel,
										// which instead uses: __x64_sys_
										"SYSLOG",
										// traceloop gadget uses strace which in turns use ptrace()
										// syscall.
										// Within kernel code, ptrace() calls ptrace_attach() which in
										// turns calls __ptrace_may_access() which calls
										// ptrace_has_cap() where CAP_SYS_PTRACE is finally checked:
										// https://elixir.bootlin.com/linux/v5.14.14/source/kernel/ptrace.c#L284
										"SYS_PTRACE",
										// Needed by setrlimit in gadgettracermanager and by the
										// traceloop gadget.
										"SYS_RESOURCE",
										// Needed for gadgets that don't dumb the memory rlimit.
										// (Currently only applies to BCC python-based gadgets)
										"IPC_LOCK",
										// Needed by BCC python-based gadgets to load the kheaders module:
										// https://github.com/iovisor/bcc/blob/v0.24.0/src/cc/frontends/clang/kbuild_helper.cc#L158
										"SYS_MODULE",
										// Needed by gadgets that open a raw sock like dns and snisnoop.
										"NET_RAW",
									},
								},
							},
							VolumeMounts: []v1.VolumeMount{
								v1.VolumeMount{
									Name:      "host",
									MountPath: "/host",
								},
								v1.VolumeMount{
									Name:      "run",
									MountPath: "/run",
								},
								v1.VolumeMount{
									Name:      "modules",
									MountPath: "/lib/modules",
								},
								v1.VolumeMount{
									Name:      "debugfs",
									MountPath: "/sys/kernel/debug",
								},
								v1.VolumeMount{
									Name:      "cgroup",
									MountPath: "/sys/fs/cgroup",
								},
								v1.VolumeMount{
									Name:      "bpffs",
									MountPath: "/sys/fs/bpf",
								},
							},
						},
					},
					Tolerations: []v1.Toleration{
						v1.Toleration{
							Effect:   v1.TaintEffectNoSchedule,
							Operator: v1.TolerationOpExists,
						},
						v1.Toleration{
							Effect:   v1.TaintEffectNoExecute,
							Operator: v1.TolerationOpExists,
						},
					},
					Volumes: []v1.Volume{
						v1.Volume{
							Name:         "host",
							VolumeSource: v1.VolumeSource{
								HostPath: &v1.HostPathVolumeSource{
									Path: "/",
								},
							},
						},
						v1.Volume{
							Name:         "run",
							VolumeSource: v1.VolumeSource{
								HostPath: &v1.HostPathVolumeSource{
									Path: "/run",
								},
							},
						},
						v1.Volume{
							Name:         "cgroup",
							VolumeSource: v1.VolumeSource{
								HostPath: &v1.HostPathVolumeSource{
									Path: "/sys/fs/cgroup",
								},
							},
						},
						v1.Volume{
							Name:         "modules",
							VolumeSource: v1.VolumeSource{
								HostPath: &v1.HostPathVolumeSource{
									Path: "/lib/modules",
								},
							},
						},
						v1.Volume{
							Name:         "bpffs",
							VolumeSource: v1.VolumeSource{
								HostPath: &v1.HostPathVolumeSource{
									Path: "/sys/fs/bpf",
								},
							},
						},
						v1.Volume{
							Name:         "debugfs",
							VolumeSource: v1.VolumeSource{
								HostPath: &v1.HostPathVolumeSource{
									Path: "/sys/kernel/debug",
								},
							},
						},
					},
				},
			},
		},
	}

	_, err := k8sClient.AppsV1().DaemonSets(namespaceName).Create(context.TODO(), daemonSetSpec, metav1.CreateOptions{})

	return err
}

func runDeploy(cmd *cobra.Command, args []string) error {
	if hookMode != "auto" &&
		hookMode != "crio" &&
		hookMode != "podinformer" &&
		hookMode != "nri" &&
		hookMode != "fanotify" {
		return fmt.Errorf("invalid argument %q for --hook-mode=[auto,crio,podinformer,nri,fanotify]", hookMode)
	}

	var pullPolicy v1.PullPolicy
	switch imagePullPolicy{
		case "Always":
			pullPolicy = v1.PullAlways
		case "Never":
			pullPolicy = v1.PullNever
		case "IfNotPresent":
			pullPolicy = v1.PullIfNotPresent
		default:
			return fmt.Errorf("invalid argument %q for --image-pull-policy=[Always,Never,IfNotPresent]", imagePullPolicy)
	}

	k8sClient, err := k8sutil.NewClientsetFromConfigFlags(utils.KubernetesConfigFlags)
	if err != nil {
		return utils.WrapInErrSetupK8sClient(err)
	}

	// 1. Create gadget namespace.
	err = createGadgetNamespace(k8sClient, gadgetNamespace)
	if err != nil {
		return fmt.Errorf("failed to create namespace %s: %w", gadgetNamespace, err)
	}

	// 2. Create gadget serviceAccount.
	err = createGadgetServiceAccount(k8sClient, gadgetNamespace, gadgetServiceAccountName)
	if err != nil {
		return fmt.Errorf("failed to create service account %s: %w", gadgetServiceAccountName, err)
	}

	// 3. Create gadget role.
	err = createGadgetRole(k8sClient, gadgetNamespace, gadgetRoleName)
	if err != nil {
		return fmt.Errorf("failed to create role %s: %w", gadgetRoleName, err)
	}

	// 4. Create gadget role binding.
	err = createGadgetRoleBinding(k8sClient, gadgetNamespace, gadgetRoleBindingName)
	if err != nil {
		return fmt.Errorf("failed to create role binding %s: %w", gadgetRoleBindingName, err)
	}

	// 5. Create gadget cluster role.
	err = createGadgetClusterRole(k8sClient, gadgetClusterRoleName)
	if err != nil {
		return fmt.Errorf("failed to create cluster role %s: %w", gadgetClusterRoleName, err)
	}

	// 6. Create gadget cluster role binding.
	err = createGadgetClusterRoleBinding(k8sClient, gadgetClusterRoleBindingName)
	if err != nil {
		return fmt.Errorf("failed to create cluster role binding %s: %w", gadgetClusterRoleBindingName, err)
	}

	fmt.Printf("%s\n---\n", resources.TracesCustomResource)

	// 7. Create gadget daemonset.
	err = createGadgetDaemonSet(k8sClient, gadgetDaemonSetName, gadgetNamespace, hookMode, image, pullPolicy, livenessProbe, fallbackPodInformer)
	if err != nil {
		return fmt.Errorf("failed to create daemon set %s: %w", gadgetDaemonSetName, err)
	}

	return nil
}
