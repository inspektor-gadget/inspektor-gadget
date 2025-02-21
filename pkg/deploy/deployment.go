// Copyright 2019-2025 The Inspektor Gadget authors
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

package deploy

import (
	"context"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/distribution/reference"
	log "github.com/sirupsen/logrus"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apiextv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/selection"
	"k8s.io/apimachinery/pkg/types"
	k8sversion "k8s.io/apimachinery/pkg/util/version"
	utilwait "k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/discovery/cached/memory"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/restmapper"
	"k8s.io/client-go/tools/cache"
	watchtools "k8s.io/client-go/tools/watch"
	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1beta1"
	"sigs.k8s.io/yaml"

	"github.com/inspektor-gadget/inspektor-gadget/cmd/kubectl-gadget/utils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/config/gadgettracermanagerconfig"
	runtimeclient "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/runtime-client"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/k8sutil"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/resources"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/experimental"
)

const (
	gadgetPullSecret = "gadget-pull-secret"
	configYamlKey    = "config.yaml"
)

const (
	ParamImage                    = "image"
	ParamImagePullPolicy          = "image-pull-policy"
	ParamHookMode                 = "hook-mode"
	ParamLivenessProbe            = "liveness-probe"
	ParamFallbackPodinformer      = "fallback-podinformer"
	ParamPrintOnly                = "print-only"
	ParamWait                     = "wait"
	ParamTimeout                  = "timeout"
	ParamQuiet                    = "quiet"
	ParamDebug                    = "debug"
	ParamSeccompProfile           = "seccomp-profile"
	ParamNodeSelector             = "node-selector"
	ParamExperimental             = "experimental"
	ParamSkipSELinuxOpts          = "skip-selinux-opts"
	ParamEventsBufferLength       = "events-buffer-length"
	ParamDaemonLogLevel           = "daemon-log-level"
	ParamAppArmorProfile          = "apparmor-profile"
	ParamVerifyImage              = "verify-image"
	ParamPublicKey                = "public-key"
	ParamVerifyGadgets            = "verify-gadgets"
	ParamGadgetsPublicKey         = "gadgets-public-keys"
	ParamAllowedGadgets           = "allowed-gadgets"
	ParamInsecureRegistries       = "insecure-registries"
	ParamDisallowGadgetPulling    = "disallow-gadgets-pulling"
	ParamOtelMetricsListen        = "otel-metrics-listen"
	ParamOtelMetricsListenAddress = "otel-metrics-listen-address"

	ParamDockerSocketPath     = "docker-socketpath"
	ParamContainerdSocketPath = "containerd-socketpath"
	ParamCrioSocketPath       = "crio-socketpath"
	ParamPodmanSocketPath     = "podman-socketpath"

	ParamGroupSecurity = "group:Security"
	ParamGroupRuntimes = "group:Runtimes"
	ParamGroupOtel     = "group:Open Telemetry"
)

type Deployment struct {
	config *DeploymentConfig
}

type RuntimesSocketPathConfig struct {
	Docker     string
	Containerd string
	Crio       string
	Podman     string
}

type DeploymentConfig struct {
	Image                 string
	ImagePullPolicy       string
	HookMode              string
	LivenessProbe         bool
	DeployTimeout         time.Duration
	FallbackPodInformer   bool
	PrintOnly             bool
	Quiet                 bool
	Debug                 bool
	SeccompProfile        string
	Wait                  bool
	RuntimesConfig        RuntimesSocketPathConfig
	NodeSelector          string
	ExperimentalVar       bool
	SkipSELinuxOpts       bool
	EventBufferLength     uint64
	DaemonLogLevel        string
	AppArmorprofile       string
	VerifyImage           bool
	PublicKey             string
	VerifyGadgets         bool
	GadgetsPublicKeys     string
	AllowedGadgets        []string
	InsecureRegistries    []string
	DisallowGadgetsPull   bool
	OtelMetricsListen     bool
	OtelMetricsListenAddr string
}

var strLevels []string

var supportedHooks = []string{"auto", "crio", "podinformer", "nri", "fanotify+ebpf"}

var clusterImagePolicyKind = schema.GroupVersionKind{
	Group:   "policy.sigstore.dev",
	Version: "v1beta1",
	Kind:    "ClusterImagePolicy",
}

var admissionControllerFormat = `
apiVersion: policy.sigstore.dev/v1beta1
kind: ClusterImagePolicy
metadata:
  name: %s-image-policy
spec:
  images:
  - glob: "%s"
  authorities:
    - key:
        hashAlgorithm: sha256
        data: !!binary |
          %s
`

func (*Deployment) Params() api.Params {
	return api.Params{
		{
			Key:          ParamImage,
			Title:        "Container Image",
			Description:  "container image",
			DefaultValue: gadgetimage,
			IsMandatory:  true,
		},
		{
			Key:            ParamImagePullPolicy,
			Title:          "Image Pull Policy",
			Description:    "pull policy for the container image",
			DefaultValue:   "Always",
			PossibleValues: []string{"Always", "Never", "IfNotPresent"},
		},
		{
			Key:            ParamHookMode,
			Title:          "Hook Mode",
			Description:    "how to get containers start/stop notifications",
			DefaultValue:   "auto",
			PossibleValues: supportedHooks,
			Tags:           []string{"advanced"},
		},
		{
			Key:          ParamLivenessProbe,
			Title:        "Liveness Probe",
			Description:  "enable liveness probe",
			TypeHint:     api.TypeBool,
			DefaultValue: "true",
			Tags:         []string{"advanced"},
		},
		{
			Key:          ParamFallbackPodinformer,
			Title:        "Fallback Pod Informer",
			Description:  "use pod informer as a fallback for the main hook",
			TypeHint:     api.TypeBool,
			DefaultValue: "true",
			Tags:         []string{"advanced"},
		},
		{
			Key:          ParamPrintOnly,
			Description:  "only print YAML of resources",
			TypeHint:     api.TypeBool,
			DefaultValue: "false",
			Tags:         []string{"gui.hide"},
		},
		{
			Key:          ParamWait,
			Description:  "wait for gadget pod to be ready",
			TypeHint:     api.TypeBool,
			DefaultValue: "true",
			Tags:         []string{"gui.hide"},
		},
		{
			Key:          ParamTimeout,
			Title:        "Timeout",
			Description:  "timeout for deployment",
			TypeHint:     api.TypeInt,
			DefaultValue: fmt.Sprintf("%d", 120*time.Second),
			Tags:         []string{"gui.hide"},
		},
		{
			Key:          ParamQuiet,
			Description:  "suppress information messages",
			TypeHint:     api.TypeBool,
			DefaultValue: "false",
			Tags:         []string{"gui.hide"},
		},
		{
			Key:          ParamDebug,
			Description:  "show extra debug information",
			TypeHint:     api.TypeBool,
			DefaultValue: "false",
			Tags:         []string{"gui.hide"},
		},
		{
			Key:         ParamSeccompProfile,
			Title:       "Seccomp Profile",
			Description: "restrict gadget pod syscalls using given seccomp profile",
			Tags:        []string{"advanced"},
		},
		{
			Key:         ParamNodeSelector,
			Title:       "Node Selector",
			Description: "node labels selector for the Inspektor Gadget DaemonSet",
		},
		{
			Key:          ParamExperimental,
			Title:        "Experimental Features",
			Description:  "enable experimental features",
			TypeHint:     api.TypeBool,
			DefaultValue: "false",
		},
		{
			Key:          ParamSkipSELinuxOpts,
			Description:  "skip setting SELinux options on the gadget pod",
			TypeHint:     api.TypeBool,
			DefaultValue: "false",
			Tags:         []string{"advanced"},
		},
		{
			Key:          ParamEventsBufferLength,
			Title:        "Event Buffer Count",
			Description:  "The events buffer length. A low value could impact horizontal scaling.", // TODO
			TypeHint:     api.TypeInt,
			DefaultValue: "16384",
			Tags:         []string{"advanced"},
		},
		{
			Key:            ParamDaemonLogLevel,
			Title:          "Daemon Log Level",
			PossibleValues: strLevels,
			Tags:           []string{"advanced"},
		},
		{
			Key:          ParamAppArmorProfile,
			DefaultValue: "unconfined",
			Tags:         []string{ParamGroupSecurity, "advanced"},
		},
		{
			Key:          ParamVerifyImage,
			Description:  "verify container image if policy-controller is installed on the cluster",
			TypeHint:     api.TypeBool,
			DefaultValue: "true",
			Tags:         []string{ParamGroupSecurity, "advanced"},
		},
		{
			Key:          ParamPublicKey,
			Description:  "public key used to verify the container image",
			DefaultValue: resources.InspektorGadgetPublicKey,
			Tags:         []string{ParamGroupSecurity, "advanced"},
		},
		{
			Key:          ParamVerifyGadgets,
			Title:        "Verify Gadget Signatures",
			Description:  "verify gadgets using the provided public keys",
			TypeHint:     api.TypeBool,
			DefaultValue: "true",
			Tags:         []string{ParamGroupSecurity},
		},
		{
			Key:          ParamGadgetsPublicKey,
			Title:        "Public Keys for Gadgets",
			Description:  "public keys used to verify the gadgets",
			TypeHint:     api.TypeStringSlice,
			DefaultValue: resources.InspektorGadgetPublicKey,
			Tags:         []string{ParamGroupSecurity},
		},
		{
			Key:         ParamAllowedGadgets,
			Title:       "Allowed Gadgets",
			TypeHint:    api.TypeStringSlice,
			Description: "List of allowed gadgets. If a gadget is not part of it, execution will be denied.",
			Tags:        []string{ParamGroupSecurity, "advanced"},
		},
		{
			Key:         ParamInsecureRegistries,
			Title:       "Insecure Registries",
			Description: "List of registries to access over plain HTTP",
			Tags:        []string{ParamGroupSecurity, "advanced"},
		},
		{
			Key:          ParamDisallowGadgetPulling,
			Title:        "Disallow Gadget Pulling",
			Description:  "Disallow pulling gadgets from registries",
			TypeHint:     api.TypeBool,
			DefaultValue: "false",
			Tags:         []string{ParamGroupSecurity, "advanced"},
		},
		{
			// TODO - migrate to otel-metrics operator
			Key:          ParamOtelMetricsListen,
			Title:        "Enable OpenTelemetry listener",
			Description:  "Enable OpenTelemetry metrics listener (Prometheus compatible) endpoint",
			TypeHint:     api.TypeBool,
			DefaultValue: "false",
			Tags:         []string{ParamGroupOtel},
		},
		{
			// TODO - migrate to otel-metrics operator
			Key:          ParamOtelMetricsListenAddress,
			Title:        "OpenTelemetry listener address",
			Description:  "Address and port to create the OpenTelemetry metrics listener on",
			DefaultValue: "0.0.0.0:2224",
			Tags:         []string{ParamGroupOtel},
		},

		{
			Key:          ParamDockerSocketPath,
			Title:        "Docker Socket Path",
			Description:  "Docker Engine API Unix socket path",
			DefaultValue: runtimeclient.DockerDefaultSocketPath,
			Tags:         []string{"advanced", ParamGroupRuntimes},
		},
		{
			Key:          ParamContainerdSocketPath,
			Title:        "containerd Socket Path",
			Description:  "containerd CRI Unix socket path",
			DefaultValue: runtimeclient.ContainerdDefaultSocketPath,
			Tags:         []string{"advanced", ParamGroupRuntimes},
		},
		{
			Key:          ParamCrioSocketPath,
			Title:        "CRI-O Socket Path",
			Description:  "CRI-O CRI Unix socket path",
			DefaultValue: runtimeclient.CrioDefaultSocketPath,
			Tags:         []string{"advanced", ParamGroupRuntimes},
		},
		{
			Key:          ParamPodmanSocketPath,
			Title:        "Podman Socket Path",
			Description:  "Podman CRI Unix socket path",
			DefaultValue: runtimeclient.PodmanDefaultSocketPath,
			Tags:         []string{"advanced", ParamGroupRuntimes},
		},
	}
}

func (d *Deployment) ValidateParamValues(pv api.ParamValues) error {
	nv, err := pv.Validate(d.Params())
	if err != nil {
		return err
	}
	d.config.Image = nv.String(ParamImage)
	d.config.ImagePullPolicy = nv.String(ParamImagePullPolicy)
	d.config.HookMode = nv.String(ParamHookMode)
	d.config.LivenessProbe = nv.Bool(ParamLivenessProbe)
	d.config.FallbackPodInformer = nv.Bool(ParamFallbackPodinformer)
	d.config.PrintOnly = nv.Bool(ParamPrintOnly)
	d.config.Wait = nv.Bool(ParamWait)
	d.config.DeployTimeout = nv.Duration(ParamTimeout)
	d.config.Quiet = nv.Bool(ParamQuiet)
	d.config.Debug = nv.Bool(ParamDebug)
	d.config.SeccompProfile = nv.String(ParamSeccompProfile)
	d.config.NodeSelector = nv.String(ParamNodeSelector)
	d.config.ExperimentalVar = nv.Bool(ParamExperimental)
	d.config.SkipSELinuxOpts = nv.Bool(ParamSkipSELinuxOpts)
	d.config.EventBufferLength = nv.Uint64(ParamEventsBufferLength)
	d.config.DaemonLogLevel = nv.String(ParamDaemonLogLevel)
	d.config.AppArmorprofile = nv.String(ParamAppArmorProfile)
	d.config.VerifyImage = nv.Bool(ParamVerifyImage)
	d.config.PublicKey = nv.String(ParamPublicKey)
	d.config.VerifyGadgets = nv.Bool(ParamVerifyGadgets)
	d.config.GadgetsPublicKeys = nv.String(ParamGadgetsPublicKey)
	d.config.AllowedGadgets = nv.StringSlice(ParamAllowedGadgets)
	d.config.InsecureRegistries = nv.StringSlice(ParamInsecureRegistries)
	d.config.DisallowGadgetsPull = nv.Bool(ParamDisallowGadgetPulling)
	d.config.OtelMetricsListen = nv.Bool(ParamOtelMetricsListen)
	d.config.OtelMetricsListenAddr = nv.String(ParamOtelMetricsListenAddress)

	d.config.RuntimesConfig.Docker = nv.String(ParamDockerSocketPath)
	d.config.RuntimesConfig.Containerd = nv.String(ParamContainerdSocketPath)
	d.config.RuntimesConfig.Crio = nv.String(ParamCrioSocketPath)
	d.config.RuntimesConfig.Podman = nv.String(ParamPodmanSocketPath)
	return nil
}

func init() {
	strLevels = make([]string, len(log.AllLevels))
	for i, level := range log.AllLevels {
		strLevels[i] = level.String()
	}
}

func (d *Deployment) info(format string, args ...any) {
	if d.config.Quiet {
		return
	}
	fmt.Printf(format, args...)
}

// parseK8sYaml parses a k8s YAML deployment file content and returns the
// corresponding objects.
// It was adapted from:
// https://github.com/kubernetes/client-go/issues/193#issuecomment-363318588
func (d *Deployment) parseK8sYaml(content string) ([]runtime.Object, error) {
	// We need to use a regex due to public key which contains "-----".
	pattern := regexp.MustCompile(`(?m)^---$`)
	sepYamlfiles := pattern.Split(content, -1)
	retVal := make([]runtime.Object, 0, len(sepYamlfiles))

	sch := runtime.NewScheme()

	if d.config.SeccompProfile != "" {
		// For SeccompProfile Kind.
		seccompprofileapi.AddToScheme(sch)
	}

	// For CustomResourceDefinition kind.
	apiextv1.AddToScheme(sch)
	// For ClusterImagePolicy kind, this avoid including all sigstore dependencies.
	sch.AddKnownTypeWithName(clusterImagePolicyKind, &unstructured.Unstructured{})
	// For all the other kinds (e.g. Namespace).
	scheme.AddToScheme(sch)

	for _, f := range sepYamlfiles {
		if f == "\n" || f == "" {
			// ignore empty cases
			continue
		}

		decode := serializer.NewCodecFactory(sch).UniversalDeserializer().Decode
		obj, _, err := decode([]byte(f), nil, nil)
		if err != nil {
			return nil, fmt.Errorf("decoding YAML object %v: %w", f, err)
		}

		retVal = append(retVal, obj)
	}

	return retVal, nil
}

// stringToPullPolicy returns the PullPolicy corresponding to the given string
// or an error if there is no corresponding policy.
func stringToPullPolicy(imagePullPolicy string) (v1.PullPolicy, error) {
	switch imagePullPolicy {
	case "Always":
		return v1.PullAlways, nil
	case "Never":
		return v1.PullNever, nil
	case "IfNotPresent":
		return v1.PullIfNotPresent, nil
	default:
		return "", fmt.Errorf("invalid pull policy: %s. Possible values are [Always, Never, IfNotPresent]",
			imagePullPolicy)
	}
}

// createOrUpdateResource creates or updates the resource corresponding
// to the object given as parameter using a dynamic client a RESTMapper
// to get the corresponding resource.
// It is inspired from:
// https://ymmt2005.hatenablog.com/entry/2020/04/14/An_example_of_using_dynamic_client_of_k8s.io/client-go#Dynamic-client
func (d *Deployment) createOrUpdateResource(client dynamic.Interface, mapper meta.RESTMapper, object runtime.Object) (*unstructured.Unstructured, error) {
	groupVersionKind := object.GetObjectKind().GroupVersionKind()
	mapping, err := mapper.RESTMapping(groupVersionKind.GroupKind(), groupVersionKind.Version)
	if err != nil {
		return nil, err
	}

	unstructuredObj, err := runtime.DefaultUnstructuredConverter.ToUnstructured(object)
	if err != nil {
		return nil, fmt.Errorf("converting object to untrusctured: %w", err)
	}

	unstruct := &unstructured.Unstructured{Object: unstructuredObj}

	var dynamicInterface dynamic.ResourceInterface
	if mapping.Scope.Name() == meta.RESTScopeNameNamespace {
		dynamicInterface = client.Resource(mapping.Resource).Namespace(unstruct.GetNamespace())
	} else {
		dynamicInterface = client.Resource(mapping.Resource)
	}

	d.info("Creating %s/%s...\n", unstruct.GetKind(), unstruct.GetName())

	data, err := json.Marshal(unstruct)
	if err != nil {
		return nil, err
	}

	obj, err := dynamicInterface.Patch(context.TODO(), unstruct.GetName(), types.ApplyPatchType, data, metav1.PatchOptions{
		FieldManager: "kubectl-gadget",
	})
	if err != nil {
		return nil, fmt.Errorf("creating %q: %w", groupVersionKind.Kind, err)
	}

	return obj, nil
}

// Based on https://github.com/kubernetes/kubernetes/issues/98256#issue-790804261
func operatorAsNodeSelectorOperator(sop selection.Operator) (v1.NodeSelectorOperator, error) {
	switch sop {
	case selection.DoesNotExist:
		return v1.NodeSelectorOpDoesNotExist, nil
	case selection.Equals, selection.DoubleEquals, selection.In:
		return v1.NodeSelectorOpIn, nil
	case selection.NotEquals, selection.NotIn:
		return v1.NodeSelectorOpNotIn, nil
	case selection.Exists:
		return v1.NodeSelectorOpExists, nil
	case selection.GreaterThan:
		return v1.NodeSelectorOpGt, nil
	case selection.LessThan:
		return v1.NodeSelectorOpLt, nil
	default:
		return v1.NodeSelectorOpIn, fmt.Errorf("%q is not a valid node selector operator", sop)
	}
}

func selectorAsNodeSelector(s string) (*v1.NodeSelector, error) {
	selector, err := labels.Parse(s)
	if err != nil {
		return nil, fmt.Errorf("parsing labels: %w", err)
	}

	nreqs := []v1.NodeSelectorRequirement{}
	reqs, _ := selector.Requirements()
	for _, req := range reqs {
		operator, err := operatorAsNodeSelectorOperator(req.Operator())
		if err != nil {
			return nil, err
		}
		nreq := v1.NodeSelectorRequirement{
			Key:      req.Key(),
			Operator: operator,
			Values:   req.Values().List(),
		}
		nreqs = append(nreqs, nreq)
	}
	nodeSelector := &v1.NodeSelector{
		NodeSelectorTerms: []v1.NodeSelectorTerm{
			{
				MatchExpressions: nreqs,
			},
		},
	}
	return nodeSelector, nil
}

// This function handles translating an AppArmor profile as given for
// annotations to the new structure offered by k8s >= 1.30:
// https://pkg.go.dev/k8s.io/api/core/v1#AppArmorProfileType
func createAppArmorProfile(profile string) (*v1.AppArmorProfile, error) {
	ret := &v1.AppArmorProfile{}

	parts := strings.Split(profile, "/")
	switch parts[0] {
	case "unconfined":
		ret.Type = v1.AppArmorProfileTypeUnconfined
	case "runtime":
		ret.Type = v1.AppArmorProfileTypeRuntimeDefault
	case "localhost":
		ret.Type = v1.AppArmorProfileTypeLocalhost

		if len(parts) != 2 {
			return nil, fmt.Errorf("AppArmor profile malformed: localhost/profile expected, got %q", profile)
		}

		ret.LocalhostProfile = &parts[1]
	default:
		return nil, fmt.Errorf("AppArmor profile badly named: expected unconfined, runtime or localhost, got %q", parts[0])
	}

	return ret, nil
}

// createAffinity returns the affinity to be used for the DaemonSet.
func (d *Deployment) createAffinity(client *kubernetes.Clientset) (*v1.Affinity, error) {
	nodes, err := client.CoreV1().Nodes().List(context.TODO(), metav1.ListOptions{LabelSelector: d.config.NodeSelector})
	if err != nil {
		return nil, fmt.Errorf("listing nodes: %w", err)
	}

	if len(nodes.Items) == 0 {
		return nil, fmt.Errorf("no nodes found for labels: %q", d.config.NodeSelector)
	}

	nodeSelector, err := selectorAsNodeSelector(d.config.NodeSelector)
	if err != nil {
		return nil, err
	}

	affinity := &v1.Affinity{
		NodeAffinity: &v1.NodeAffinity{
			RequiredDuringSchedulingIgnoredDuringExecution: nodeSelector,
		},
	}

	return affinity, nil
}

func (d *Deployment) Deploy(gadgetNamespace string) error {
	if !d.config.PrintOnly {
		gadgetNamespaces, err := utils.GetRunningGadgetNamespaces()
		if err != nil {
			return fmt.Errorf("searching for running Inspektor Gadget instances: %w", err)
		}
		if len(gadgetNamespaces) != 0 && gadgetNamespaces[0] != gadgetNamespace {
			// Inspektor Gadget is the program name and therefore capitalized (Lint error ST1005)
			//nolint:all
			return fmt.Errorf("Inspektor Gadget is already deployed to the following namespaces: %v. Only a single instance is allowed", gadgetNamespaces)
		}
	}

	if d.config.Quiet && d.config.Debug {
		return fmt.Errorf("it's not possible to use --quiet and --debug together")
	}

	objects, err := d.parseK8sYaml(resources.GadgetDeployment)
	if err != nil {
		return err
	}

	traceObjects, err := d.parseK8sYaml(resources.TracesCustomResource)
	if err != nil {
		return err
	}

	objects = append(objects, traceObjects...)

	if d.config.SeccompProfile != "" {
		content, err := os.ReadFile(d.config.SeccompProfile)
		if err != nil {
			return fmt.Errorf("reading %s: %w", d.config.SeccompProfile, err)
		}

		seccompProfileObject, err := d.parseK8sYaml(string(content))
		if err != nil {
			return err
		}

		if len(seccompProfileObject) > 1 {
			return fmt.Errorf("created seccomp profile has several objects")
		}

		// We need to create the seccomp profile before the daemonset but after the
		// namespace.
		objects = append(objects[:1], objects...)
		objects[1] = seccompProfileObject[0]
	}

	config, err := utils.KubernetesConfigFlags.ToRESTConfig()
	if err != nil {
		return fmt.Errorf("creating RESTConfig: %w", err)
	}

	discoveryClient, err := discovery.NewDiscoveryClientForConfig(config)
	if err != nil {
		return err
	}
	mapper := restmapper.NewDeferredDiscoveryRESTMapper(memory.NewMemCacheClient(discoveryClient))

	dynamicClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("creating dynamic client: %w", err)
	}

	k8sClient, err := k8sutil.NewClientsetFromConfigFlags(utils.KubernetesConfigFlags)
	if err != nil {
		return fmt.Errorf("creating k8s client: %w", err)
	}

	var isPullSecretPresent bool
	if _, err = k8sClient.CoreV1().Secrets(gadgetNamespace).Get(context.TODO(), gadgetPullSecret, metav1.GetOptions{}); err == nil {
		isPullSecretPresent = true
	}

	var isPolicyControllerPresent bool
	if d.config.VerifyImage {
		if _, err = k8sClient.CoreV1().Namespaces().Get(context.TODO(), "cosign-system", metav1.GetOptions{}); err == nil {
			isPolicyControllerPresent = true
		} else {
			log.Warnf("No policy controller found, the container image will not be verified")
		}

		if isPolicyControllerPresent {
			encodedKey := base64.StdEncoding.EncodeToString([]byte(d.config.PublicKey))

			ref, err := reference.Parse(d.config.Image)
			if err != nil {
				return fmt.Errorf("parsing image name %q: %w", d.config.Image, err)
			}

			// We cannot use tag as image for admission controller, as the tested image
			// will use digest:
			// Error: problem while creating resource: creating "DaemonSet": admission webhook "policy.sigstore.dev" denied the request: validation failed: no matching policies: spec.template.spec.containers[0].image
			// ghcr.io/inspektor-gadget/inspektor-gadget@sha256:a6c2b00174013789d4af0cc48ba5e269426ff44f27dcb9b84f489537280e0871
			// So, if users gave a digest, we use it directly.
			// Otherwise, i.e. user gave a tag or the image itself, we extract the
			// repository from it and add "**" to glob it.
			admissionImage := ""
			if digested, ok := ref.(reference.Digested); ok {
				admissionImage = digested.String()
			} else if named, ok := ref.(reference.Named); ok {
				admissionImage = fmt.Sprintf("%s**", reference.TrimNamed(named).String())
			} else {
				return fmt.Errorf("reference is neither reference.Digested nor reference.Named but %T", ref)
			}

			admissionControllerYAML := fmt.Sprintf(admissionControllerFormat, gadgetNamespace, admissionImage, encodedKey)

			admissionControllerObject, err := d.parseK8sYaml(admissionControllerYAML)
			if err != nil {
				return err
			}

			objects = append(admissionControllerObject, objects...)
		}
	} else {
		log.Warnf("You used --verify-image=false, the container image will not be verified")
	}

	for _, object := range objects {
		var currentGadgetDS *appsv1.DaemonSet

		daemonSet, handlingDaemonSet := object.(*appsv1.DaemonSet)
		if handlingDaemonSet {
			daemonSet.Spec.Template.Annotations["inspektor-gadget.kinvolk.io/option-hook-mode"] = d.config.HookMode

			daemonSet.Namespace = gadgetNamespace

			if d.config.SeccompProfile != "" {
				path := "operator/gadget/profile.json"
				daemonSet.Spec.Template.Spec.SecurityContext = &v1.PodSecurityContext{
					SeccompProfile: &v1.SeccompProfile{
						Type:             v1.SeccompProfileTypeLocalhost,
						LocalhostProfile: &path,
					},
				}
			}

			if !d.config.PrintOnly {
				serverInfo, err := discoveryClient.ServerVersion()
				if err != nil {
					return fmt.Errorf("getting server version: %w", err)
				}

				serverVersion := k8sversion.MustParseSemantic(serverInfo.String())

				// The "kubernetes.io/os" node label was introduced in v1.14.0
				// (https://github.com/kubernetes/kubernetes/blob/master/CHANGELOG/CHANGELOG-1.14.md.)
				// Remove this if the cluster is older than that to allow Inspektor Gadget to work there.
				if serverVersion.LessThan(k8sversion.MustParseSemantic("v1.14.0")) {
					delete(daemonSet.Spec.Template.Spec.NodeSelector, "kubernetes.io/os")
				}

				// Before 1.30, AppArmor profile was set as annotation, but since 1.30
				// it has specific types:
				// https://kubernetes.io/docs/tutorials/security/apparmor/#securing-a-pod
				if serverVersion.AtLeast(k8sversion.MustParseSemantic("v1.30.0")) {
					delete(daemonSet.Spec.Template.Annotations, "container.apparmor.security.beta.kubernetes.io/gadget")

					profile, err := createAppArmorProfile(d.config.AppArmorprofile)
					if err != nil {
						return fmt.Errorf("creating AppArmor profile: %w", err)
					}

					if daemonSet.Spec.Template.Spec.SecurityContext == nil {
						daemonSet.Spec.Template.Spec.SecurityContext = &v1.PodSecurityContext{}
					}

					daemonSet.Spec.Template.Spec.SecurityContext.AppArmorProfile = profile
				} else {
					daemonSet.Spec.Template.Annotations["container.apparmor.security.beta.kubernetes.io/gadget"] = d.config.AppArmorprofile
				}
			}

			gadgetContainer := &daemonSet.Spec.Template.Spec.Containers[0]

			gadgetContainer.Image = d.config.Image

			policy, err := stringToPullPolicy(d.config.ImagePullPolicy)
			if err != nil {
				return err
			}
			gadgetContainer.ImagePullPolicy = policy

			if !d.config.LivenessProbe {
				gadgetContainer.LivenessProbe = nil
			}

			for i := range gadgetContainer.Env {
				switch gadgetContainer.Env[i].Name {
				case "GADGET_IMAGE":
					gadgetContainer.Env[i].Value = d.config.Image
				case "INSPEKTOR_GADGET_OPTION_HOOK_MODE":
					gadgetContainer.Env[i].Value = d.config.HookMode
				case "INSPEKTOR_GADGET_OPTION_FALLBACK_POD_INFORMER":
					gadgetContainer.Env[i].Value = strconv.FormatBool(d.config.FallbackPodInformer)
				case utils.GadgetEnvironmentContainerdSocketpath:
					gadgetContainer.Env[i].Value = d.config.RuntimesConfig.Containerd
				case utils.GadgetEnvironmentCRIOSocketpath:
					gadgetContainer.Env[i].Value = d.config.RuntimesConfig.Crio
				case utils.GadgetEnvironmentDockerSocketpath:
					gadgetContainer.Env[i].Value = d.config.RuntimesConfig.Docker
				case utils.GadgetEnvironmentPodmanSocketpath:
					gadgetContainer.Env[i].Value = d.config.RuntimesConfig.Podman
				case experimental.EnvName:
					value := experimental.Enabled() || d.config.ExperimentalVar
					gadgetContainer.Env[i].Value = strconv.FormatBool(value)
				case "EVENTS_BUFFER_LENGTH":
					gadgetContainer.Env[i].Value = strconv.FormatUint(d.config.EventBufferLength, 10)
				case "GADGET_TRACER_MANAGER_LOG_LEVEL":
					if !slices.Contains(strLevels, d.config.DaemonLogLevel) {
						return fmt.Errorf("invalid log level %q, valid levels are: %v", d.config.DaemonLogLevel, strings.Join(strLevels, ", "))
					}
					gadgetContainer.Env[i].Value = d.config.DaemonLogLevel
				}
			}

			if d.config.NodeSelector != "" {
				affinity, err := d.createAffinity(k8sClient)
				if err != nil {
					return fmt.Errorf("creating affinity: %w", err)
				}
				daemonSet.Spec.Template.Spec.Affinity = affinity
			}

			// skip SELinux options if the user explicitly requests it
			if d.config.SkipSELinuxOpts {
				gadgetContainer.SecurityContext.SELinuxOptions = nil
			}

			// Get gadget daemon set (if any) to check if it was modified
			currentGadgetDS, _ = k8sClient.AppsV1().DaemonSets(gadgetNamespace).Get(
				context.TODO(), "gadget", metav1.GetOptions{},
			)

			// handle pull secret
			if isPullSecretPresent {
				daemonSet.Spec.Template.Spec.Volumes = append(daemonSet.Spec.Template.Spec.Volumes, v1.Volume{
					Name: "pull-secret",
					VolumeSource: v1.VolumeSource{
						Secret: &v1.SecretVolumeSource{
							SecretName: gadgetPullSecret,
							Items: []v1.KeyToPath{
								{
									Key:  ".dockerconfigjson",
									Path: "config.json",
								},
							},
						},
					},
				})
				gadgetContainer.VolumeMounts = append(gadgetContainer.VolumeMounts, v1.VolumeMount{
					Name:      "pull-secret",
					MountPath: "/var/run/secrets/gadget/pull-secret",
					ReadOnly:  true,
				})
			}
		}

		if ns, isNs := object.(*v1.Namespace); isNs {
			ns.Name = gadgetNamespace

			if d.config.VerifyImage && isPolicyControllerPresent {
				if ns.Labels != nil {
					ns.Labels["policy.sigstore.dev/include"] = "true"
				} else {
					ns.Labels = map[string]string{"policy.sigstore.dev/include": "true"}
				}
			}
		}
		if sa, isSa := object.(*v1.ServiceAccount); isSa {
			sa.Namespace = gadgetNamespace
		}
		if crBinding, isCrBinding := object.(*rbacv1.ClusterRoleBinding); isCrBinding {
			if len(crBinding.Subjects) == 1 {
				crBinding.Subjects[0].Namespace = gadgetNamespace
			}
		}
		if role, isRole := object.(*rbacv1.Role); isRole {
			role.Namespace = gadgetNamespace
		}
		if rBinding, isRole := object.(*rbacv1.RoleBinding); isRole {
			rBinding.Namespace = gadgetNamespace
		}

		if cm, isCm := object.(*v1.ConfigMap); isCm {
			cm.Namespace = gadgetNamespace
			cfgData, ok := cm.Data[configYamlKey]
			if !ok {
				return fmt.Errorf("%q not found in ConfigMap %q", configYamlKey, cm.Name)
			}
			cfg := make(map[string]interface{}, len(cm.Data))
			err = yaml.Unmarshal([]byte(cfgData), &cfg)
			if err != nil {
				return fmt.Errorf("unmarshaling config.yaml: %w", err)
			}

			cfg[gadgettracermanagerconfig.HookModeKey] = d.config.HookMode
			cfg[gadgettracermanagerconfig.FallbackPodInformerKey] = d.config.FallbackPodInformer
			cfg[gadgettracermanagerconfig.EventsBufferLengthKey] = d.config.EventBufferLength
			cfg[gadgettracermanagerconfig.ContainerdSocketPath] = d.config.RuntimesConfig.Containerd
			cfg[gadgettracermanagerconfig.CrioSocketPath] = d.config.RuntimesConfig.Crio
			cfg[gadgettracermanagerconfig.DockerSocketPath] = d.config.RuntimesConfig.Docker
			cfg[gadgettracermanagerconfig.PodmanSocketPath] = d.config.RuntimesConfig.Podman

			opCfg, ok := cfg[gadgettracermanagerconfig.Operator].(map[string]interface{})
			if !ok {
				return fmt.Errorf("%s not found in config.yaml", gadgettracermanagerconfig.Operator)
			}

			opOciCfg, ok := opCfg[gadgettracermanagerconfig.Oci].(map[string]interface{})
			if !ok {
				return fmt.Errorf("%s.%s not found in config.yaml", gadgettracermanagerconfig.Operator, gadgettracermanagerconfig.Oci)
			}

			opOciCfg[gadgettracermanagerconfig.VerifyImage] = d.config.VerifyGadgets
			opOciCfg[gadgettracermanagerconfig.PublicKeys] = strings.Split(d.config.GadgetsPublicKeys, ",")
			opOciCfg[gadgettracermanagerconfig.AllowedGadgets] = d.config.AllowedGadgets
			opOciCfg[gadgettracermanagerconfig.InsecureRegistries] = d.config.InsecureRegistries
			opOciCfg[gadgettracermanagerconfig.DisallowPulling] = d.config.DisallowGadgetsPull

			if d.config.OtelMetricsListen {
				otelMetricsConfig := map[string]interface{}{
					gadgettracermanagerconfig.OtelMetricsListen:        d.config.OtelMetricsListen,
					gadgettracermanagerconfig.OtelMetricsListenAddress: d.config.OtelMetricsListenAddr,
				}
				opCfg[gadgettracermanagerconfig.OtelMetrics] = otelMetricsConfig
			}

			data, err := yaml.Marshal(cfg)
			if err != nil {
				return fmt.Errorf("marshaling config.yaml: %w", err)
			}
			cm.Data[configYamlKey] = string(data)
		}

		if d.config.PrintOnly {
			bytes, err := yaml.Marshal(object)
			if err != nil {
				return fmt.Errorf("problem while marshaling object: %w", err)
			}
			fmt.Printf("%s---\n", bytes)
			continue
		}

		obj, err := d.createOrUpdateResource(dynamicClient, mapper, object)
		if err != nil {
			return fmt.Errorf("problem while creating resource: %w", err)
		}

		if handlingDaemonSet {
			var appliedGadgetDS appsv1.DaemonSet
			err := runtime.DefaultUnstructuredConverter.FromUnstructured(obj.Object, &appliedGadgetDS)
			if err != nil {
				return fmt.Errorf("converting data: %w", err)
			}

			// If the spec of the DaemonSet is the same just return
			if reflect.DeepEqual(currentGadgetDS.Spec, appliedGadgetDS.Spec) {
				d.info("The gadget pod(s) weren't modified!\n")
				return nil
			}
		}
	}

	if d.config.PrintOnly {
		return nil
	}
	if !d.config.Wait {
		d.info("Inspektor Gadget is being deployed\n")
		return nil
	}

	d.info("Waiting for gadget pod(s) to be ready...\n")

	// The below code (particularly how to use UntilWithSync) is highly
	// inspired from kubectl wait source code:
	// https://github.com/kubernetes/kubectl/blob/b5fe0f6e9c65ea95a2118746b7e04822255d76c2/pkg/cmd/wait/wait.go#L364
	daemonSetInterface := k8sClient.AppsV1().DaemonSets(gadgetNamespace)
	lw := &cache.ListWatch{
		ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
			options.LabelSelector = "k8s-app=gadget"

			return daemonSetInterface.List(context.TODO(), options)
		},
		WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
			options.LabelSelector = "k8s-app=gadget"

			return daemonSetInterface.Watch(context.TODO(), options)
		},
	}

	ctx, cancel := watchtools.ContextWithOptionalTimeout(context.TODO(), d.config.DeployTimeout)
	defer cancel()

	_, err = watchtools.UntilWithSync(ctx, lw, &appsv1.DaemonSet{}, nil, func(event watch.Event) (bool, error) {
		switch event.Type {
		case watch.Deleted:
			return false, fmt.Errorf("DaemonSet from namespace %s should not be deleted", gadgetNamespace)
		case watch.Modified:
			daemonSet, _ := event.Object.(*appsv1.DaemonSet)
			status := daemonSet.Status

			ready := status.NumberReady
			if status.UpdatedNumberScheduled < ready {
				ready = status.UpdatedNumberScheduled
			}

			d.info("%d/%d gadget pod(s) ready\n", ready, status.DesiredNumberScheduled)

			return (status.DesiredNumberScheduled == status.NumberReady) &&
				(status.DesiredNumberScheduled == status.UpdatedNumberScheduled), nil
		case watch.Error:
			// Deal particularly with error.
			return false, fmt.Errorf("received event is an error one: %v", event)
		default:
			// We are not interested in other event types.
			return false, nil
		}
	})
	if err != nil {
		if utilwait.Interrupted(err) && d.config.Debug {
			fmt.Println("DUMP PODS:")
			fmt.Println(getGadgetPodsDebug(k8sClient, gadgetNamespace))
			fmt.Println("DUMP EVENTS:")
			fmt.Println(getEvents(k8sClient, gadgetNamespace))
		}
		return err
	}
	return nil
}
