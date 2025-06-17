// Copyright 2024 The Inspektor Gadget authors
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

package gadgettracermanagerconfig

const ConfigPath = "/etc/ig/config.yaml"

const (
	HookModeKey            = "hook-mode"
	FallbackPodInformerKey = "fallback-pod-informer"
	EventsBufferLengthKey  = "events-buffer-length"
	ContainerdSocketPath   = "containerd-socketpath"
	CrioSocketPath         = "crio-socketpath"
	DockerSocketPath       = "docker-socketpath"
	PodmanSocketPath       = "podman-socketpath"
	GadgetNamespace        = "gadget-namespace"

	VerifyImage        = "verify-image"
	PublicKeys         = "public-keys"
	InsecureRegistries = "insecure-registries"
	DisallowPulling    = "disallow-pulling"
	AllowedGadgets     = "allowed-gadgets"

	OtelMetricsListen        = "otel-metrics-listen"
	OtelMetricsListenAddress = "otel-metrics-listen-address"
)

// IsValidKey checks if the given key is a valid configuration key for the GadgetTracerManager.
// TODO: Remove in the future once we remove the flags from kubectl-gadget deploy.
func IsValidKey(key string) bool {
	return isRootKey(key) || isOciKey(key) || isOtelKey(key)
}

// FullKeyPath returns the full key path for the given key.
// TODO: Remove in the future once we remove the flags from kubectl-gadget deploy.
func FullKeyPath(key string) string {
	if isRootKey(key) {
		return key
	} else if isOciKey(key) {
		return "operator.oci." + key
	} else if isOtelKey(key) {
		return "operator.otel-metrics." + key
	}
	return ""
}

// TODO: Remove in the future once we remove the flags from kubectl-gadget deploy.
func isRootKey(key string) bool {
	switch key {
	case HookModeKey, FallbackPodInformerKey, EventsBufferLengthKey,
		ContainerdSocketPath, CrioSocketPath, DockerSocketPath,
		PodmanSocketPath, GadgetNamespace:
		return true
	default:
		return false
	}
}

// TODO: Remove in the future once we remove the flags from kubectl-gadget deploy.
func isOciKey(key string) bool {
	switch key {
	case VerifyImage, PublicKeys, AllowedGadgets, InsecureRegistries, DisallowPulling:
		return true
	default:
		return false
	}
}

// TODO: Remove in the future once we remove the flags from kubectl-gadget deploy.
func isOtelKey(key string) bool {
	switch key {
	case OtelMetricsListen, OtelMetricsListenAddress:
		return true
	default:
		return false
	}
}
