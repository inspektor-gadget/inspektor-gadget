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

import (
	"fmt"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/config"
)

const ConfigPath = "/etc/ig/config.yaml"

const (
	EventsBufferLengthKey = "events-buffer-length"
	ContainerdSocketPath  = "containerd-socketpath"
	CrioSocketPath        = "crio-socketpath"
	DockerSocketPath      = "docker-socketpath"
	PodmanSocketPath      = "podman-socketpath"
	GadgetNamespace       = "gadget-namespace"
	DaemonLogLevel        = "daemon-log-level"
)

func Init() error {
	config.Config = config.NewWithPath(ConfigPath)

	config.Config.SetDefault(EventsBufferLengthKey, 16384)
	config.Config.SetDefault(DaemonLogLevel, "info")

	err := config.Config.ReadInConfig()
	if err != nil {
		return fmt.Errorf("reading config: %w", err)
	}
	return nil
}
