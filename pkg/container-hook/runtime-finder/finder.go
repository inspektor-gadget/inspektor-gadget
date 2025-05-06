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

package finder

import (
	"errors"
	"fmt"
	"os"
	"strings"

	securejoin "github.com/cyphar/filepath-securejoin"
	"github.com/s3rj1k/go-fanotify/fanotify"
	"golang.org/x/sys/unix"
)

// RuntimePaths is the list of paths where the container runtime runc or crun
// could be installed. Depending on the Linux distribution, it could be in
// different locations.
//
// When this package is executed in a container, it prepends the HOST_ROOT env
// variable to the path.
var RuntimePaths = []string{
	"/bin/runc",
	"/usr/bin/runc",
	"/usr/sbin/runc",
	"/usr/local/bin/runc",
	"/usr/local/sbin/runc",
	"/usr/lib/cri-o-runc/sbin/runc",
	"/run/torcx/unpack/docker/bin/runc", // Used in Flatcar Container Linux
	"/usr/bin/crun",
	"/var/lib/rancher/k3s/data/current/bin/runc", // Used in k3s
	"/var/lib/rancher/rke2/bin/runc",             // Used in RKE2
	"/usr/libexec/crio/runc",                     // Used in kubeadm on Debian, upstream crio
	"/var/lib/k0s/bin/runc",                      // Used in k0s
}

// Notify marks the runtime path given as argument if it exists.
// The host root is prepend is not already present in runtime path.
// If prepend runtime path is a symbolic link, it will be resolved.
// The resulting runtime path is then marked using the corresponding NotifyFD.
func Notify(runtimePath string, hostRoot string, notifyFD *fanotify.NotifyFD) (string, error) {
	path := runtimePath
	var err error

	// Check if we have to prepend the host root to the runtime path
	if !strings.HasPrefix(runtimePath, hostRoot) {
		// SecureJoin will resolve symlinks according to the host root
		path, err = securejoin.SecureJoin(hostRoot, path)
		if err != nil {
			return "", fmt.Errorf("securejoining of %s: %w", path, err)
		}
	}

	if _, err = os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return "", err
	}

	if err = notifyFD.Mark(unix.FAN_MARK_ADD, unix.FAN_OPEN_EXEC_PERM, unix.AT_FDCWD, path); err != nil {
		return "", fmt.Errorf("marking of %s: %w", path, err)
	}

	return path, nil
}
