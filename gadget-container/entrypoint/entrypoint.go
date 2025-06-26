// Copyright 2019-2023 The Inspektor Gadget authors
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

package entrypoint

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/oci"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
)

const gadgetPullSecretPath = "/var/run/secrets/gadget/pull-secret/config.json"

func getPrettyName() (string, error) {
	path := filepath.Join(host.HostRoot, "/etc/os-release")
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("opening file %s: %w", path, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		if parts[0] == "PRETTY_NAME" {
			return strings.Trim(parts[1], "\""), nil
		}
	}

	err = scanner.Err()
	if err != nil {
		return "", fmt.Errorf("reading file %s: %w", path, err)
	}

	return "", fmt.Errorf("%s does not contain PRETTY_NAME", path)
}

func getKernelRelease() (string, error) {
	uts := &unix.Utsname{}
	if err := unix.Uname(uts); err != nil {
		return "", fmt.Errorf("calling uname: %w", err)
	}

	return unix.ByteSliceToString(uts.Release[:]), nil
}

func hasGadgetPullSecret() bool {
	_, err := os.Stat(gadgetPullSecretPath)
	return err == nil
}

func prepareGadgetPullSecret() error {
	log.Info("Preparing gadget pull secret")

	err := os.MkdirAll("/var/lib/ig", 0o755)
	if err != nil {
		return fmt.Errorf("creating /var/lib/ig: %w", err)
	}

	err = os.Symlink(gadgetPullSecretPath, oci.DefaultAuthFile)
	if err != nil {
		return fmt.Errorf("creating symlink %s: %w", oci.DefaultAuthFile, err)
	}

	return nil
}

func Init() error {
	if _, err := os.Stat(filepath.Join(host.HostRoot, "/bin")); os.IsNotExist(err) {
		return fmt.Errorf("%s must be executed in a pod with access to the host via %s", os.Args[0], host.HostRoot)
	}

	prettyName, err := getPrettyName()
	if err != nil {
		log.Warnf("os-release information not available. Some features could not work")
	}

	log.Infof("OS detected: %s", prettyName)

	kernelRelease, err := getKernelRelease()
	if err != nil {
		return fmt.Errorf("getting kernel release: %w", err)
	}

	log.Infof("Kernel detected: %s", kernelRelease)

	log.Infof("Gadget Image: %s", os.Getenv("GADGET_IMAGE"))

	if hasGadgetPullSecret() {
		err = prepareGadgetPullSecret()
		if err != nil {
			return fmt.Errorf("preparing gadget pull secret: %w", err)
		}
	}

	log.Info("Starting the Gadget Tracer Manager...")

	err = os.Chdir("/")
	if err != nil {
		return fmt.Errorf("changing directory: %w", err)
	}

	os.Remove("/run/gadgetservice.socket")

	return nil
}
