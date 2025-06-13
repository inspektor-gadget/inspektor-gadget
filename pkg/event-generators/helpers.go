// Copyright 2025 The Inspektor Gadget authors
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

package eventgenerators

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

const (
	ManifestDir = "/etc/kubernetes/manifests"
)

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func GenerateRandomPodName(namePrefix string) (string, error) {
	// Generate a random suffix for the pod name
	suffix, err := randomHex(3)
	if err != nil {
		return "", fmt.Errorf("could not generate pod name: %w", err)
	}
	return fmt.Sprintf("%s-%s", namePrefix, suffix), nil
}

func GenerateRandomContainerName(namePrefix string) (string, error) {
	// Generate a random suffix for the container name
	suffix, err := randomHex(3)
	if err != nil {
		return "", fmt.Errorf("could not generate container name: %w", err)
	}
	return fmt.Sprintf("%s-container-%s", namePrefix, suffix), nil
}

func VerifyManifestDir() error {
	fi, err := os.Stat(ManifestDir)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("manifest directory %s does not exist; are you on a Kubernetes node?", ManifestDir)
		}
		return fmt.Errorf("error checking %s: %w", ManifestDir, err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s exists but is not a directory", ManifestDir)
	}
	return nil
}

// FindDNSContainerID looks for the container ID of a given container name
func FindDNSContainerID(containerName string) (string, error) {
	out, err := exec.Command("crictl",
		"ps", "-a",
		"--name", containerName,
		"-o", "json",
	).Output()
	if err != nil {
		return "", fmt.Errorf("crictl ps failed: %w", err)
	}

	// The JSON looks like:
	// { "containers": [ { "id": "abcdef...", ... }, ... ] }
	var resp struct {
		Containers []struct {
			Id string `json:"id"`
		} `json:"containers"`
	}
	if err := json.Unmarshal(out, &resp); err != nil {
		return "", fmt.Errorf("failed to parse crictl ps JSON: %w", err)
	}
	if len(resp.Containers) == 0 {
		return "", fmt.Errorf("no container found for %q", containerName)
	}
	if len(resp.Containers) > 1 {
		return "", fmt.Errorf("multiple containers found for %q, expected only one", containerName)
	}
	return resp.Containers[0].Id, nil
}

// InspectAndFetchLogs inspects the given container to retrieve its exit code,
// then grabs its logs.  It returns (exitCode, logs, error).
func InspectAndFetchLogs(cid string) (int, string, error) {
	// Inspect the container status
	out, err := exec.Command("crictl",
		"inspect",
		"-o", "json",
		cid,
	).Output()
	if err != nil {
		return 0, "", fmt.Errorf("crictl inspect failed: %w", err)
	}

	// The JSON looks like:
	// { "status": { "exitCode": 0, ... }, ... }
	var insp struct {
		Status struct {
			ExitCode int `json:"exitCode"`
		} `json:"status"`
	}
	if err := json.Unmarshal(out, &insp); err != nil {
		return 0, "", fmt.Errorf("failed to parse inspect JSON: %w", err)
	}

	// Grab the container logs
	logBytes, logErr := exec.Command("crictl", "logs", cid).CombinedOutput()
	logs := strings.TrimSpace(string(logBytes))
	if logErr != nil {
		// If logs failed, include whatever we got plus the error
		return insp.Status.ExitCode, logs,
			fmt.Errorf("failed to fetch logs: %w; logs:\n%s", logErr, logs)
	}

	return insp.Status.ExitCode, logs, nil
}
