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

// Package version stores the semver of this binary. It is filled out by the Makefile at build time
// by using "-ldflags github.com/inspektor-gadget/inspektor-gadget/internal/version.version".
package version

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"time"

	"github.com/blang/semver"
)

// When used in the Inspektor Gadget project, version is filled out by the
// Makefile at build-time using:
// -ldflags "-X github.com/inspektor-gadget/inspektor-gadget/internal/version.version=${VERSION}"
var (
	version       = "v0.0.0"
	parsedVersion semver.Version

	userAgent = ""
)

func init() {
	thirdParty := false
	if version == "v0.0.0" {
		// If Inspektor Gadget is used as a library, its version will
		// be in ReadBuildInfo
		if info, ok := debug.ReadBuildInfo(); ok {
			for _, dep := range info.Deps {
				if dep.Path != "github.com/inspektor-gadget/inspektor-gadget" {
					continue
				}
				thirdParty = true
				if dep.Replace == nil {
					version = dep.Version
				} else {
					version = dep.Replace.Version
				}
				break
			}
		}
	}

	parsedVersion, _ = semver.ParseTolerant(version)

	kubernetesVersion, mainVersion := getVersions()
	userAgent = buildUserAgent(thirdParty, kubernetesVersion, mainVersion)
}

func getVersions() (kubernetesVersion string, mainVersion string) {
	kubernetesVersion = "unknown"
	mainVersion = "unknown"

	info, ok := debug.ReadBuildInfo()
	if !ok {
		return kubernetesVersion, mainVersion
	}

	mainVersion = info.Main.Version
	for _, dep := range info.Deps {
		if dep.Path != "k8s.io/client-go" {
			continue
		}

		if dep.Replace == nil {
			kubernetesVersion = dep.Version
		} else {
			kubernetesVersion = dep.Replace.Version
		}
		break
	}
	// Avoid parenthesis such as "(devel)" when compiled without vcs info
	mainVersion = strings.Trim(mainVersion, "()")

	return kubernetesVersion, mainVersion
}

func getCommand() string {
	command := os.Args[0]
	if command == "" {
		command = "unknown"
	}
	return filepath.Base(command)
}

// buildUserAgent builds the user agent similarly to
// https://github.com/kubernetes/client-go/blob/v0.33.0/rest/config.go#L524
// but with correct IG versioning. User agent should be in the format:
// https://www.rfc-editor.org/rfc/rfc9110#name-user-agent
func buildUserAgent(thirdParty bool, kubernetesVersion string, mainVersion string) string {
	if thirdParty {
		// Other software using IG Golang packages
		return fmt.Sprintf("%s/%s (%s/%s) ig/%s kubernetes/%s",
			getCommand(), mainVersion,
			runtime.GOOS, runtime.GOARCH,
			version,
			kubernetesVersion)
	}
	// Executable from the main inspektor-gadget repository.
	// No need to give version twice.
	return fmt.Sprintf("%s/%s (%s/%s) kubernetes/%s",
		getCommand(), version,
		runtime.GOOS, runtime.GOARCH,
		kubernetesVersion)
}

func Version() semver.Version {
	return parsedVersion
}

func VersionString() string {
	return version
}

// BuildInfo contains version information
type BuildInfo struct {
	Major         string `json:"major,omitempty"`
	Minor         string `json:"minor,omitempty"`
	Version       string `json:"version"`
	GitCommit     string `json:"gitCommit"`
	GitTreeState  string `json:"gitTreeState"`
	BuildDate     string `json:"buildDate"`
	GoVersion     string `json:"goVersion"`
	Compiler      string `json:"compiler"`
	Platform      string `json:"platform"`
}

// GetBuildInfo returns detailed build information
func GetBuildInfo() *BuildInfo {
	info := &BuildInfo{
		Version:       version,
		GoVersion:     runtime.Version(),
		Compiler:      runtime.Compiler,
		Platform:      fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
		GitTreeState:  "clean",
		BuildDate:     time.Now().UTC().Format(time.RFC3339),
	}

	// Parse version into major.minor
	if v, err := semver.ParseTolerant(version); err == nil {
		info.Major = fmt.Sprintf("%d", v.Major)
		info.Minor = fmt.Sprintf("%d", v.Minor)

		// If there's a pre-release or metadata, it might contain the git commit
		if len(v.Pre) > 0 {
			info.GitCommit = v.Pre[0].VersionStr
		}
	}

	return info
}

func UserAgent() string {
	return userAgent
}
