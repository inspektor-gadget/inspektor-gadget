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
	"runtime"
	"github.com/blang/semver"
)

// version is filled out by the Makefile at build
var (
	version       = "v0.0.0"
	parsedVersion semver.Version
)

func init() {
	parsedVersion, _ = semver.ParseTolerant(version)
}

func Version() semver.Version {
	return parsedVersion
}

func GetMajorMinorVersion() (string, string) {
    return fmt.Sprintf("%d", parsedVersion.Major), 
           fmt.Sprintf("%d", parsedVersion.Minor)
}

func GetVersionDetails() map[string]string {
    return map[string]string{
        "gitVersion": version,
        "goVersion": runtime.Version(),
        "compiler":  runtime.Compiler,
        "platform":  fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
    }
}