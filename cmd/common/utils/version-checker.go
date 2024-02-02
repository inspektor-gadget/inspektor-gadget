// Copyright 2024 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package utils

import (
	"fmt"

	"github.com/blang/semver"
	log "github.com/sirupsen/logrus"

	"github.com/inspektor-gadget/inspektor-gadget/internal/version"
)

func CheckServerVersionSkew(serverVersion string) error {
	clientSemver := version.Version()

	// Do not print any warning if this is a prerelease to avoid annoying developers
	if len(clientSemver.Pre) > 0 {
		return nil
	}

	serverSemver, err := semver.ParseTolerant(serverVersion)
	if err != nil {
		log.Debugf("parsing server version: %s", err)
		return nil
	}

	if !serverSemver.EQ(clientSemver) {
		return fmt.Errorf("version skew detected: client (v%s) vs server (v%s)", clientSemver, serverSemver)
	}

	return nil
}
