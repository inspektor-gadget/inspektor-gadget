// Copyright 2025 The Inspektor Gadget authors
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
package version_test

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/inspektor-gadget/inspektor-gadget/internal/version"
)

func TestVersion(t *testing.T) {
	// Example of version when running unit tests:
	// v0.0.0
	v := version.VersionString()
	assert.NotEqual(t, v, "")
	assert.NotContains(t, v, "unknown")
	assert.Regexp(t, regexp.MustCompile(`^v\d+\.\d+\.\d+`), v)
}

func TestUserAgent(t *testing.T) {
	// Example of user agent when running unit tests:
	// version.test/v0.0.0 (linux/amd64) kubernetes/unknown
	ua := version.UserAgent()
	assert.NotEqual(t, ua, "")
	assert.Regexp(t, regexp.MustCompile(`[\w.-]+/v\d+\.\d+\.\d+[\w-]* \(\w+/\w+\) kubernetes/[\w.-]+`), ua)
}
