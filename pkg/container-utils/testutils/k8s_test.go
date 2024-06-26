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

package testutils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCreatePodYaml(t *testing.T) {
	type testCases struct {
		testName string
		// expected is an array of strings because the order of maps is not guaranteed
		expected  []string
		podName   string
		imageName string
		namespace string
		cmd       string
		args      string
		limits    map[string]string
	}

	tests := []testCases{
		{
			testName: "Simple",
			expected: []string{`apiVersion: v1
kind: Pod
metadata:
  name: foo
  namespace: ns
  labels:
    run: foo
spec:
  restartPolicy: Never
  terminationGracePeriodSeconds: 0
  containers:
  - name: foo
    image: foo-image
`},
			podName:   "foo",
			imageName: "foo-image",
			namespace: "ns",
			cmd:       "",
			args:      "",
			limits:    nil,
		},
		{
			testName: "WithCmd",
			expected: []string{`apiVersion: v1
kind: Pod
metadata:
  name: foo
  namespace: ns
  labels:
    run: foo
spec:
  restartPolicy: Never
  terminationGracePeriodSeconds: 0
  containers:
  - name: foo
    image: foo-image
    command: MyCmd
`},
			podName:   "foo",
			imageName: "foo-image",
			namespace: "ns",
			cmd:       "MyCmd",
			args:      "",
			limits:    nil,
		},
		{
			testName: "WithCmdAndArgs",
			expected: []string{`apiVersion: v1
kind: Pod
metadata:
  name: foo
  namespace: ns
  labels:
    run: foo
spec:
  restartPolicy: Never
  terminationGracePeriodSeconds: 0
  containers:
  - name: foo
    image: foo-image
    command: MyCmd
    args:
    - arg arg2
`},
			podName:   "foo",
			imageName: "foo-image",
			namespace: "ns",
			cmd:       "MyCmd",
			args:      "arg arg2",
			limits:    nil,
		},
		{
			testName: "WithLimits",
			expected: []string{
				`apiVersion: v1
kind: Pod
metadata:
  name: foo
  namespace: ns
  labels:
    run: foo
spec:
  restartPolicy: Never
  terminationGracePeriodSeconds: 0
  containers:
  - name: foo
    image: foo-image
    resources:
      limits:
        cpu: "1"
        memory: "2Gi"
`,
				`apiVersion: v1
kind: Pod
metadata:
  name: foo
  namespace: ns
  labels:
    run: foo
spec:
  restartPolicy: Never
  terminationGracePeriodSeconds: 0
  containers:
  - name: foo
    image: foo-image
    resources:
      limits:
        memory: "2Gi"
        cpu: "1"
`,
			},
			podName:   "foo",
			imageName: "foo-image",
			namespace: "ns",
			cmd:       "",
			args:      "",
			limits: map[string]string{
				"cpu":    "1",
				"memory": "2Gi",
			},
		},
		{
			testName: "WithCmdAndArgsAndLimits",
			expected: []string{
				`apiVersion: v1
kind: Pod
metadata:
  name: foo
  namespace: ns
  labels:
    run: foo
spec:
  restartPolicy: Never
  terminationGracePeriodSeconds: 0
  containers:
  - name: foo
    image: foo-image
    command: MyCmd
    args:
    - arg arg2
    resources:
      limits:
        cpu: "1"
        memory: "2Gi"
`,
				`apiVersion: v1
kind: Pod
metadata:
  name: foo
  namespace: ns
  labels:
    run: foo
spec:
  restartPolicy: Never
  terminationGracePeriodSeconds: 0
  containers:
  - name: foo
    image: foo-image
    command: MyCmd
    args:
    - arg arg2
    resources:
      limits:
        memory: "2Gi"
        cpu: "1"
`,
			},
			podName:   "foo",
			imageName: "foo-image",
			namespace: "ns",
			cmd:       "MyCmd",
			args:      "arg arg2",
			limits: map[string]string{
				"cpu":    "1",
				"memory": "2Gi",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			actual := createPodYaml(tc.podName, tc.imageName, tc.namespace, tc.cmd, tc.args, tc.limits)
			foundEqual := false
			for _, e := range tc.expected {
				if e == actual {
					foundEqual = true
					break
				}
			}

			if !foundEqual {
				// Compare again just to have a better error message
				assert.Equal(t, tc.expected[0], actual, "No matching expected yaml equals actual yaml")
			}
		})
	}
}
