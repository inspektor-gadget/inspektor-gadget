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

package ocihandler

import (
	"bytes"
	"context"
	"testing"

	"github.com/blang/semver"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestCheckBuilderVersion(t *testing.T) {
	var logBuffer bytes.Buffer
	logrus.SetOutput(&logBuffer)
	logrus.SetLevel(logrus.DebugLevel)
	tests := []struct {
		currentVersion  string
		name            string
		annotationValue string
		expectedLogPart string
	}{
		{"v1.0.0", "Missing annotation warn", "", "Builder version not found in the gadget image. Gadget could be incompatible"},
		{"v1.0.0", "Invalid annotation debug", "invalid", "parsing builder version:"},
		{"v1.0.0", "Different version warn", "0.9.0", "This gadget was built with ig 0.9.0 and it's being run with v1.0.0. Gadget could be incompatible"},
		{"v1.0.0", "Matching version no log", "1.0.0", ""},
	}

	lg := logrus.StandardLogger()

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// version.Version = func() *semver.Version { return tc.currentVersion }
			logBuffer.Reset()
			mn := v1.Manifest{Annotations: map[string]string{}}
			mn.Annotations[builderVersionAnnotation] = tc.annotationValue
			cV, _ := semver.ParseTolerant(tc.currentVersion)
			checkBuilderVersion(&mn, lg, cV)

			loggedOutput := logBuffer.String()
			if tc.expectedLogPart == "" {
				assert.Empty(t, loggedOutput)
			} else {
				assert.Contains(t, loggedOutput, tc.expectedLogPart)
			}
		})
	}
}

func TestGetPullSecret(t *testing.T) {
	type testCase struct {
		name             string
		secretName       string
		secretNamespace  string
		secretType       corev1.SecretType
		secretDataKey    string
		secretContent    string
		expectError      bool
		expectedErrorMsg string
		expectedResult   string
	}

	tests := []testCase{
		{
			name:            "valid secret",
			secretName:      "pullSecret",
			secretNamespace: "default",
			secretType:      corev1.SecretTypeDockerConfigJson,
			secretDataKey:   corev1.DockerConfigJsonKey,
			secretContent:   "valid-content",
			expectError:     false,
			expectedResult:  "valid-content",
		},
		{
			name:             "secret not found",
			secretName:       "nonexistent",
			secretNamespace:  "default",
			expectError:      true,
			expectedErrorMsg: "getting secret \"nonexistent\"",
		},
		{
			name:             "wrong secret type",
			secretName:       "wrongType",
			secretNamespace:  "default",
			secretType:       corev1.SecretTypeOpaque,
			secretDataKey:    corev1.DockerConfigJsonKey,
			secretContent:    "data",
			expectError:      true,
			expectedErrorMsg: "secret \"wrongType\" is not of type \"kubernetes.io/dockerconfigjson\"",
		},
		{
			name:            "missing dockerconfigjson key",
			secretName:      "missingKey",
			secretNamespace: "default",
			secretType:      corev1.SecretTypeDockerConfigJson,
			secretDataKey:   "someOtherKey",
			secretContent:   "data",
			expectError:     false,
			expectedResult:  "",
		},
		{
			name:            "empty secret content",
			secretName:      "emptySecret",
			secretNamespace: "default",
			secretType:      corev1.SecretTypeDockerConfigJson,
			secretDataKey:   corev1.DockerConfigJsonKey,
			secretContent:   "",
			expectError:     false,
			expectedResult:  "",
		},
		{
			name:            "valid special characters",
			secretName:      "docker-pull",
			secretNamespace: "custom-ns",
			secretType:      corev1.SecretTypeDockerConfigJson,
			secretDataKey:   corev1.DockerConfigJsonKey,
			secretContent:   `$%{}!@#`,
			expectError:     false,
			expectedResult:  `$%{}!@#`,
		},
		{
			name:             "secret in different namespace",
			secretName:       "wrong-ns-secret",
			secretNamespace:  "wrong-ns",
			expectError:      true,
			expectedErrorMsg: "getting secret \"wrong-ns-secret\"",
		},
		{
			name:            "large content",
			secretName:      "largeSecret",
			secretNamespace: "default",
			secretType:      corev1.SecretTypeDockerConfigJson,
			secretDataKey:   corev1.DockerConfigJsonKey,
			secretContent:   string(make([]byte, 1000)),
			expectError:     false,
			expectedResult:  string(make([]byte, 1000)),
		},
		{
			name:            "nil data map",
			secretName:      "nilDataSecret",
			secretNamespace: "default",
			secretType:      corev1.SecretTypeDockerConfigJson,
			expectError:     false,
			expectedResult:  "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fcs := fake.NewSimpleClientset()

			if test.secretType != "" {
				secret := &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      test.secretName,
						Namespace: test.secretNamespace,
					},
					Type: test.secretType,
				}
				if test.secretDataKey != "" {
					secret.Data = map[string][]byte{
						test.secretDataKey: []byte(test.secretContent),
					}
				}
				_, err := fcs.CoreV1().Secrets(test.secretNamespace).Create(context.TODO(), secret, metav1.CreateOptions{})
				require.NoError(t, err, "setup: failed to create test secret")
			}

			result, err := getPullSecret(test.secretName, test.secretNamespace, fcs)

			if test.expectError {
				require.Error(t, err)
				require.Contains(t, err.Error(), test.expectedErrorMsg)
			} else {
				require.NoError(t, err)
				require.Equal(t, test.expectedResult, string(result))
			}
		})
	}
}

func TestConstructTempConfig(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantErr    bool
		wantConfig map[string]any
		wantLength int
	}{
		{
			name:    "Invalid no colon",
			input:   "invalidannotation",
			wantErr: true,
		},
		{
			name:    "Invalid no equal sign",
			input:   "source:invalidannotation",
			wantErr: true,
		},
		{
			name:    "Valid datasource annotation",
			input:   "source:foo=bar",
			wantErr: false,
			wantConfig: map[string]any{
				"datasources": map[string]any{
					"source": map[string]any{
						"annotations": map[string]any{
							"foo": "bar",
						},
					},
				},
			},
			wantLength: 1,
		},
		{
			name:    "Valid field annotation",
			input:   "source.field:foo=bar",
			wantErr: false,
			wantConfig: map[string]any{
				"datasources": map[string]any{
					"source": map[string]any{
						"fields": map[string]any{
							"field": map[string]any{
								"annotations": map[string]any{
									"foo": "bar",
								},
							},
						},
					},
				},
			},
			wantLength: 2,
		},
		// TODO: Shouldn't these be invalid?
		// {
		// 	name:    "Invalid multiple colons",
		// 	input:   "source:field:foo=bar",
		// 	wantErr: true,
		// },
		// {
		// 	name:    "Invalid multiple equal signs",
		// 	input:   "source:foo=bar=baz",
		// 	wantErr: true,
		// },
		// {
		// 	name:    "Invalid multiple dots",
		// 	input:   "source.field.foo:foo=bar",
		// 	wantErr: true,
		// },
		{
			name:    "Empty annotation key",
			input:   "source:=bar",
			wantErr: false,
			wantConfig: map[string]any{
				"datasources": map[string]any{
					"source": map[string]any{
						"annotations": map[string]any{
							"": "bar",
						},
					},
				},
			},
			wantLength: 1,
		},
		{
			name:    "Empty annotation value",
			input:   "source:foo=",
			wantErr: false,
			wantConfig: map[string]any{
				"datasources": map[string]any{
					"source": map[string]any{
						"annotations": map[string]any{
							"foo": "",
						},
					},
				},
			},
			wantLength: 1,
		},
		{
			name:    "Empty subject",
			input:   ":foo=bar",
			wantErr: false,
			wantConfig: map[string]any{
				"datasources": map[string]any{
					"": map[string]any{
						"annotations": map[string]any{
							"foo": "bar",
						},
					},
				},
			},
			wantLength: 1,
		},
		{
			name:    "Empty field name",
			input:   "source.:foo=bar",
			wantErr: false,
			wantConfig: map[string]any{
				"datasources": map[string]any{
					"source": map[string]any{
						"fields": map[string]any{
							"": map[string]any{
								"annotations": map[string]any{
									"foo": "bar",
								},
							},
						},
					},
				},
			},
			wantLength: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotConfig, err, gotLength := constructTempConfig(tt.input)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.wantConfig, gotConfig)
			require.Equal(t, tt.wantLength, gotLength)
		})
	}
}
