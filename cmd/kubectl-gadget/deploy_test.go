// Copyright 2019-2021 The Inspektor Gadget authors
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

package main

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"

	"github.com/inspektor-gadget/inspektor-gadget/cmd/common"
	grpcruntime "github.com/inspektor-gadget/inspektor-gadget/pkg/runtime/grpc"
)

func TestPrintOnly(t *testing.T) {
	grpcRuntime = grpcruntime.New(grpcruntime.WithConnectUsingK8SProxy)
	runtimeGlobalParams = grpcRuntime.GlobalParamDescs().ToParams()

	cmd := rootCmd
	common.AddFlags(cmd, runtimeGlobalParams, nil, grpcRuntime)
	cmd.SetArgs([]string{"deploy", "--print-only"})

	var stdErr bytes.Buffer
	cmd.SetErr(&stdErr)
	cmd.Execute()
	if stdErr.Len() != 0 {
		t.Fatalf("Error while running command: %s", stdErr.String())
	}
}

func TestApplyConfigToConfgMap(t *testing.T) {
	// Helper to create a ConfigMap with config.yaml data
	makeCM := func(yaml string) *v1.ConfigMap {
		return &v1.ConfigMap{
			Data: map[string]string{
				"config.yaml": yaml,
			},
		}
	}

	tmpFileWith := func(content string) (string, func()) {
		f, err := os.CreateTemp("", "ig-config-*.yaml")
		if err != nil {
			t.Fatalf("failed to create temp file: %v", err)
		}
		if _, err := f.WriteString(content); err != nil {
			t.Fatalf("failed to write temp file: %v", err)
		}
		return f.Name(), func() { os.Remove(f.Name()) }
	}

	tests := []struct {
		name          string
		cm            *v1.ConfigMap
		configContent string
		setConfig     []string
		flagSetup     func(*pflag.FlagSet)
		wantContains  []string
		wantErr       bool
	}{
		{
			name:         "default configmap only",
			cm:           makeCM("operator:\n  oci:\n    disallow-pulling: false\n"),
			flagSetup:    func(fs *pflag.FlagSet) {},
			wantContains: []string{"disallow-pulling: false"},
		},
		{
			name:         "set-config overrides configmap",
			cm:           makeCM("operator:\n  oci:\n    disallow-pulling: false\n"),
			setConfig:    []string{"operator.oci.disallow-pulling=true"},
			flagSetup:    func(fs *pflag.FlagSet) {},
			wantContains: []string{"disallow-pulling: true"},
		},
		{
			name:          "config file overrides configmap",
			cm:            makeCM("operator:\n  oci:\n    disallow-pulling: false\n"),
			configContent: "operator:\n  oci:\n    disallow-pulling: true\n",
			flagSetup:     func(fs *pflag.FlagSet) {},
			wantContains:  []string{"disallow-pulling: true"},
		},
		{
			name: "flag overrides configmap",
			cm:   makeCM("operator:\n  oci:\n    disallow-pulling: false\n"),
			flagSetup: func(fs *pflag.FlagSet) {
				fs.Set("disallow-gadgets-pulling", "true")
			},
			wantContains: []string{"disallow-pulling: true"},
		},
		{
			name:          "set-config overrides config file",
			cm:            makeCM("operator:\n  oci:\n    disallow-pulling: false\n"),
			setConfig:     []string{"operator.oci.disallow-pulling=true"},
			configContent: "operator:\n  oci:\n    disallow-pulling: false\n",
			flagSetup:     func(fs *pflag.FlagSet) {},
			wantContains:  []string{"disallow-pulling: true"},
		},
		{
			name:      "flag overrides set-config",
			cm:        makeCM("operator:\n  oci:\n    disallow-pulling: false\n"),
			setConfig: []string{"operator.oci.disallow-pulling=false"},
			flagSetup: func(fs *pflag.FlagSet) {
				fs.Set("disallow-gadgets-pulling", "true")
			},
			wantContains: []string{"disallow-pulling: true"},
		},
		{
			name:          "Merge configmap, set-config, and config file",
			cm:            makeCM("operator:\n  oci:\n    disallow-pulling: false\n"),
			setConfig:     []string{"operator.oci.verify-image=true"},
			configContent: "operator:\n  oci:\n    insecure-registries: registry.example.com\n",
			wantContains:  []string{"disallow-pulling: false", "verify-image: \"true\"", "insecure-registries: registry.example.com"},
		},
		{
			name:      "invalid set-config format",
			cm:        makeCM("operator:\n  oci:\n    disallow-pulling: false\n"),
			setConfig: []string{"badformat"},
			flagSetup: func(fs *pflag.FlagSet) {},
			wantErr:   true,
		},
		{
			name:      "missing config.yaml",
			cm:        &v1.ConfigMap{Data: map[string]string{}},
			flagSetup: func(fs *pflag.FlagSet) {},
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
			fs.Bool("disallow-gadgets-pulling", false, "")

			if tt.flagSetup != nil {
				tt.flagSetup(fs)
			}

			// Patch global setDaemonConfig for this test
			oldSetConfig := setDaemonConfig
			setDaemonConfig = tt.setConfig
			defer func() { setDaemonConfig = oldSetConfig }()

			// if configContent is provided, create a temp file
			var configPath string
			if tt.configContent != "" {
				var cleanup func()
				configPath, cleanup = tmpFileWith(tt.configContent)
				defer cleanup()
				fs.String("config", configPath, "Path to the configuration file")
			} else {
				fs.String("config", "", "Path to the configuration file")
			}

			err := applyConfigToConfigMap(tt.cm, configPath, fs)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			got := tt.cm.Data["config.yaml"]
			for _, want := range tt.wantContains {
				if !strings.Contains(got, want) {
					t.Errorf("config.yaml does not contain %q, got:\n%s", want, got)
				}
			}
		})
	}
}
