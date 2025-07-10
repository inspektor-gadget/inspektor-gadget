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

package benchmarks

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

var benchmark = flag.Bool("benchmark", false, "run benchmark tests")

type BenchmarkConfig struct {
	Ntimes       string                `yaml:"ntimes"`
	OutputFolder string                `yaml:"output_folder"`
	IgPath       string                `yaml:"ig_path"`
	IgFlags      []string              `yaml:"ig_flags"`
	IgRuntime    string                `yaml:"ig_runtime"`
	GadgetTag    string                `yaml:"gadget_tag"`
	Tests        map[string]TestConfig `yaml:"tests"`
}

type TestConfig struct {
	Server          *ServerConfig   `yaml:"server,omitempty"`
	Generator       GeneratorConfig `yaml:"generator"`
	EventsPerSecond []int           `yaml:"eventsPerSecond"`
}

type ServerConfig struct {
	Image string `yaml:"image"`
	Cmd   string `yaml:"cmd"`
}

type GeneratorConfig struct {
	Image      string `yaml:"image"`
	Entrypoint string `yaml:"entrypoint"`
}

func TestMain(m *testing.M) {
	flag.Parse()

	if !*benchmark {
		fmt.Println("Skipping benchmark tests")
		os.Exit(0)
	}

	fmt.Println("Running benchmark tests")
	os.Exit(m.Run())
}

func TestBenchmarks(t *testing.T) {
	configData, err := os.ReadFile("benchmarks.yaml")
	if err != nil {
		t.Fatalf("failed to read benchmarks.yaml: %v", err)
	}

	var config BenchmarkConfig
	if err := yaml.Unmarshal(configData, &config); err != nil {
		t.Fatalf("failed to parse benchmarks.yaml: %v", err)
	}

	// set up the environment for benchmarks
	if err = os.Setenv("IG_PATH", config.IgPath); err != nil {
		t.Fatalf("failed to set IG_PATH: %v", err)
	}
	if err = os.Setenv("IG_FLAGS", strings.Join(config.IgFlags, " ")); err != nil {
		t.Fatalf("failed to set IG_FLAGS: %v", err)
	}
	if err = os.Setenv("IG_RUNTIME", config.IgRuntime); err != nil {
		t.Fatalf("failed to set IG_RUNTIME: %v", err)
	}
	if err = os.Setenv("IG_N_RUNS", config.Ntimes); err != nil {
		t.Fatalf("failed to set IG_N_RUNS: %v", err)
	}
	if err = os.Setenv("IG_OUTPUT_FOLDER", config.OutputFolder); err != nil {
		t.Fatalf("failed to set IG_OUTPUT_FOLDER: %v", err)
	}
	if err = os.Setenv("GADGET_TAG", config.GadgetTag); err != nil {
		t.Fatalf("failed to set GADGET_TAG: %v", err)
	}

	// create the output folder if it doesn't exist
	if config.OutputFolder != "" {
		if err := os.MkdirAll(config.OutputFolder, 0755); err != nil {
			t.Fatalf("failed to create output folder %s: %v", config.OutputFolder, err)
		}
	}

	for gadgetName, testConfig := range config.Tests {
		t.Run(gadgetName, func(t *testing.T) {
			for _, eventsPerSecond := range testConfig.EventsPerSecond {
				t.Run(fmt.Sprintf("%d_eps", eventsPerSecond), func(t *testing.T) {
					c := &GadgetBenchTest{
						Gadget:         gadgetName,
						GeneratorImage: testConfig.Generator.Image,
						TestConfs:      []any{eventsPerSecond},
						GeneratorCmd: func(serverIP string, a any) string {
							cmd := testConfig.Generator.Entrypoint
							// Replace placeholders with actual values
							cmd = strings.ReplaceAll(cmd, "{serverIP}", serverIP)
							cmd = strings.ReplaceAll(cmd, "{eventsPerSecond}", fmt.Sprintf("%d", a))
							return cmd
						},
					}

					if testConfig.Server != nil {
						c.ServerCmd = func(rps any) string {
							return testConfig.Server.Cmd
						}
						c.ServerImage = testConfig.Server.Image
					}

					RunGadgetBenchmark(t, c)
				})
			}
		})
	}
}
