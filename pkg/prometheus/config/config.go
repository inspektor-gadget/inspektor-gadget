// Copyright 2023 The Inspektor Gadget authors
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

package config

import (
	"errors"
	"fmt"

	"gopkg.in/yaml.v3"
)

type Metric struct {
	Name     string   `yaml:"name"`
	Category string   `yaml:"category"`
	Gadget   string   `yaml:"gadget"`
	Type     string   `yaml:"type"`
	Field    string   `yaml:"field,omitempty"`
	Labels   []string `yaml:"labels,omitempty"`
	Selector []string `yaml:"selector,omitempty"`
	Bucket   Bucket   `yaml:"bucket,omitempty"`
}

type Config struct {
	MetricsName string   `yaml:"metrics_name"`
	Metrics     []Metric `yaml:"metrics"`
}

type Bucket struct {
	Unit       string  `yaml:"unit"`
	Type       string  `yaml:"type"`
	Min        int     `yaml:"min"`
	Max        int     `yaml:"max"`
	Multiplier float64 `yaml:"multiplier"`
}

func ParseConfig(configBytes []byte) (*Config, error) {
	config := &Config{}
	if err := yaml.Unmarshal(configBytes, config); err != nil {
		return nil, err
	}

	if config.MetricsName == "" {
		return nil, errors.New("metrics_name is missing")
	}

	if config.Metrics == nil {
		return nil, errors.New("metrics section is missing")
	}

	for _, metric := range config.Metrics {
		if metric.Name == "" {
			return nil, errors.New("metric name is missing")
		}

		if metric.Category == "" {
			return nil, fmt.Errorf("metric category is missing in %q", metric.Name)
		}

		if metric.Gadget == "" {
			return nil, fmt.Errorf("metric gadget is missing in %q", metric.Name)
		}

		if metric.Type == "" {
			return nil, fmt.Errorf("metric type is missing in %q", metric.Name)
		}
	}

	return config, nil
}
