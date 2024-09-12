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

package metadatav1

import (
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

const (
	DefaultColumnWidth = 16
)

type Alignment string

const (
	AlignmenNone   Alignment = ""
	AlignmentLeft  Alignment = "left"
	AlignmentRight Alignment = "right"
)

type EllipsisType string

const (
	EllipsisNone   EllipsisType = ""
	EllipsisStart  EllipsisType = "start"
	EllipsisMiddle EllipsisType = "middle"
	EllipsisEnd    EllipsisType = "end"
)

type Field struct {
	Annotations map[string]string `yaml:"annotations,omitempty"`
}

type DataSource struct {
	Annotations map[string]string `yaml:"annotations,omitempty"`
	Fields      map[string]Field  `yaml:"fields"`
}

type GadgetMetadata struct {
	// Gadget name
	Name string `yaml:"name"`
	// Gadget description
	Description string `yaml:"description,omitempty"`
	// HomepageURL is the URL to the gadget's homepage
	HomepageURL string `yaml:"homepageURL,omitempty"`
	// DocumentationURL is the URL to the gadget's documentation
	DocumentationURL string `yaml:"documentationURL,omitempty"`
	// SourceURL is the URL to the gadget's source code repository
	SourceURL string `yaml:"sourceURL,omitempty"`
	// Annotations is a map of key-value pairs that provide additional information about the gadget
	Annotations map[string]string `yaml:"annotations,omitempty"`
	// DataSources exposed by the gadget
	DataSources map[string]*DataSource `yaml:"datasources,omitempty"`
	// Params exposed by this gadget. It includes params for different operators
	Params map[string]map[string]params.ParamDesc `yaml:"params,omitempty"`
	// Other params exposed by the gadget
	GadgetParams map[string]params.ParamDesc `yaml:"gadgetParams,omitempty"`
}
