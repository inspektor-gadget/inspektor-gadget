// Copyright 2026 The Inspektor Gadget authors
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

// Package catalog contains the types and helpers used to expose a server-side
// curated list ("catalog") of gadgets to clients for discovery purposes.
package catalog

import (
	"fmt"

	"github.com/spf13/viper"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/config/gadgettracermanagerconfig"
)

// Entry represents a single gadget in the catalog. It is populated from the
// server-side configuration (the `catalog` key in config.yaml) and returned to
// clients for discovery.
type Entry struct {
	// Gadget is the short name / image reference of the gadget (e.g. trace_open).
	Gadget string `mapstructure:"gadget" yaml:"gadget"`

	// Description is a short description of what the gadget does.
	Description string `mapstructure:"description" yaml:"description"`

	// Tags can hold multiple opaque strings so that users can more easily find
	// gadgets in the catalog.
	Tags []string `mapstructure:"tags" yaml:"tags"`
}

// FromConfig reads the catalog entries from the given viper configuration. It
// returns an empty slice (and no error) when no catalog is configured, since
// the catalog is purely additive and optional.
func FromConfig(cfg *viper.Viper) ([]Entry, error) {
	if cfg == nil || !cfg.IsSet(gadgettracermanagerconfig.Catalog) {
		return nil, nil
	}

	var entries []Entry
	if err := cfg.UnmarshalKey(gadgettracermanagerconfig.Catalog, &entries); err != nil {
		return nil, fmt.Errorf("unmarshalling %q: %w", gadgettracermanagerconfig.Catalog, err)
	}
	return entries, nil
}
