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

package image

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/run/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/metrics"
)

func NewHelpersCmd() *cobra.Command {
	opts := &cmdOpts{}
	var metricsHelperFileName string

	cmd := &cobra.Command{
		Use:          "generate-helpers PATH",
		Short:        "Generates helper files from metadata",
		SilenceUsage: true,
		Args:         cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// TODO: re-use from build.go
			fFlag := cmd.Flags().Lookup("file")
			opts.fileChanged = fFlag.Changed

			opts.path = args[0]
			return runHelpers(opts, metricsHelperFileName)
		},
	}

	cmd.Flags().StringVarP(&opts.file, "file", "f", "build.yaml", "Path to build.yaml")
	cmd.Flags().StringVarP(&metricsHelperFileName, "metrics-filename", "", "metrics.h", "filename for metrics helper")

	return cmd
}

func runHelpers(opts *cmdOpts, metricsHelperFileName string) error {
	conf := &buildFile{
		EBPFSource: DEFAULT_EBPF_SOURCE,
		Metadata:   DEFAULT_METADATA,
	}

	var buildContent []byte
	var err error

	if opts.fileChanged {
		buildContent, err = os.ReadFile(opts.file)
		if err != nil {
			return fmt.Errorf("reading build file: %w", err)
		}
	} else {
		// The user specified the path but not the file. Use the default file build.yaml
		buildContent, err = os.ReadFile(filepath.Join(opts.path, opts.file))
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("reading build file: %w", err)
		}
	}

	if err := yaml.Unmarshal(buildContent, conf); err != nil {
		return fmt.Errorf("unmarshaling build.yaml: %w", err)
	}

	// TODO: merge with build.go
	if opts.path != "." {
		cwd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("getting current directory: %w", err)
		}
		defer os.Chdir(cwd)

		if err := os.Chdir(opts.path); err != nil {
			return fmt.Errorf("changing directory: %w", err)
		}
	}

	// Parse metadata
	metadataContent, err := os.ReadFile(conf.Metadata)
	if err != nil {
		return fmt.Errorf("reading metadata file: %w", err)
	}

	var metdata types.GadgetMetadata
	if err := yaml.Unmarshal(metadataContent, &metdata); err != nil {
		return fmt.Errorf("unmarshaling metadata file: %w", err)
	}

	f, err := os.OpenFile(metricsHelperFileName, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0o755)
	if err != nil {
		return fmt.Errorf("creating %q: %w", metricsHelperFileName, err)
	}
	defer f.Close()

	err = metrics.RenderMetricsHeader(metdata.Metrics, f)
	if err != nil {
		return fmt.Errorf("rendering metrics: %w", err)
	}

	return nil
}
