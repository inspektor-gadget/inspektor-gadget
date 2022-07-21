// Copyright 2022 The Inspektor Gadget authors
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

package utils

import (
	"errors"
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"
)

const (
	OutputModeColumns       = "columns"
	OutputModeJSON          = "json"
	OutputModeCustomColumns = "custom-columns"
)

var SupportedOutputModes = []string{OutputModeColumns, OutputModeJSON, OutputModeCustomColumns}

// OutputConfig contains the flags that describes how to print the gadget's output
type OutputConfig struct {
	// OutputMode specifies the format output should be printed
	OutputMode string

	// List of columns to print (only meaningful when OutputMode is "columns=...")
	CustomColumns []string

	// Verbose prints additional information
	Verbose bool
}

func (config *OutputConfig) ParseOutputConfig() error {
	if config.Verbose {
		log.StandardLogger().SetLevel(log.DebugLevel)
	}

	switch {
	case config.OutputMode == OutputModeColumns:
		fallthrough
	case config.OutputMode == OutputModeJSON:
		return nil
	case strings.HasPrefix(config.OutputMode, OutputModeCustomColumns):
		parts := strings.Split(config.OutputMode, "=")
		if len(parts) != 2 {
			return WrapInErrInvalidArg(OutputModeCustomColumns,
				errors.New("expects a comma separated list of columns to use"))
		}

		cols := strings.Split(strings.ToLower(parts[1]), ",")
		for _, col := range cols {
			if len(col) == 0 {
				return WrapInErrInvalidArg(OutputModeCustomColumns,
					errors.New("column can't be empty"))
			}
		}

		config.CustomColumns = cols
		config.OutputMode = OutputModeCustomColumns
		return nil
	default:
		return WrapInErrInvalidArg("--output / -o",
			fmt.Errorf("%q is not a valid output format", config.OutputMode))
	}
}
