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

package deployinfo

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime"
)

type DeployInfo struct {
	Catalog *runtime.Catalog
}

func getFilename() (string, error) {
	homedir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("getting home dir: %w", err)
	}
	configFile := filepath.Join(homedir, ".ig", "info.json")
	return configFile, nil
}

func Load() (*DeployInfo, error) {
	infoFile, err := getFilename()
	if err != nil {
		return nil, fmt.Errorf("getting info filename: %w", err)
	}

	f, err := os.Open(infoFile)
	if err != nil {
		return nil, fmt.Errorf("opening info file: %w", err)
	}

	info := &DeployInfo{}

	dec := json.NewDecoder(f)
	err = dec.Decode(&info)
	if err != nil {
		return nil, fmt.Errorf("reading info: %w", err)
	}

	return info, err
}

func Store(info *DeployInfo) error {
	infoFile, err := getFilename()
	if err != nil {
		return fmt.Errorf("getting info filename: %w", err)
	}
	err = os.MkdirAll(filepath.Dir(infoFile), 0o750)
	if err != nil && errors.Is(err, os.ErrExist) {
		return fmt.Errorf("creating config dir: %w", err)
	}
	infoJSON, err := json.Marshal(info)
	if err != nil {
		return fmt.Errorf("marshaling info JSON: %w", err)
	}
	err = os.WriteFile(infoFile, infoJSON, 0o600)
	if err != nil {
		return fmt.Errorf("writing info file: %w", err)
	}
	return nil
}
