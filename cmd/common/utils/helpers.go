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

package utils

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/docker/distribution/reference"
	"oras.land/oras-go/v2/content/oci"
)

var (
	defaultOciStore = "/var/lib/ig/oci-store"
)

func GetLocalOciStore() (*oci.Store, error) {
	if err := os.MkdirAll(filepath.Dir(defaultOciStore), 0o710); err != nil {
		return nil, err
	}
	return oci.New(defaultOciStore)
}

func GetTagFromImage(image string) (string, error) {
	repo, err := reference.Parse(image)
	if err != nil {
		return "", fmt.Errorf("parse image %q: %w", image, err)
	}
	tagged, ok := repo.(reference.Tagged)
	if !ok {
		return "latest", nil
	}
	return tagged.Tag(), nil
}

func GetRepositoryFromImage(image string) (string, error) {
	repo, err := reference.Parse(image)
	if err != nil {
		return "", fmt.Errorf("parse image %q: %w", image, err)
	}
	if named, ok := repo.(reference.Named); ok {
		return named.Name(), nil
	}
	return "", fmt.Errorf("image has to be a named reference")
}

func NormalizeImage(image string) (string, error) {
	name, err := reference.ParseNormalizedNamed(image)
	if err != nil {
		return "", fmt.Errorf("parse normalized image %q: %w", image, err)
	}
	return reference.TagNameOnly(name).String(), nil
}
