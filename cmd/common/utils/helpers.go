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

	"github.com/docker/cli/cli/config"
	"github.com/docker/cli/cli/config/configfile"
	"github.com/docker/distribution/reference"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"oras.land/oras-go/v2/content/oci"
	oras_auth "oras.land/oras-go/v2/registry/remote/auth"
)

type AuthOptions struct {
	AuthFile string
}

var (
	defaultOciStore = "/var/lib/ig/oci-store"
	DefaultAuthFile = "/var/lib/ig/config.json"
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

func GetHostString(repository string) (string, error) {
	repo, err := reference.Parse(repository)
	if err != nil {
		return "", fmt.Errorf("parse repository %q: %w", repository, err)
	}
	if named, ok := repo.(reference.Named); ok {
		return reference.Domain(named), nil
	}
	return "", fmt.Errorf("image has to be a named reference")
}

func SetupAuthVariablesAndFlags(cmd *cobra.Command, authOptions *AuthOptions) {
	// Flag inspired by https://github.com/containers/common/blob/cac40138f7e3c2b29ca32e64348535516bf6aa51/pkg/auth/cli.go#L48
	cmd.Flags().StringVar(&authOptions.AuthFile, "authfile", DefaultAuthFile,
		"path of the authentication file. This overrides the REGISTRY_AUTH_FILE environment variable")
	viper.BindPFlag("registry.auth_file", cmd.Flags().Lookup("authfile"))
	viper.BindEnv("registry.auth_file", "REGISTRY_AUTH_FILE")
}

func CreateAuthClient(repository string, authOptions *AuthOptions) (*oras_auth.Client, error) {
	logrus.Debugf("Using auth file %q", authOptions.AuthFile)

	var cfg *configfile.ConfigFile
	var err error

	// 1. Explicitly setting the auth file
	// 2. Using the default auth file
	// 3. Using the default docker auth file if 2. doesn't exist
	if authOptions.AuthFile != DefaultAuthFile {
		authFileReader, err := os.Open(authOptions.AuthFile)
		if err != nil {
			return nil, fmt.Errorf("open auth file %q: %w", authOptions.AuthFile, err)
		}
		defer authFileReader.Close()
		cfg, err = config.LoadFromReader(authFileReader)
		if err != nil {
			return nil, fmt.Errorf("load auth config: %w", err)
		}
	} else if _, err := os.Stat(authOptions.AuthFile); err == nil {
		authFileReader, err := os.Open(authOptions.AuthFile)
		if err != nil {
			return nil, fmt.Errorf("open auth file %q: %w", authOptions.AuthFile, err)
		}
		defer authFileReader.Close()
		cfg, err = config.LoadFromReader(authFileReader)
		if err != nil {
			return nil, fmt.Errorf("load auth config: %w", err)
		}
	} else {
		logrus.Debugf("Couldn't find default auth file %q...", authOptions.AuthFile)
		logrus.Debugf("Using default docker auth file instead")
		logrus.Debugf("$HOME: %q", os.Getenv("HOME"))

		cfg, err = config.Load("")
		if err != nil {
			return nil, fmt.Errorf("load auth config: %w", err)
		}
	}

	hostString, err := GetHostString(repository)
	if err != nil {
		return nil, fmt.Errorf("get host string: %w", err)
	}
	authConfig, err := cfg.GetAuthConfig(hostString)
	if err != nil {
		return nil, fmt.Errorf("get auth config: %w", err)
	}

	return &oras_auth.Client{
		Credential: oras_auth.StaticCredential(hostString, oras_auth.Credential{
			Username:    authConfig.Username,
			Password:    authConfig.Password,
			AccessToken: authConfig.Auth,
		}),
	}, nil
}
