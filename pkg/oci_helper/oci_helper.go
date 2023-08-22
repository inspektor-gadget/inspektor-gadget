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

package oci_helper

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"

	"github.com/docker/cli/cli/config"
	"github.com/docker/cli/cli/config/configfile"
	"github.com/docker/distribution/reference"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/memory"
	"oras.land/oras-go/v2/content/oci"
	"oras.land/oras-go/v2/errdef"
	"oras.land/oras-go/v2/registry/remote"
	oras_auth "oras.land/oras-go/v2/registry/remote/auth"
)

type AuthOptions struct {
	AuthFile string
	Insecure bool
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

func GetMemoryStore() *memory.Store {
	return memory.New()
}

func PullIfNotExist(imageStore oras.Target, authOpts *AuthOptions, image string) error {
	_, err := imageStore.Resolve(context.TODO(), image)
	if err == nil {
		return nil
	}
	if err != errdef.ErrNotFound {
		return fmt.Errorf("resolve image %q: %v", image, err)
	}

	repo, err := CreateRemoteRepository(image, authOpts)
	if err != nil {
		return fmt.Errorf("create remote repository: %w", err)
	}
	_, err = oras.Copy(context.TODO(), repo, image, imageStore, image, oras.DefaultCopyOptions)
	if err != nil {
		return fmt.Errorf("download to local repository: %w", err)
	}
	return nil
}

func GetImageListDescriptor(imageStore oras.ReadOnlyTarget, image string) (ocispec.Index, error) {
	imageListDescriptor, err := imageStore.Resolve(context.TODO(), image)
	if err != nil {
		return ocispec.Index{}, fmt.Errorf("resolve image %q: %w", image, err)
	}
	if imageListDescriptor.MediaType != ocispec.MediaTypeImageIndex {
		return ocispec.Index{}, fmt.Errorf("image %q is not an image index", image)
	}

	reader, err := imageStore.Fetch(context.Background(), imageListDescriptor)
	if err != nil {
		return ocispec.Index{}, fmt.Errorf("fetch image index: %w", err)
	}
	defer reader.Close()
	bytes, err := io.ReadAll(reader)
	if err != nil {
		return ocispec.Index{}, fmt.Errorf("read image index: %w", err)
	}
	var index ocispec.Index
	err = json.Unmarshal(bytes, &index)
	if err != nil {
		return ocispec.Index{}, fmt.Errorf("unmarshal image index: %w", err)
	}
	return index, nil
}

func GetHostArchManifest(imageStore oras.ReadOnlyTarget, index ocispec.Index) (ocispec.Manifest, error) {
	var manifestDesc ocispec.Descriptor
	for _, indexManifest := range index.Manifests {
		// TODO: Check docker code
		if indexManifest.Platform.Architecture == runtime.GOARCH {
			manifestDesc = indexManifest
			break
		}
	}
	if manifestDesc.Digest == "" {
		return ocispec.Manifest{}, fmt.Errorf("no manifest found for architecture %q", runtime.GOARCH)
	}

	reader, err := imageStore.Fetch(context.Background(), manifestDesc)
	if err != nil {
		return ocispec.Manifest{}, fmt.Errorf("fetch manifest: %w", err)
	}
	defer reader.Close()
	bytes, err := io.ReadAll(reader)
	if err != nil {
		return ocispec.Manifest{}, fmt.Errorf("read manifest: %w", err)
	}
	var manifest ocispec.Manifest
	err = json.Unmarshal(bytes, &manifest)
	if err != nil {
		return ocispec.Manifest{}, fmt.Errorf("unmarshal manifest: %w", err)
	}
	return manifest, nil
}

func GetContentFromDescriptor(imageStore oras.ReadOnlyTarget, desc ocispec.Descriptor) ([]byte, error) {
	reader, err := imageStore.Fetch(context.Background(), desc)
	if err != nil {
		return nil, fmt.Errorf("fetch descriptor: %w", err)
	}
	defer reader.Close()
	bytes, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("read descriptor: %w", err)
	}
	return bytes, nil
}

func GetDefinition(target oras.Target, authOpts *AuthOptions, image string) ([]byte, error) {
	err := PullIfNotExist(target, authOpts, image)
	if err != nil {
		return nil, fmt.Errorf("pull image: %w", err)
	}
	index, err := GetImageListDescriptor(target, image)
	if err != nil {
		return nil, fmt.Errorf("get image list descriptor: %w", err)
	}
	manifest, err := GetHostArchManifest(target, index)
	if err != nil {
		return nil, fmt.Errorf("get arch manifest: %w", err)
	}
	definition, err := GetContentFromDescriptor(target, manifest.Config)
	if err != nil {
		return nil, fmt.Errorf("get definition from descriptor: %w", err)
	}

	return definition, nil
}

func GetEbpfProgram(target oras.Target, authOpts *AuthOptions, image string) ([]byte, error) {
	err := PullIfNotExist(target, authOpts, image)
	if err != nil {
		return nil, fmt.Errorf("pull image: %w", err)
	}
	index, err := GetImageListDescriptor(target, image)
	if err != nil {
		return nil, fmt.Errorf("get image list descriptor: %w", err)
	}
	manifest, err := GetHostArchManifest(target, index)
	if err != nil {
		return nil, fmt.Errorf("get arch manifest: %w", err)
	}
	if len(manifest.Layers) != 1 {
		return nil, fmt.Errorf("expected exactly one layer, got %d", len(manifest.Layers))
	}
	definition, err := GetContentFromDescriptor(target, manifest.Layers[0])
	if err != nil {
		return nil, fmt.Errorf("get ebpf program from descriptor: %w", err)
	}

	return definition, nil
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

	cmd.Flags().BoolVar(&authOptions.Insecure, "insecure", false, "allow connections to HTTP only registries")
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

func CreateRemoteRepository(image string, authOpts *AuthOptions) (*remote.Repository, error) {
	repository, err := GetRepositoryFromImage(image)
	if err != nil {
		return nil, fmt.Errorf("get repository from image %q: %w", image, err)
	}
	repo, err := remote.NewRepository(repository)
	if err != nil {
		return nil, fmt.Errorf("create remote repository: %w", err)
	}
	repo.PlainHTTP = authOpts.Insecure
	if !authOpts.Insecure {
		client, err := CreateAuthClient(repository, authOpts)
		if err != nil {
			return nil, fmt.Errorf("create auth client: %w", err)
		}
		repo.Client = client
	}

	return repo, nil
}
