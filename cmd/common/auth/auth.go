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

package auth

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/docker/cli/cli/config"
	"github.com/docker/cli/cli/config/configfile"
	dockertypes "github.com/docker/cli/cli/config/types"
	"github.com/spf13/pflag"
	"oras.land/oras-go/v2/registry/remote"
	oras_auth "oras.land/oras-go/v2/registry/remote/auth"
)

// LoginOptions holds all parameters for a Login call.
type LoginOptions struct {
	Username      string
	Password      string
	StdinPassword bool
	AuthFile      string
	TLSVerify     bool
	PlainHTTP     bool
	Stdin         io.Reader
	Stdout        io.Writer
}

// LogoutOptions holds all parameters for a Logout call.
type LogoutOptions struct {
	AuthFile string
	All      bool
	Stdout   io.Writer
}

// GetLoginFlags registers CLI flags on the returned FlagSet, binding to opts.
func GetLoginFlags(opts *LoginOptions) *pflag.FlagSet {
	fs := pflag.NewFlagSet("login", pflag.ContinueOnError)
	fs.StringVarP(&opts.Username, "username", "u", "", "Username for registry authentication")
	fs.StringVarP(&opts.Password, "password", "p", "", "Password for registry authentication")
	fs.BoolVar(&opts.StdinPassword, "password-stdin", false, "Read password from stdin")
	fs.StringVar(&opts.AuthFile, "authfile", "", "Path to the auth file")
	fs.BoolVar(&opts.TLSVerify, "tls-verify", true, "Verify TLS certificates")
	fs.BoolVar(&opts.PlainHTTP, "plain-http", false, "Use HTTP instead of HTTPS (for local registries)")
	return fs
}

// GetLogoutFlags registers CLI flags on the returned FlagSet, binding to opts.
func GetLogoutFlags(opts *LogoutOptions) *pflag.FlagSet {
	fs := pflag.NewFlagSet("logout", pflag.ContinueOnError)
	fs.StringVar(&opts.AuthFile, "authfile", "", "Path to the auth file")
	fs.BoolVarP(&opts.All, "all", "a", false, "Remove credentials for all registries")
	return fs
}

// Login authenticates against the given registry and persists the credentials.
func Login(ctx context.Context, opts *LoginOptions, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("login requires exactly one registry argument")
	}
	registry := args[0]

	if opts.Password != "" && opts.StdinPassword {
		return fmt.Errorf("--password and --password-stdin are mutually exclusive")
	}

	if opts.Password != "" {
		fmt.Fprintln(os.Stderr, "WARNING! Using --password via the CLI is insecure. Use --password-stdin.")
	}

	password := opts.Password
	if opts.StdinPassword {
		data, err := io.ReadAll(io.LimitReader(opts.Stdin, 100*1024))
		if err != nil {
			return fmt.Errorf("reading password from stdin: %w", err)
		}
		password = strings.TrimRight(string(data), "\n\r")
	}

	if opts.Username == "" || password == "" {
		return fmt.Errorf("username and password are required")
	}

	if err := checkAuth(ctx, registry, opts.Username, password, opts.TLSVerify, opts.PlainHTTP); err != nil {
		return err
	}

	cfg, err := loadConfigFile(opts.AuthFile)
	if err != nil {
		return err
	}

	creds := dockertypes.AuthConfig{
		Username:      opts.Username,
		Password:      password,
		ServerAddress: registry,
	}
	if err := cfg.GetCredentialsStore(registry).Store(creds); err != nil {
		return fmt.Errorf("storing credentials: %w", err)
	}
	if err := cfg.Save(); err != nil {
		return fmt.Errorf("saving auth config: %w", err)
	}

	fmt.Fprintf(opts.Stdout, "Login Succeeded\n")
	return nil
}

// Logout removes credentials for the given registry (or all registries).
func Logout(opts *LogoutOptions, args []string) error {
	if !opts.All && len(args) != 1 {
		return fmt.Errorf("logout requires exactly one registry argument (or --all)")
	}

	cfg, err := loadConfigFile(opts.AuthFile)
	if err != nil {
		return err
	}

	if opts.All {
		for registry := range cfg.GetAuthConfigs() {
			if err := cfg.GetCredentialsStore(registry).Erase(registry); err != nil {
				return fmt.Errorf("removing credentials for %s: %w", registry, err)
			}
		}
	} else {
		registry := args[0]
		if _, ok := cfg.GetAuthConfigs()[registry]; !ok {
			return fmt.Errorf("not logged in to %s", registry)
		}
		if err := cfg.GetCredentialsStore(registry).Erase(registry); err != nil {
			return fmt.Errorf("removing credentials for %s: %w", registry, err)
		}
	}

	if err := cfg.Save(); err != nil {
		return fmt.Errorf("saving auth config: %w", err)
	}

	fmt.Fprintf(opts.Stdout, "Logout Succeeded\n")
	return nil
}

// loadConfigFile loads a Docker-compatible config file from the given path.
// If authFile is empty, it falls back to the default Docker config directory.
func loadConfigFile(authFile string) (*configfile.ConfigFile, error) {
	if authFile == "" {
		cfg, err := config.Load("")
		if err != nil {
			return nil, fmt.Errorf("loading auth config: %w", err)
		}
		return cfg, nil
	}

	f, err := os.Open(authFile)
	if err != nil {
		if os.IsNotExist(err) {
			cfg := configfile.New(authFile)
			return cfg, nil
		}
		return nil, fmt.Errorf("opening auth file %q: %w", authFile, err)
	}
	defer f.Close()

	cfg, err := config.LoadFromReader(f)
	if err != nil {
		return nil, fmt.Errorf("loading auth config: %w", err)
	}
	cfg.Filename = authFile
	return cfg, nil
}

// checkAuth verifies credentials against the registry using the OCI
// distribution protocol. It handles both Basic and Bearer token auth flows.
func checkAuth(ctx context.Context, registryAddr, username, password string, tlsVerify, plainHTTP bool) error {
	reg, err := remote.NewRegistry(registryAddr)
	if err != nil {
		return fmt.Errorf("invalid registry address: %w", err)
	}

	reg.PlainHTTP = plainHTTP

	httpClient := &http.Client{Timeout: 30 * time.Second}
	if !tlsVerify {
		httpClient.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	reg.Client = &oras_auth.Client{
		Client: httpClient,
		Credential: oras_auth.StaticCredential(registryAddr, oras_auth.Credential{
			Username: username,
			Password: password,
		}),
	}

	if err := reg.Ping(ctx); err != nil {
		return fmt.Errorf("unauthorized: %w", err)
	}
	return nil
}
