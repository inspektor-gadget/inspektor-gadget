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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoginWritesCredentials(t *testing.T) {
	const validUser = "testuser"
	const validPass = "testpass"
	srv := newFakeRegistry(t, validUser, validPass)
	defer srv.Close()

	authFile := filepath.Join(t.TempDir(), "config.json")

	opts := &LoginOptions{
		Username:  validUser,
		Password:  validPass,
		AuthFile:  authFile,
		PlainHTTP: true,
		Stdout:    &bytes.Buffer{},
	}

	err := Login(context.Background(), opts, []string{registryHost(srv)})
	require.NoError(t, err)

	data, err := os.ReadFile(authFile)
	require.NoError(t, err)

	var cfg configJSON
	err = json.Unmarshal(data, &cfg)
	require.NoError(t, err)

	_, ok := cfg.Auths[registryHost(srv)]
	assert.True(t, ok, "expected registry %q in auth file, got keys: %v", registryHost(srv), keys(cfg.Auths))
}

func TestLoginFailsWithBadCredentials(t *testing.T) {
	srv := newFakeRegistry(t, "gooduser", "goodpass")
	defer srv.Close()

	authFile := filepath.Join(t.TempDir(), "config.json")

	opts := &LoginOptions{
		Username:  "baduser",
		Password:  "badpass",
		AuthFile:  authFile,
		PlainHTTP: true,
		Stdout:    &bytes.Buffer{},
	}

	err := Login(context.Background(), opts, []string{registryHost(srv)})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unauthorized")

	_, statErr := os.Stat(authFile)
	assert.True(t, os.IsNotExist(statErr), "auth file should not be created on failed login")
}

func TestLoginRequiresExactlyOneRegistry(t *testing.T) {
	authFile := filepath.Join(t.TempDir(), "config.json")

	opts := &LoginOptions{
		Username:  "u",
		Password:  "p",
		AuthFile:  authFile,
		PlainHTTP: true,
		Stdout:    &bytes.Buffer{},
	}

	err := Login(context.Background(), opts, nil)
	require.Error(t, err)

	err = Login(context.Background(), opts, []string{"a", "b"})
	require.Error(t, err)
}

func TestLoginRejectsPasswordAndStdinTogether(t *testing.T) {
	opts := &LoginOptions{
		Username:      "u",
		Password:      "p",
		StdinPassword: true,
		AuthFile:      filepath.Join(t.TempDir(), "config.json"),
		PlainHTTP:     true,
		Stdin:         strings.NewReader("p"),
		Stdout:        &bytes.Buffer{},
	}
	err := Login(context.Background(), opts, []string{"registry.example.com"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mutually exclusive")
}

func TestLoginRejectsEmptyCredentials(t *testing.T) {
	opts := &LoginOptions{
		AuthFile:  filepath.Join(t.TempDir(), "config.json"),
		PlainHTTP: true,
		Stdout:    &bytes.Buffer{},
	}

	err := Login(context.Background(), opts, []string{"registry.example.com"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "username and password are required")
}

func TestLoginPasswordStdin(t *testing.T) {
	const validUser = "stdinuser"
	const validPass = "stdinpass"
	srv := newFakeRegistry(t, validUser, validPass)
	defer srv.Close()

	authFile := filepath.Join(t.TempDir(), "config.json")

	opts := &LoginOptions{
		Username:      validUser,
		StdinPassword: true,
		AuthFile:      authFile,
		PlainHTTP:     true,
		Stdin:         strings.NewReader(validPass),
		Stdout:        &bytes.Buffer{},
	}

	err := Login(context.Background(), opts, []string{registryHost(srv)})
	require.NoError(t, err)

	data, err := os.ReadFile(authFile)
	require.NoError(t, err)
	assert.Contains(t, string(data), registryHost(srv))
}

func TestLogout(t *testing.T) {
	srv := newFakeRegistry(t, "user", "pass")
	defer srv.Close()

	authFile := filepath.Join(t.TempDir(), "config.json")

	loginOpts := &LoginOptions{
		Username:  "user",
		Password:  "pass",
		AuthFile:  authFile,
		PlainHTTP: true,
		Stdout:    &bytes.Buffer{},
	}
	err := Login(context.Background(), loginOpts, []string{registryHost(srv)})
	require.NoError(t, err)

	logoutOpts := &LogoutOptions{
		AuthFile: authFile,
		Stdout:   &bytes.Buffer{},
	}
	err = Logout(logoutOpts, []string{registryHost(srv)})
	require.NoError(t, err)

	data, err := os.ReadFile(authFile)
	require.NoError(t, err)

	var cfg configJSON
	err = json.Unmarshal(data, &cfg)
	require.NoError(t, err)

	_, ok := cfg.Auths[registryHost(srv)]
	assert.False(t, ok, "expected registry %q to be removed from auth file", registryHost(srv))
}

func TestLogoutAll(t *testing.T) {
	srv1 := newFakeRegistry(t, "user1", "pass1")
	defer srv1.Close()
	srv2 := newFakeRegistry(t, "user2", "pass2")
	defer srv2.Close()

	authFile := filepath.Join(t.TempDir(), "config.json")

	for _, tc := range []struct {
		srv  *httptest.Server
		user string
		pass string
	}{
		{srv1, "user1", "pass1"},
		{srv2, "user2", "pass2"},
	} {
		err := Login(context.Background(), &LoginOptions{
			Username:  tc.user,
			Password:  tc.pass,
			AuthFile:  authFile,
			PlainHTTP: true,
			Stdout:    &bytes.Buffer{},
		}, []string{registryHost(tc.srv)})
		require.NoError(t, err)
	}

	err := Logout(&LogoutOptions{
		AuthFile: authFile,
		All:      true,
		Stdout:   &bytes.Buffer{},
	}, nil)
	require.NoError(t, err)

	data, err := os.ReadFile(authFile)
	require.NoError(t, err)

	var cfg configJSON
	err = json.Unmarshal(data, &cfg)
	require.NoError(t, err)
	assert.Empty(t, cfg.Auths, "expected all auths to be removed")
}

func TestLogoutRequiresExactlyOneRegistry(t *testing.T) {
	authFile := filepath.Join(t.TempDir(), "config.json")
	opts := &LogoutOptions{AuthFile: authFile, Stdout: &bytes.Buffer{}}

	err := Logout(opts, nil)
	require.Error(t, err)

	err = Logout(opts, []string{"a", "b"})
	require.Error(t, err)
}

func TestLogoutNotLoggedIn(t *testing.T) {
	authFile := filepath.Join(t.TempDir(), "config.json")
	require.NoError(t, os.WriteFile(authFile, []byte(`{"auths":{}}`), 0o600))

	opts := &LogoutOptions{
		AuthFile: authFile,
		Stdout:   &bytes.Buffer{},
	}
	err := Logout(opts, []string{"registry.example.com"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not logged in")
}

func TestGetLoginFlags(t *testing.T) {
	opts := &LoginOptions{}
	fs := GetLoginFlags(opts)

	require.NoError(t, fs.Parse([]string{
		"--username", "myuser",
		"--password", "mypass",
		"--authfile", "/tmp/auth.json",
		"--tls-verify=false",
		"--plain-http",
	}))
	assert.Equal(t, "myuser", opts.Username)
	assert.Equal(t, "mypass", opts.Password)
	assert.Equal(t, "/tmp/auth.json", opts.AuthFile)
	assert.False(t, opts.TLSVerify)
	assert.True(t, opts.PlainHTTP)
}

func TestGetLogoutFlags(t *testing.T) {
	opts := &LogoutOptions{}
	fs := GetLogoutFlags(opts)

	require.NoError(t, fs.Parse([]string{
		"--authfile", "/tmp/auth.json",
		"--all",
	}))
	assert.Equal(t, "/tmp/auth.json", opts.AuthFile)
	assert.True(t, opts.All)
}

// configJSON is a minimal representation of a Docker config.json for test assertions.
type configJSON struct {
	Auths map[string]json.RawMessage `json:"auths"`
}

func keys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func newFakeRegistry(t *testing.T, validUser, validPass string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/v2/", func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != validUser || pass != validPass {
			w.Header().Set("WWW-Authenticate", `Basic realm="test"`)
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprintln(w, `{"errors":[{"code":"UNAUTHORIZED","message":"unauthorized"}]}`)
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, `{}`)
	})
	return httptest.NewServer(mux)
}

func registryHost(srv *httptest.Server) string {
	return strings.TrimPrefix(srv.URL, "http://")
}
