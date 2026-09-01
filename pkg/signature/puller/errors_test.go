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

package puller

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
	"oras.land/oras-go/v2/errdef"
	"oras.land/oras-go/v2/registry/remote/auth"
	"oras.land/oras-go/v2/registry/remote/errcode"
)

func notFoundErr(tag string) error {
	return fmt.Errorf("pulling signing information with cosign: %s: %w", tag, errdef.ErrNotFound)
}

func statusErr(code int) error {
	u, _ := url.Parse("https://ghcr.io/v2/inspektor-gadget/gadget/trace_open/manifests/latest")
	return &errcode.ErrorResponse{Method: "GET", URL: u, StatusCode: code}
}

func dnsErr() error {
	return &url.Error{
		Op:  "Get",
		URL: "https://ghcr.io/v2/",
		Err: &net.DNSError{Err: "no such host", Name: "ghcr.io", IsNotFound: true},
	}
}

func refusedErr() error {
	return &url.Error{
		Op:  "Get",
		URL: "https://registry.local/v2/",
		Err: &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED},
	}
}

func TestClassify(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		errs []error
		want error
	}{
		"no_errors": {
			errs: nil,
			want: nil,
		},
		"all_not_found": {
			// The common case: the gadget is simply not signed, so each
			// puller gets a 404 (or finds no referrer) in turn.
			errs: []error{notFoundErr("sha256-abc.sig"), notFoundErr("sha256-abc"), notFoundErr("sha256-abc")},
			want: ErrSignatureNotFound,
		},
		"unauthorized": {
			errs: []error{statusErr(401), statusErr(401), statusErr(401)},
			want: ErrSignatureUnauthorized,
		},
		"denied": {
			errs: []error{statusErr(403)},
			want: ErrSignatureUnauthorized,
		},
		"missing_credentials": {
			errs: []error{fmt.Errorf("fetching token: %w", auth.ErrBasicCredentialNotFound)},
			want: ErrSignatureUnauthorized,
		},
		"dns_failure": {
			errs: []error{dnsErr(), dnsErr(), dnsErr()},
			want: ErrRegistryUnreachable,
		},
		"connection_refused": {
			errs: []error{refusedErr()},
			want: ErrRegistryUnreachable,
		},
		"unauthorized_wins_over_not_found": {
			// A 404 from one puller next to a 401 from another means the
			// registry is hiding the repository, not that it is unsigned.
			errs: []error{notFoundErr("sha256-abc.sig"), statusErr(401), notFoundErr("sha256-abc")},
			want: ErrSignatureUnauthorized,
		},
		"unauthorized_wins_over_unreachable": {
			errs: []error{dnsErr(), statusErr(403)},
			want: ErrSignatureUnauthorized,
		},
		"unreachable_wins_over_not_found": {
			errs: []error{notFoundErr("sha256-abc.sig"), dnsErr()},
			want: ErrRegistryUnreachable,
		},
		"unknown_error_is_not_classified": {
			// Anything we do not recognise must keep its original wording
			// instead of being mislabelled as a missing signature.
			errs: []error{notFoundErr("sha256-abc.sig"), errors.New("images with several referrers are not supported")},
			want: nil,
		},
		"server_error_is_not_classified": {
			errs: []error{statusErr(500)},
			want: nil,
		},
	}

	for name, test := range tests {
		test := test
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			err := classify(test.errs)

			if len(test.errs) == 0 {
				require.NoError(t, err)
				return
			}

			require.Error(t, err)

			if test.want != nil {
				require.ErrorIs(t, err, test.want)
			} else {
				for _, sentinel := range []error{ErrSignatureNotFound, ErrRegistryUnreachable, ErrSignatureUnauthorized} {
					require.NotErrorIs(t, err, sentinel)
				}
			}

			// Whatever the classification, the underlying errors must stay
			// reachable so they can still be logged at debug level.
			for _, e := range test.errs {
				require.ErrorIs(t, err, e)
			}
		})
	}
}
