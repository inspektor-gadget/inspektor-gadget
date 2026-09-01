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

package oci

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/signature/puller"
)

const testImage = "ghcr.io/inspektor-gadget/gadget/trace_open:latest"

// errDetail stands in for the raw, multi-line error the pullers produce; none of
// it should reach the user-facing message.
var errDetail = errors.New(`pulling signing information with cosign: not found
pulling signing information with oci 1.1: not found
pulling signing information with bundle: no referrers found`)

func TestSignaturePullError(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		err          error
		wantContains []string
		wantHint     bool
	}{
		"not_found": {
			err:          fmt.Errorf("%w: %w", puller.ErrSignatureNotFound, errDetail),
			wantContains: []string{"no signature found for gadget", testImage},
			wantHint:     true,
		},
		"unreachable": {
			err:          fmt.Errorf("%w: %w", puller.ErrRegistryUnreachable, errDetail),
			wantContains: []string{"ghcr.io is unreachable", "air-gapped", testImage},
			wantHint:     true,
		},
		"unauthorized": {
			err:          fmt.Errorf("%w: %w", puller.ErrSignatureUnauthorized, errDetail),
			wantContains: []string{"not authorized", "Log in to ghcr.io", testImage},
			wantHint:     true,
		},
		"unclassified_keeps_detail": {
			err:          errDetail,
			wantContains: []string{"pulling gadget signature", "no referrers found"},
		},
	}

	for name, test := range tests {
		test := test
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ref, err := normalizeImageName(testImage)
			require.NoError(t, err)

			got := signaturePullError(ref, test.err).Error()

			for _, want := range test.wantContains {
				require.Contains(t, got, want)
			}

			if test.wantHint {
				require.Contains(t, got, "--verify-image=false")
				// The raw per-puller dump is what confuses users; it belongs
				// in the debug log, not in the message they are shown.
				require.NotContains(t, got, "pulling signing information with cosign")
			}
		})
	}
}

func TestSignaturePullWarning(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		err  error
		want string
	}{
		"not_found": {
			err:  fmt.Errorf("%w: %w", puller.ErrSignatureNotFound, errDetail),
			want: "no signature found for gadget " + testImage,
		},
		"unreachable": {
			err:  fmt.Errorf("%w: %w", puller.ErrRegistryUnreachable, errDetail),
			want: "fetching the signature for gadget " + testImage + ": ghcr.io is unreachable",
		},
		"unauthorized": {
			err:  fmt.Errorf("%w: %w", puller.ErrSignatureUnauthorized, errDetail),
			want: "not authorized to fetch the signature for gadget " + testImage,
		},
	}

	for name, test := range tests {
		test := test
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ref, err := normalizeImageName(testImage)
			require.NoError(t, err)

			got := signaturePullWarning(ref, test.err)

			require.Equal(t, test.want, got)
			// Pulling is not verifying, so the message must not tell the user
			// to turn verification off.
			require.NotContains(t, got, "--verify-image")
		})
	}
}
