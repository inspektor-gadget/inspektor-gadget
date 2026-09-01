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
	"net/http"

	"oras.land/oras-go/v2/errdef"
	"oras.land/oras-go/v2/registry/remote/auth"
	"oras.land/oras-go/v2/registry/remote/errcode"
)

// Every puller fails on its own terms when there is nothing to pull, which
// makes the joined error unreadable. These sentinels let callers tell the
// three interesting situations apart and phrase an actionable message.
var (
	// ErrSignatureNotFound means the registry was reachable and readable, but
	// holds no signing information for the image: the gadget is not signed.
	ErrSignatureNotFound = errors.New("signature not found")

	// ErrRegistryUnreachable means the registry could not be contacted at all,
	// typically because the host is running air-gapped.
	ErrRegistryUnreachable = errors.New("registry unreachable")

	// ErrSignatureUnauthorized means the registry refused to serve the signing
	// information, typically because the repository is private and no
	// credentials were provided.
	ErrSignatureUnauthorized = errors.New("signature not accessible")
)

// classify turns the errors collected from the pullers into a single error
// tagged with the sentinel that best describes them. The original errors stay
// reachable through errors.Is and errors.As, so callers can still log the full
// detail at debug level. Errors we do not recognise are returned as they are
// rather than being forced into a category.
func classify(errs []error) error {
	joined := errors.Join(errs...)
	if joined == nil {
		return nil
	}

	// Unauthorized is checked first, and unreachable before not found: a 404
	// from one puller next to a 401 from another means the registry is hiding
	// the repository, not that the image is unsigned.
	switch {
	case anyIs(errs, isUnauthorized):
		return fmt.Errorf("%w: %w", ErrSignatureUnauthorized, joined)
	case anyIs(errs, isUnreachable):
		return fmt.Errorf("%w: %w", ErrRegistryUnreachable, joined)
	case allAre(errs, isNotFound):
		return fmt.Errorf("%w: %w", ErrSignatureNotFound, joined)
	}

	return joined
}

func anyIs(errs []error, pred func(error) bool) bool {
	for _, err := range errs {
		if pred(err) {
			return true
		}
	}
	return false
}

func allAre(errs []error, pred func(error) bool) bool {
	for _, err := range errs {
		if !pred(err) {
			return false
		}
	}
	return true
}

func isNotFound(err error) bool {
	return errors.Is(err, errdef.ErrNotFound)
}

func isUnauthorized(err error) bool {
	if errors.Is(err, auth.ErrBasicCredentialNotFound) {
		return true
	}

	var resp *errcode.ErrorResponse
	if !errors.As(err, &resp) {
		return false
	}

	return resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden
}

func isUnreachable(err error) bool {
	// An error response, however unhelpful, still proves we reached the
	// registry, so it must never be reported as a connectivity problem.
	var resp *errcode.ErrorResponse
	if errors.As(err, &resp) {
		return false
	}

	var netErr net.Error
	return errors.As(err, &netErr)
}
