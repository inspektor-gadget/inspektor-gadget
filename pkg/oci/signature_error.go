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

	"github.com/distribution/reference"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/signature/puller"
)

const skipVerificationHint = "If the gadget is not signed and you are sure you want to skip signature " +
	"verification, run or deploy Inspektor Gadget with --verify-image=false"

// signaturePullError turns the error returned by the signature puller into a
// message a user can act on. The three cases below look identical in the raw
// output of the pullers, but call for very different fixes. Anything we cannot
// classify keeps its original wording so no detail is lost.
//
// The caller is expected to log err at debug level: the returned error
// deliberately drops the per-puller detail.
func signaturePullError(imageRef reference.Named, err error) error {
	image := imageRef.String()

	switch {
	case errors.Is(err, puller.ErrSignatureNotFound):
		return fmt.Errorf("no signature found for gadget %s\n%s", image, skipVerificationHint)
	case errors.Is(err, puller.ErrRegistryUnreachable):
		return fmt.Errorf("fetching the signature for gadget %s: %s is unreachable\n"+
			"If you are running air-gapped, pull the gadget while online, as its signature is pulled along with it. "+
			"Otherwise, run or deploy Inspektor Gadget with --verify-image=false",
			image, reference.Domain(imageRef))
	case errors.Is(err, puller.ErrSignatureUnauthorized):
		return fmt.Errorf("not authorized to fetch the signature for gadget %s\n"+
			"Log in to %s, or run or deploy Inspektor Gadget with --verify-image=false",
			image, reference.Domain(imageRef))
	}

	return fmt.Errorf("pulling gadget signature %q: %w", image, err)
}

// signaturePullWarning is the non-fatal counterpart of signaturePullError, used
// while pulling an image. Verification is not being asked for here, so the
// message states what happened without suggesting how to bypass anything.
func signaturePullWarning(imageRef reference.Named, err error) string {
	image := imageRef.String()

	switch {
	case errors.Is(err, puller.ErrSignatureNotFound):
		return fmt.Sprintf("no signature found for gadget %s", image)
	case errors.Is(err, puller.ErrRegistryUnreachable):
		return fmt.Sprintf("fetching the signature for gadget %s: %s is unreachable",
			image, reference.Domain(imageRef))
	case errors.Is(err, puller.ErrSignatureUnauthorized):
		return fmt.Sprintf("not authorized to fetch the signature for gadget %s", image)
	}

	return fmt.Sprintf("error pulling signature for gadget %s: %v", image, err)
}
