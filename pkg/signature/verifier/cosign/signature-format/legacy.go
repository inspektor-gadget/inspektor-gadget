// Copyright 2025 The Inspektor Gadget authors
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

package signatureformat

import (
	"context"

	"oras.land/oras-go/v2"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/signature/helpers"
)

type LegacyFormat struct{}

func (*LegacyFormat) CheckPayloadImage(payloadBytes []byte, imageDigest string) error {
	return checkPayloadImage(payloadBytes, imageDigest)
}

func (*LegacyFormat) CraftSigningInfoTag(imageDigest string) (string, error) {
	return helpers.CraftCosignSignatureTag(imageDigest)
}

func (*LegacyFormat) FindSignatureTag(_ context.Context, _ oras.GraphTarget, signingInfoTag string) (string, error) {
	return signingInfoTag, nil
}

func (*LegacyFormat) LoadSignatureAndPayload(ctx context.Context, imageStore oras.GraphTarget, signatureTag string) ([]byte, []byte, []byte, error) {
	return loadSignatureAndPayload(ctx, imageStore, signatureTag)
}

func (*LegacyFormat) Name() string {
	return "legacy"
}
