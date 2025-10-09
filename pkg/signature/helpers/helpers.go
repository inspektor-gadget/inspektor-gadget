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

package helpers

import (
	"context"
	"fmt"
	"strings"

	"oras.land/oras-go/v2"
)

func GetImageDigest(ctx context.Context, store oras.Target, imageRef string) (string, error) {
	desc, err := store.Resolve(ctx, imageRef)
	if err != nil {
		return "", fmt.Errorf("resolving image %q: %w", imageRef, err)
	}

	return desc.Digest.String(), nil
}
