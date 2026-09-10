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

package image

import (
	"context"
	"fmt"

	"github.com/dustin/go-humanize"
	"github.com/spf13/cobra"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/oci"
)

func NewPruneCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "prune",
		Short: "Remove unused gadget images from the local store",
		Long: `Remove the manifests no gadget image refers to any more, and the blobs
they were the last users of. Pulling or building a gadget supersedes the
previous version of it, whose manifest is kept in the local store, so a store
that is used for a long time accumulates content nothing can reach.

Tagged images are never removed, nor are their signatures: use "ig image
remove" to delete an image.

Run this while no other ig process is using the store: the blobs of a gadget
another process is pulling right now may not be reachable from the store index
yet.`,
		SilenceUsage: true,
		Args:         cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			result, err := oci.PruneGadgetImages(context.TODO())
			if err != nil {
				return fmt.Errorf("pruning gadget images: %w", err)
			}

			cmd.Printf("Removed %d unreferenced manifests and %d blobs\n",
				result.IndexEntriesRemoved, result.BlobsRemoved)
			cmd.Printf("Total reclaimed space: %s\n", humanize.Bytes(uint64(result.BytesFreed)))

			return nil
		},
	}

	return cmd
}
