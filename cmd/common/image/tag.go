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

package image

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/oci_helper"
)

type tagOptions struct {
	srcImage string
	dstImage string
}

func NewTagCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "tag SRC_IMAGE DST_IMAGE",
		Short:        "Tag the local SRC_IMAGE image with the DST_IMAGE",
		SilenceUsage: true,
		RunE:         runTag,
	}

	return cmd
}

func runTag(cmd *cobra.Command, args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("expected exactly two arguments")
	}

	o := &tagOptions{
		srcImage: args[0],
		dstImage: args[1],
	}

	src, err := oci_helper.NormalizeImage(o.srcImage)
	if err != nil {
		return fmt.Errorf("normalize src image: %w", err)
	}
	dst, err := oci_helper.NormalizeImage(o.dstImage)
	if err != nil {
		return fmt.Errorf("normalize dst image: %w", err)
	}

	ociStore, err := oci_helper.GetLocalOciStore()
	if err != nil {
		return fmt.Errorf("get oci store: %w", err)
	}

	targetDescriptor, err := ociStore.Resolve(context.TODO(), src)
	if err != nil {
		// Error message not that helpful
		return fmt.Errorf("resolve srcTag: %w", err)
	}
	ociStore.Tag(context.TODO(), targetDescriptor, dst)

	fmt.Printf("Successfully tagged with %s@%s\n", dst, targetDescriptor.Digest)
	return nil
}
