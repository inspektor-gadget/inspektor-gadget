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
	"oras.land/oras-go/v2"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/oci_helper"
)

type pushOptions struct {
	image    string
	authOpts oci_helper.AuthOptions
}

func NewPushCmd() *cobra.Command {
	o := pushOptions{}
	cmd := &cobra.Command{
		Use:          "push IMAGE",
		Short:        "Push the specified image to a remote registry",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return fmt.Errorf("expected exactly one argument")
			}
			o.image = args[0]
			return runPush(o)
		},
	}
	oci_helper.SetupAuthVariablesAndFlags(cmd, &o.authOpts)
	return cmd
}

func runPush(o pushOptions) error {
	ociStore, err := oci_helper.GetLocalOciStore()
	if err != nil {
		return fmt.Errorf("get oci store: %w", err)
	}

	repo, err := oci_helper.CreateRemoteRepository(o.image, &o.authOpts)
	if err != nil {
		return fmt.Errorf("create remote repository: %w", err)
	}
	targetImage, err := oci_helper.NormalizeImage(o.image)
	if err != nil {
		return fmt.Errorf("normalize image: %w", err)
	}
	fmt.Printf("Pushing %s...\n", targetImage)
	desc, err := oras.Copy(context.TODO(), ociStore, targetImage, repo, targetImage, oras.DefaultCopyOptions)
	if err != nil {
		return fmt.Errorf("copy to remote repository: %w", err)
	}

	fmt.Printf("Successfully pushed %s@%s\n", targetImage, desc.Digest)
	return nil
}
