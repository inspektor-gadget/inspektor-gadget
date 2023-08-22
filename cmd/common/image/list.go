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
	"os"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns/formatter/textcolumns"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/oci_helper"
)

type listOptions struct {
	noTrunc bool
}

func NewListCmd() *cobra.Command {
	o := listOptions{}
	cmd := &cobra.Command{
		Use:          "list",
		Short:        "List gadget images in the host",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runList(o)
		},
	}

	cmd.Flags().BoolVar(&o.noTrunc, "no-trunc", false, "Don't truncate output")

	return cmd
}

func runList(o listOptions) error {
	ociStore, err := oci_helper.GetLocalOciStore()
	if err != nil {
		return fmt.Errorf("get oci store: %w", err)
	}

	type imageColumn struct {
		Repository string `column:"repository"`
		Tag        string `column:"tag"`
		Digest     string `column:"digest,width:12,fixed"`
	}

	imageColumns := []*imageColumn{}
	err = ociStore.Tags(context.TODO(), "", func(tags []string) error {
		for _, fullTag := range tags {
			repository, err := oci_helper.GetRepositoryFromImage(fullTag)
			if err != nil {
				logrus.Debugf("get repository from image %q: %s", fullTag, err)
				continue
			}
			tag, err := oci_helper.GetTagFromImage(fullTag)
			if err != nil {
				logrus.Debugf("get tag from image %q: %s", fullTag, err)
				continue
			}
			imageColumn := imageColumn{
				Repository: repository,
				Tag:        tag,
			}

			desc, err := ociStore.Resolve(context.TODO(), fullTag)
			if err != nil {
				logrus.Debugf("Found tag %q but couldn't get a descriptor for it: %v", fullTag, err)
				continue
			}
			imageColumn.Digest = desc.Digest.String()
			imageColumns = append(imageColumns, &imageColumn)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("listing all tags: %w", err)
	}

	cols := columns.MustCreateColumns[imageColumn]()
	if !o.noTrunc {
		cols.MustSetExtractor("digest", func(i *imageColumn) string {
			if i.Digest == "" {
				return ""
			}
			// Return the shortened digest and remove the sha256: prefix
			return strings.TrimPrefix(i.Digest, "sha256:")[:12]
		})
	}
	formatter := textcolumns.NewFormatter(cols.GetColumnMap())
	formatter.WriteTable(os.Stdout, imageColumns)
	return nil
}
