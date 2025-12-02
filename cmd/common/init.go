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

package common

import (
	"context"
	"fmt"
	"os"
	"strconv"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"oras.land/oras-go/v2"
	orasoci "oras.land/oras-go/v2/content/oci"

	"github.com/inspektor-gadget/inspektor-gadget/cmd/common/utils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/oci"
)

type initOptions struct {
	from  string
	local bool
}

func sudoCallerIDs() (int, int) {
	uidStr := os.Getenv("SUDO_UID")
	gidStr := os.Getenv("SUDO_GID")
	if uidStr == "" || gidStr == "" {
		return -1, -1 // not running under sudo (or no env), keep root or current UID/GID
	}
	uid, err1 := strconv.Atoi(uidStr)
	gid, err2 := strconv.Atoi(gidStr)
	if err1 != nil || err2 != nil {
		return -1, -1
	}
	return uid, gid
}

func NewInitCommand() *cobra.Command {
	o := initOptions{}
	var authOpts oci.AuthOptions
	cmd := &cobra.Command{
		Use:          "init PATH",
		Short:        "Create a new gadget",
		SilenceUsage: true,
		Args:         cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			targetDir := args[0]

			// Check whether the diretory is existing already
			if _, err := os.Stat(targetDir); !os.IsNotExist(err) {
				return fmt.Errorf("%s already exists", targetDir)
			}

			err := os.MkdirAll(args[0], 0o755)
			if err != nil {
				return fmt.Errorf("creating directory %q: %w", targetDir, err)
			}
			if o.from != "" {
				ctx := context.TODO()
				var target oras.Target

				uid, gid := -1, -1

				if !o.local {
					// Create and use temp dir; this avoids requiring to run as root at the price of
					// always pulling the image
					dir, err := os.MkdirTemp(os.TempDir(), "inspektor-gadget")
					if err != nil {
						return fmt.Errorf("creating temporary directory: %w", err)
					}
					defer os.RemoveAll(dir)
					target, err = orasoci.NewWithContext(ctx, dir)
					if err != nil {
						return fmt.Errorf("creating OCI store: %w", err)
					}
				} else {
					// Fetch sudo caller uid/gid to chown to that user
					uid, gid = sudoCallerIDs()

					if uid != -1 && gid != -1 {
						log.Debugf("Detected running with sudo; will chown files/directories to uid=%d, gid=%d", uid, gid)
					}

					err = os.Chown(targetDir, uid, gid)
					if err != nil {
						return fmt.Errorf("chown target: %w", err)
					}
				}

				cmd.Printf("Extracting sources to %s...\n", targetDir)
				found, err := oci.ExtractSources(ctx, target, o.from, targetDir, &authOpts, uid, gid)
				if err != nil {
					return fmt.Errorf("extracting sources: %w", err)
				}
				if !found {
					return fmt.Errorf("image does not contain gadget sources")
				}
			}
			return nil
		},
	}
	cmd.Flags().BoolVarP(&o.local, "local", "", false, "use local store (probably requires root privileges)")
	cmd.Flags().StringVarP(&o.from, "from", "", "", "use existing image as starting point")
	utils.AddRegistryAuthVariablesAndFlags(cmd, &authOpts)
	return cmd
}
