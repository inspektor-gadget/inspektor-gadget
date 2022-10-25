// Copyright 2022 The Inspektor Gadget authors
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

package trace

import (
	"bytes"
	"compress/zlib"
	b64 "encoding/base64"
	"io"
	"os"

	"github.com/spf13/cobra"
)

type BeeFlags struct {
	OCIImage string
	File     string
}

func NewBeeCmd(runCmd func(*cobra.Command, []string) error, flags *BeeFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "bee",
		Short: "Trace with bees",
		RunE:  runCmd,
	}

	cmd.PersistentFlags().StringVarP(
		&flags.OCIImage,
		"oci-image",
		"",
		"",
		"Name of the OCI image containing the BPF program",
	)

	cmd.PersistentFlags().StringVarP(
		&flags.File,
		"file",
		"",
		"",
		"BPF program local file",
	)

	return cmd
}

func LoadBeeFile(path string) (string, error) {
	// Open the file for reading
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	// Create a new zlib.Writer, which will write to a bytes.Buffer
	var b bytes.Buffer
	w := zlib.NewWriter(&b)

	// Write the contents of the file to the zlib.Writer
	if _, err := io.Copy(w, file); err != nil {
		return "", err
	}

	// Close the zlib.Writer to ensure that all data has been written
	if err := w.Close(); err != nil {
		return "", err
	}

	return b64.StdEncoding.EncodeToString([]byte(b.Bytes())), nil
}
