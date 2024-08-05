// Copyright 2024 The Inspektor Gadget authors
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

package main

import (
	"bytes"
	"context"
	_ "embed"
	"fmt"
	"os"

	orasoci "oras.land/oras-go/v2/content/oci"

	"github.com/quay/claircore/pkg/tarfs"

	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	clioperator "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/cli"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/ebpf"
	ocihandler "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/oci-handler"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime/local"
)

// embed the tarball containing the gadget image. It was created with
// $ sudo ig image export trace_open:latest trace_open.tar

//go:embed trace_open.tar
var traceOpenBytes []byte

func do() error {
	ctx := context.Background()

	// Create an FS from the tarball bytes
	fs, err := tarfs.New(bytes.NewReader(traceOpenBytes))
	if err != nil {
		return err
	}

	// Create the oras target from the FS
	target, err := orasoci.NewFromFS(ctx, fs)
	if err != nil {
		return fmt.Errorf("getting oci store from bytes: %w", err)
	}

	gadgetCtx := gadgetcontext.New(
		context.Background(),
		// The name of the gadget to run is needed as a tarball can contain multiple images.
		"ghcr.io/inspektor-gadget/gadget/trace_open:latest",
		gadgetcontext.WithDataOperators(ocihandler.OciHandler, clioperator.CLIOperator),
		gadgetcontext.WithOrasReadonlyTarget(target),
	)

	runtime := local.New()
	if err := runtime.Init(nil); err != nil {
		return fmt.Errorf("runtime init: %w", err)
	}
	defer runtime.Close()

	params := map[string]string{
		"operator.cli.output": "columns",
	}
	if err := runtime.RunGadget(gadgetCtx, nil, params); err != nil {
		return fmt.Errorf("running gadget: %w", err)
	}

	return nil
}

func main() {
	if err := do(); err != nil {
		fmt.Printf("Error running application: %s\n", err)
		os.Exit(1)
	}
}
