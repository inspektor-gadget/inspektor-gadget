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

package ebpfoperator_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	orasoci "oras.land/oras-go/v2/content/oci"

	utilstest "github.com/inspektor-gadget/inspektor-gadget/internal/test"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/ebpf"
	ocihandler "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/oci-handler"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime/local"
)

func TestEmpty(t *testing.T) {
	utilstest.RequireRoot(t)

	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*2)
	t.Cleanup(cancel)

	ociStore, err := orasoci.NewFromTar(ctx, "testdata/empty.tar")
	require.NoError(t, err, "creating oci store")

	gadgetCtx := gadgetcontext.New(
		ctx,
		"empty:latest",
		gadgetcontext.WithDataOperators(ocihandler.OciHandler),
		gadgetcontext.WithOrasReadonlyTarget(ociStore),
	)

	runtime := local.New()
	err = runtime.Init(nil)
	require.NoError(t, err, "runtime init")
	t.Cleanup(func() { runtime.Close() })

	params := map[string]string{
		"operator.oci.verify-image": "false",
	}
	err = runtime.RunGadget(gadgetCtx, nil, params)
	require.Error(t, err, "running gadget")
}
