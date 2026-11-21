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

//go:build linux

package ustack

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

type warnRecorder struct {
	logger.Logger
	warnings []string
}

func (w *warnRecorder) Warnf(format string, params ...any) {
	w.warnings = append(w.warnings, fmt.Sprintf(format, params...))
}

type testGadgetContext struct {
	operators.GadgetContext
	logger logger.Logger
}

func (t *testGadgetContext) Logger() logger.Logger { return t.logger }

// bpf_get_stackid() returns a negative errno on failure, which the gadget
// stores in the unsigned stack ID field. It must be reported as such and not
// be looked up in the stack map.
func TestReadUserStackMapErrno(t *testing.T) {
	t.Parallel()

	errno := unix.EEXIST
	rec := &warnRecorder{Logger: logger.DefaultLogger()}
	gadgetCtx := &testGadgetContext{logger: rec}

	// The maps are nil on purpose: they must not be used for a failed stack ID.
	addresses, buildIDs, queries, err := readUserStackMap(gadgetCtx, nil, nil, uint32(-int32(errno)))
	require.NoError(t, err)
	assert.Empty(t, addresses)
	assert.Empty(t, buildIDs)
	assert.Empty(t, queries)
	require.Len(t, rec.warnings, 1)
	assert.Contains(t, rec.warnings[0], errno.Error())
}
