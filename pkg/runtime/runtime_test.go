// Copyright 2022-2024 The Inspektor Gadget authors
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

package runtime

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCombinedGadgetResult(t *testing.T) {
	t.Run("empty result", func(t *testing.T) {
		r := make(CombinedGadgetResult)
		require.NoError(t, r.Err())
	})

	t.Run("result with errors", func(t *testing.T) {
		err1 := errors.New("error1")
		err2 := errors.New("error2")
		r := CombinedGadgetResult{
			"node1": &GadgetResult{Error: err1},
			"node2": &GadgetResult{Error: err2},
		}

		combinedErr := r.Err()
		require.Error(t, combinedErr)

		// Test error unwrapping
		ce := &combinedErrors{}
		if errors.As(combinedErr, &ce) {
			errs := ce.Unwrap()
			require.Contains(t, errs, err1)
			require.Contains(t, errs, err2)
		}
	})
}

func TestCombinedErrors(t *testing.T) {
	t.Run("error string formatting", func(t *testing.T) {
		errs := []error{
			errors.New("error1"),
			errors.New("error2"),
		}
		ce := &combinedErrors{errs: errs}
		require.Equal(t, "error1\nerror2", ce.Error())
	})
}
