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

// Package limiter is a data operator that limits the number of entries in each
// batch of data. This operator is only enabled for data sources of type array.
// A great scenario for this operator is when you are already sorting data
// within an array of data and you want to filter out the top `X` entries.
package limiter

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
)

func TestLimiter(t *testing.T) {
	type testCase struct {
		originalSize int
		limit        int
		ok           bool
	}

	testCases := []testCase{
		{
			originalSize: 10,
			limit:        5,
			ok:           true,
		},
		{
			originalSize: 10,
			limit:        10,
			ok:           true,
		},
		{
			originalSize: 10,
			limit:        15,
			ok:           true,
		},
		{
			originalSize: 10,
			limit:        -10,
			ok:           false,
		},
	}

	for _, tc := range testCases {
		t.Run(
			fmt.Sprintf("originalSize=%d, limit=%d", tc.originalSize, tc.limit),
			func(t *testing.T) {
				ds, err := datasource.New(datasource.TypeArray, "limiter")
				require.NoError(t, err)

				data, err := ds.NewPacketArray()
				require.NoError(t, err)

				for i := 0; i < tc.originalSize; i++ {
					data.Append(data.New())
				}

				err = limiterFn(ds, data, tc.limit)

				if !tc.ok {
					require.Error(t, err)
					return
				}

				require.NoError(t, err)
				require.Equal(t, min(tc.limit, data.Len()), data.Len()) // limiting to a greater size should not change the size
			},
		)
	}
}
