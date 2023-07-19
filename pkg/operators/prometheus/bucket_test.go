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

package prometheus

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_exp2Buckets(t *testing.T) {
	cfg := &BucketConfig{Type: BucketTypeExp2, Min: 0, Max: 10, Multiplier: 0.0001}
	got := cfg.buckets()
	want := []float64{
		0.0001, 0.0002, 0.0004, 0.0008, 0.0016, 0.0032, 0.0064, 0.0128, 0.0256, 0.0512,
	}
	require.Equal(t, want, got)
}

func Test_linearBuckets(t *testing.T) {
	cfg := &BucketConfig{Type: BucketTypeLinear, Min: 0, Max: 10, Multiplier: 0.0001}
	got := cfg.buckets()
	want := []float64{
		0, 0.0001, 0.0002, 0.0003, 0.0004, 0.0005, 0.0006, 0.0007, 0.0008, 0.0009,
	}
	require.Equal(t, want, got)
}
