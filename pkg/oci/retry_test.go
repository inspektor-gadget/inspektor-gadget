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

package oci

import (
	"errors"
	"testing"
)

func TestRetry(t *testing.T) {
	permanentErr := errors.New("permanent error")

	testCases := []struct {
		name          string
		mockFn        func(*int) error
		expectedErr   error
		expectedCalls int
	}{
		{
			name: "success on first call",
			mockFn: func(calls *int) error {
				*calls++
				return nil
			},
			expectedErr:   nil,
			expectedCalls: 1,
		},
		{
			name: "permanent error on first call",
			mockFn: func(calls *int) error {
				*calls++
				return permanentErr
			},
			expectedErr:   permanentErr,
			expectedCalls: 1,
		},
		{
			name: "succeeds after three retries",
			mockFn: func(calls *int) error {
				*calls++
				if *calls <= 3 {
					return errRetry
				}
				return nil
			},
			expectedErr:   nil,
			expectedCalls: 4,
		},
		{
			name: "exceeds retry limit",
			mockFn: func(calls *int) error {
				*calls++
				return errRetry
			},
			expectedErr:   ErrRetryLimitExceeded,
			expectedCalls: retryLimit,
		},
		{
			name: "mixed retry and permanent error",
			mockFn: func(calls *int) error {
				*calls++
				if *calls == 1 {
					return errRetry
				}
				return permanentErr
			},
			expectedErr:   permanentErr,
			expectedCalls: 2,
		},
		{
			name: "succeeds on last attempt",
			mockFn: func(calls *int) error {
				*calls++
				if *calls < retryLimit {
					return errRetry
				}
				return nil
			},
			expectedErr:   nil,
			expectedCalls: retryLimit,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			err := retry(tc.name, func() error {
				return tc.mockFn(&calls)
			})

			if tc.expectedErr != nil {
				if !errors.Is(err, tc.expectedErr) {
					t.Errorf("expected error %v, got %v", tc.expectedErr, err)
				}
			} else {
				if err != nil {
					t.Errorf("expected no error, got %v", err)
				}
			}

			if calls != tc.expectedCalls {
				t.Errorf("expected %d calls, got %d", tc.expectedCalls, calls)
			}
		})
	}
}
