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
	"time"
)

func TestRetry(t *testing.T) {
	tests := []struct {
		name          string
		fn            func(int *int) error
		expectedErr   error
		expectedCalls int
	}{
		{
			name: "success on first try",
			fn: func(calls *int) error {
				*calls++
				return nil
			},
			expectedErr:   nil,
			expectedCalls: 1,
		},
		{
			name: "success after retries",
			fn: func(calls *int) error {
				*calls++
				if *calls < 3 {
					return errRetry
				}
				return nil
			},
			expectedErr:   nil,
			expectedCalls: 3,
		},
		{
			name: "non-retry error",
			fn: func(calls *int) error {
				*calls++
				return errors.New("permanent error")
			},
			expectedErr:   errors.New("permanent error"),
			expectedCalls: 1,
		},
		{
			name: "exceeds retry limit",
			fn: func(calls *int) error {
				*calls++
				return errRetry
			},
			expectedErr:   ErrRetryLimitExceeded,
			expectedCalls: retryLimit,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calls := 0
			err := retry(tt.name, func() error {
				return tt.fn(&calls)
			})

			if tt.expectedErr == nil && err != nil {
				t.Errorf("expected no error, got %v", err)
			} else if tt.expectedErr != nil && err == nil {
				t.Errorf("expected error %v, got nil", tt.expectedErr)
			} else if tt.expectedErr != nil && err != nil && tt.expectedErr.Error() != err.Error() {
				t.Errorf("expected error %v, got %v", tt.expectedErr, err)
			}

			if calls != tt.expectedCalls {
				t.Errorf("expected %d calls, got %d", tt.expectedCalls, calls)
			}
		})
	}
}

func TestRetryTiming(t *testing.T) {
	start := time.Now()

	err := retry("timing-test", func() error {
		return errRetry
	})

	duration := time.Since(start)

	if !errors.Is(err, ErrRetryLimitExceeded) {
		t.Errorf("expected ErrRetryLimitExceeded, got %v", err)
	}

	expectedMinDuration := time.Duration(retryLimit-1) * retryDelay

	if duration < expectedMinDuration {
		t.Errorf("retry finished too quickly. Expected at least %v, got %v", expectedMinDuration, duration)
	}

	maxDuration := expectedMinDuration + (2 * time.Second)
	if duration > maxDuration {
		t.Errorf("retry took too long. Expected less than %v, got %v", maxDuration, duration)
	}
}
