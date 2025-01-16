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
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	retryLimit = 20
	retryDelay = 500 * time.Millisecond
)

// errRetry hints that the function can safely be tried again after a small
// time.
var errRetry = errors.New("retry")

// ErrRetryLimitExceeded indicates the function was retried too many times.
var ErrRetryLimitExceeded = errors.New("retry limit exceeded")

// retry calls the fn callback multiple times until it succeeds.
//
// The fn callback should return errRetry to indicate that it failed but it is
// safe to try it again after waiting a small time. If the retry limit is
// reached, the function returns ErrRetryLimitExceeded.
func retry(name string, fn func() error) error {
	for i := 0; i < retryLimit; i++ {
		err := fn()
		if err == nil {
			return nil
		}
		if !errors.Is(err, errRetry) {
			return err
		}

		log.Debugf("retrying %s (%d of %d)", name, i+1, retryLimit)
		time.Sleep(retryDelay)
	}

	return ErrRetryLimitExceeded
}
