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

package main

import (
	"time"
)

type RateLimiter struct {
	maxEventsPerSecond int
	tokens             chan struct{}
}

// NewRateLimiter creates a new RateLimiter with the specified maximum events
// per second.
func NewRateLimiter(maxEventsPerSecond int) *RateLimiter {
	if maxEventsPerSecond <= 0 {
		return &RateLimiter{}
	}

	rl := &RateLimiter{
		maxEventsPerSecond: maxEventsPerSecond,
		tokens:             make(chan struct{}, maxEventsPerSecond),
	}

	// Fill the channel with tokens to allow immediate processing of events
	for i := 0; i < maxEventsPerSecond; i++ {
		rl.tokens <- struct{}{}
	}

	// Refill tokens at the specified rate
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()

		for range ticker.C {
			for i := 0; i < maxEventsPerSecond; i++ {
				select {
				case rl.tokens <- struct{}{}:
				default:
					break
				}
			}
		}
	}()

	return rl
}

func (rl *RateLimiter) Run(fn func()) {
	if rl.tokens != nil {
		<-rl.tokens
	}

	fn()
}
