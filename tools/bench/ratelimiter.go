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
	ticker             *time.Ticker
}

// NewRateLimiter creates a new RateLimiter with the specified maximum events
// per second.
func NewRateLimiter(maxEventsPerSecond int) *RateLimiter {
	if maxEventsPerSecond <= 0 {
		return &RateLimiter{}
	}

	interval := time.Second / time.Duration(maxEventsPerSecond)
	ticker := time.NewTicker(interval)

	return &RateLimiter{
		maxEventsPerSecond: maxEventsPerSecond,
		ticker:             ticker,
	}
}

func (rl *RateLimiter) Close() {
	if rl.ticker != nil {
		rl.ticker.Stop()
		rl.ticker = nil
	}
}

func (rl *RateLimiter) Run(fn func()) {
	if rl.ticker != nil {
		<-rl.ticker.C
	}

	fn()
}
