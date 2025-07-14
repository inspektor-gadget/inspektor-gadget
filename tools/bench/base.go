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
	"fmt"
	"sync/atomic"
	"time"
)

type baseGenerator struct {
	rateLimiter *RateLimiter
	done        chan struct{}
	fn          func() error
}

func NewBaseGen(cb func() error) baseGenerator {
	return baseGenerator{
		fn: cb,
	}
}

func (g *baseGenerator) Start() error {

	g.done = make(chan struct{})

	// TODO: Configurable
	g.rateLimiter = NewRateLimiter(eventsPerSecond)

	var counter uint64

	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()

		var lastCount uint64

		for {
			select {
			case <-ticker.C:
				currentCount := atomic.LoadUint64(&counter)
				rps := currentCount - lastCount
				fmt.Printf("events: %d total, %d req/s\n", currentCount, rps)

				lastCount = currentCount
			case <-g.done:
				return
			}
		}
	}()

	for range numWorkers {
		go func() {
			for {
				g.rateLimiter.Run(func() {
					err := g.fn()
					if err == nil {
						atomic.AddUint64(&counter, 1)
					}
				})
			}
		}()
	}
	return nil
}

func (g *baseGenerator) Stop() error {
	close(g.done)
	g.rateLimiter.Close()

	return nil
}
