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
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

type baseGenerator struct {
	rateLimiter *RateLimiter
	done        chan struct{}
	doneBool    atomic.Bool
	fn          func() error

	startTime time.Time
	counter   uint64

	wg sync.WaitGroup
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

	// print stats
	g.wg.Add(1)
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()

		var lastCount uint64

		for {
			select {
			case <-ticker.C:
				currentCount := atomic.LoadUint64(&g.counter)
				rps := currentCount - lastCount
				fmt.Printf("events: %d total, %d events/s\n", currentCount, rps)

				lastCount = currentCount
			case <-g.done:
				g.wg.Done()
				return
			}
		}
	}()

	g.startTime = time.Now()

	// Start worker goroutines
	for range runtime.GOMAXPROCS(0) {
		g.wg.Add(1)
		go func() {
			for !g.doneBool.Load() {
				g.rateLimiter.Run(func() {
					err := g.fn()
					if err == nil {
						atomic.AddUint64(&g.counter, 1)
					}
				})

			}

			g.wg.Done()
		}()
	}
	return nil
}

func (g *baseGenerator) Stop() error {
	close(g.done)
	g.doneBool.Store(true)
	g.wg.Wait()

	now := time.Now()
	diff := now.Sub(g.startTime)
	generatedPerSecond := float64(atomic.LoadUint64(&g.counter)) / diff.Seconds()
	fmt.Printf("run for %s seconds, generated %f events/s\n", diff, generatedPerSecond)

	if 0.99*float64(eventsPerSecond) > generatedPerSecond {
		return fmt.Errorf("expected: %d, generated: %f",
			eventsPerSecond, generatedPerSecond)
	}

	return nil
}
