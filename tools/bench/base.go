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
		//fmt.Printf("Starting DNS request rate monitor...\n")
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
	fmt.Printf("Stopping DNS client generator...\n")

	close(g.done)
	g.rateLimiter.Close()

	return nil
}
