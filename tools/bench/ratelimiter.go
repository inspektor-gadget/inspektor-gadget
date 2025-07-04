package main

import (
	"time"
)

type RateLimiter struct {
	maxRPS int
	ticker *time.Ticker
}

// NewRateLimiter creates a new RateLimiter with the specified maximum requests per second (RPS).
func NewRateLimiter(maxRPS int) *RateLimiter {
	if maxRPS <= 0 {
		return &RateLimiter{}
	}

	interval := time.Second / time.Duration(maxRPS)
	ticker := time.NewTicker(interval)

	return &RateLimiter{
		maxRPS: maxRPS,
		ticker: ticker,
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
