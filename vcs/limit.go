package vcs

import (
	"context"
	"github.com/google/go-github/v63/github"
	"golang.org/x/time/rate"
	"sync"
	"time"
)

var (
	rl = rate.NewLimiter(defaultLimitsPerHour/secondsPerHour, 1)
	mx sync.Mutex
)

const (
	defaultLimitsPerHour = 60.
	secondsPerHour       = 3600.
)

func SetBurst(n int) {
	rl.SetBurst(n)
}

func UpdateRateLimit(ctx context.Context, client *github.Client, lock bool) error {
	if lock {
		mx.Lock()
		defer mx.Unlock()
	}

	rateLimits, _, err := client.RateLimit.Get(ctx)
	if err != nil {
		return err
	}

	rl.SetLimitAt(
		rateLimits.Core.Reset.Time.Add(-time.Hour),
		rate.Limit(rateLimits.Core.Limit),
	)

	return nil
}
