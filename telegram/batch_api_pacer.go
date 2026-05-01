package telegram

import (
	"context"
	"sync"
	"time"
)

const batchAPICallInterval = time.Second

type batchAPIPacer struct {
	interval time.Duration
	next     time.Time
	mu       sync.Mutex
}

func newBatchAPIPacer() *batchAPIPacer {
	return newBatchAPIPacerWithInterval(batchAPICallInterval)
}

func newBatchAPIPacerWithInterval(interval time.Duration) *batchAPIPacer {
	return &batchAPIPacer{interval: interval}
}

func (p *batchAPIPacer) Wait(ctx context.Context) error {
	if p == nil || p.interval <= 0 {
		return nil
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	now := time.Now()
	if !p.next.IsZero() && now.Before(p.next) {
		timer := time.NewTimer(p.next.Sub(now))
		defer timer.Stop()

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		}
	}

	p.next = time.Now().Add(p.interval)
	return nil
}
