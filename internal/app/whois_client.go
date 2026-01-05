package app

import (
	"context"

	"DomainC/tools"
)

type DefaultWhoisClient struct{}

func (DefaultWhoisClient) Query(ctx context.Context, domain string) (string, error) {
	type result struct {
		data string
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		ch <- result{data: tools.CheckWhois(domain)}
	}()

	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case res := <-ch:
		return res.data, res.err
	}
}
