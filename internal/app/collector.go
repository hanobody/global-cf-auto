package app

import (
	"context"

	"DomainC/config"
	"DomainC/domain"
)

// Collector 负责从 Cloudflare 账户及仓库读取域名列表。
type Collector struct {
	Service  *domain.Service
	Accounts []config.CF
}

func (c *Collector) Collect(ctx context.Context) ([]domain.DomainSource, error) {
	if c.Service == nil {
		return nil, ErrMissingDependencies
	}
	return c.Service.CollectActiveNotPaused(c.Accounts)
}
