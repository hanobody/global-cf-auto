package app

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"DomainC/domain"
	"DomainC/tools"
)

type WhoisClient interface {
	Query(ctx context.Context, domain string) (string, error)
}

type ExpiryCheckerService struct {
	Whois        WhoisClient
	Repo         domain.Repository
	AlertWithin  time.Duration
	RateLimit    time.Duration
	QueryTimeout time.Duration
}

func (c *ExpiryCheckerService) Check(ctx context.Context, domains []domain.DomainSource) ([]domain.DomainSource, []domain.FailureRecord, error) {
	if c.Whois == nil {
		return nil, nil, ErrMissingDependencies
	}
	if c.AlertWithin == 0 {
		c.AlertWithin = 24 * time.Hour
	}
	var ticker *time.Ticker
	if c.RateLimit > 0 {
		ticker = time.NewTicker(c.RateLimit)
		defer ticker.Stop()
	}

	var expiring []domain.DomainSource
	var failures []domain.FailureRecord
	for i, ds := range domains {
		if expiryStr := strings.TrimSpace(ds.Expiry); expiryStr != "" {
			expiryTime, err := time.Parse("2006-01-02", expiryStr)
			if err != nil {
				failures = append(failures, domain.FailureRecord{Domain: ds.Domain, Source: ds.Source, Reason: fmt.Sprintf("解析失败: %v", err)})
				continue
			}

			if time.Until(expiryTime) <= c.AlertWithin {
				ds.Expiry = expiryTime.Format("2006-01-02")
				expiring = append(expiring, ds)
			}
			continue
		}

		if i > 0 && ticker != nil {
			select {
			case <-ctx.Done():
				return expiring, failures, ctx.Err()
			case <-ticker.C:
			}
		}

		lookupCtx := ctx
		cancel := func() {}
		if c.QueryTimeout > 0 {
			lookupCtx, cancel = context.WithTimeout(ctx, c.QueryTimeout)
		}
		result, err := c.Whois.Query(lookupCtx, ds.Domain)
		cancel()
		if err != nil {
			log.Printf("WHOIS 查询失败 (%s): %v", ds.Domain, err)
			failures = append(failures, domain.FailureRecord{Domain: ds.Domain, Source: ds.Source, Reason: err.Error()})
			continue
		}

		expiry, ok := tools.ExtractExpiry(result)
		if !ok {
			failures = append(failures, domain.FailureRecord{Domain: ds.Domain, Source: ds.Source, Reason: truncateReason("未找到到期时间字段: " + result)})
			continue
		}
		expiryTime, err := time.Parse("2006-01-02", expiry)
		if err != nil {
			log.Printf("解析到期时间失败 [%s]: %v", ds.Domain, err)
			failures = append(failures, domain.FailureRecord{Domain: ds.Domain, Source: ds.Source, Reason: fmt.Sprintf("解析失败: %v", err)})
			continue
		}

		if time.Until(expiryTime) <= c.AlertWithin {
			ds.Expiry = expiry
			expiring = append(expiring, ds)
		}
	}

	if c.Repo != nil {
		if err := c.Repo.SaveExpiring(expiring); err != nil {
			return expiring, failures, err
		}
		if err := c.Repo.SaveFailures(failures); err != nil {
			return expiring, failures, err
		}
	}
	return expiring, failures, nil
}

func truncateReason(reason string) string {
	// 信息太常进行截断，先不启用
	// const maxLen = 200
	// if len(reason) <= maxLen {
	// 	return reason
	// }
	// return reason[:maxLen] + "..."
	return reason
}
