package telegram

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
)

const recordLookupConcurrency = 20

func (h *CommandHandler) handleRecordCommand(args []string) {
	if len(args) < 1 {
		h.sendText("用法: /record <解析记录内容-必须精确匹配>")
		return
	}

	query := normalizeRecordContent(args[0])
	if query == "" {
		h.sendText("用法: /record <解析记录内容-必须精确匹配>")
		return
	}

	if len(h.Accounts) == 0 {
		h.sendText("未配置可用的 Cloudflare 账号，无法查询。")
		return
	}
	h.sendText("要遍历所有账号的所有解析记录，且要控制查询速度，避免被 Cloudflare 限制，因此过程较慢，请耐心等待...")
	ctx := context.Background()
	var (
		mu      sync.Mutex
		wg      sync.WaitGroup
		matches []string
	)
	sem := make(chan struct{}, recordLookupConcurrency)
	errCh := make(chan error, 1)

	reportErr := func(err error) {
		select {
		case errCh <- err:
		default:
		}
	}

	for _, acc := range h.Accounts {
		acc := acc
		wg.Add(1)
		go func() {
			defer wg.Done()

			zones, err := h.CFClient.ListZones(ctx, acc)
			if err != nil {
				reportErr(fmt.Errorf("列出账号 %s 的域名失败: %v", acc.Label, err))
				return
			}

			for _, zone := range zones {
				zone := zone
				wg.Add(1)
				sem <- struct{}{}
				go func() {
					defer wg.Done()
					defer func() { <-sem }()

					records, err := h.CFClient.ListDNSRecords(ctx, acc, zone.Name)
					if err != nil {
						reportErr(fmt.Errorf("获取 %s(%s) DNS 失败: %v", zone.Name, acc.Label, err))
						return
					}

					localMatches := make([]string, 0)
					for _, r := range records {
						if !recordContentEqual(r.Content, query) {
							continue
						}

						proxied := "否"
						if r.Proxied != nil && *r.Proxied {
							proxied = "是"
						}
						localMatches = append(localMatches, fmt.Sprintf("- [%s] %s (代理: %s)",
							acc.Label, r.Name, proxied))
					}

					if len(localMatches) == 0 {
						return
					}

					mu.Lock()
					matches = append(matches, localMatches...)
					mu.Unlock()
				}()
			}
		}()
	}

	wg.Wait()

	select {
	case err := <-errCh:
		h.sendText(err.Error())
		return
	default:
	}

	if len(matches) == 0 {
		h.sendText(fmt.Sprintf("未找到内容为 %s 的解析记录。", query))
		return
	}

	sort.Strings(matches)

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("以下记录精确匹配：\n%s\n", query))
	for _, line := range matches {
		sb.WriteString(line)
		sb.WriteString("\n")
	}
	h.sendText(sb.String())
}

func normalizeRecordContent(content string) string {
	trimmed := strings.TrimSpace(content)
	return strings.TrimSuffix(trimmed, ".")
}

func recordContentEqual(content string, query string) bool {
	left := normalizeRecordContent(content)
	right := normalizeRecordContent(query)
	return strings.EqualFold(left, right)
}
