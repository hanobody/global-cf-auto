package telegram

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/url"
	"sort"
	"strings"
	"time"

	"DomainC/cfclient"

	"github.com/cloudflare/cloudflare-go"
)

func (h *CommandHandler) handleDNSCommand(_ string, args []string) {
	if len(args) < 1 {
		h.sendText("用法: /dns <domain.com | sub.domain.com | URL>")
		return
	}

	raw := strings.TrimSpace(args[0])
	q, err := extractDomainOrHost(raw)
	if err != nil {
		log.Printf("[/dns] invalid input: raw=%q err=%v", raw, err)
		h.sendText(fmt.Sprintf("参数不合法：%v\n用法: /dns <domain.com | sub.domain.com | URL>", err))
		return
	}

	log.Printf("[/dns] query normalized: raw=%q q=%q", raw, q)

	// ✅ findZone 已经被你改成“支持子域候选”的版本（上一轮给你的 findZone 改法）
	account, zone, err := h.findZone(q)
	if err != nil {
		log.Printf("[/dns] findZone failed: q=%q err=%v", q, err)
		if errors.Is(err, cfclient.ErrZoneNotFound) {
			h.sendDigLikeDNSFallback(q, fmt.Sprintf("域名 %s 未在已配置的 Cloudflare 账号中找到，已执行类似 dig 的 DNS 查询。", q))
			return
		}
		h.sendText(fmt.Sprintf("查询域名失败: %v", err))
		return
	}

	log.Printf("[/dns] matched: q=%q zone=%q account=%q", q, zone.Name, account.Label)

	records, err := h.CFClient.ListDNSRecords(context.Background(), *account, zone.Name)
	if err != nil {
		log.Printf("[/dns] ListDNSRecords failed: q=%q zone=%q account=%q err=%v", q, zone.Name, account.Label, err)
		h.sendText(fmt.Sprintf("获取 %s 解析失败: %v", q, err))
		return
	}

	if len(records) == 0 {
		log.Printf("[/dns] no records: q=%q zone=%q account=%q", q, zone.Name, account.Label)
		h.sendDigLikeDNSFallback(q, fmt.Sprintf("Cloudflare Zone %s 中暂未读取到 DNS 记录，已执行类似 dig 的 DNS 查询。", zone.Name))
		return
	}

	// ✅ 如果用户查的是子域名，只展示该子域名（以及更深层）的记录；查 zone 本身则展示全 zone。
	filtered := records
	if !strings.EqualFold(q, zone.Name) {
		filtered = filterRecordsByNameOrSubtree(records, q)
	}

	log.Printf("[/dns] records: total=%d filtered=%d q=%q zone=%q", len(records), len(filtered), q, zone.Name)

	if len(filtered) == 0 {
		h.sendDigLikeDNSFallback(q, fmt.Sprintf("在 Cloudflare Zone %s 中没有找到与 %s 相关的 DNS 记录，已执行类似 dig 的 DNS 查询。", zone.Name, q))
		return
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("域名 %s 的 DNS 记录（账号: %s，Zone: %s）：\n", q, account.Label, zone.Name))
	for _, r := range filtered {
		proxied := "否"
		if r.Proxied != nil && *r.Proxied {
			proxied = "是"
		}
		sb.WriteString(fmt.Sprintf("- %s %s → %s (代理: %s, TTL: %d)\n",
			r.Type, r.Name, r.Content, proxied, r.TTL))
	}
	h.sendText(sb.String())
}

const dnsFallbackLookupTimeout = 10 * time.Second

type digLikeDNSResult struct {
	A      []string
	AAAA   []string
	CNAME  []string
	MX     []string
	NS     []string
	TXT    []string
	Errors []string
}

func (h *CommandHandler) sendDigLikeDNSFallback(host, reason string) {
	ctx, cancel := context.WithTimeout(context.Background(), dnsFallbackLookupTimeout)
	defer cancel()

	result := lookupDigLikeDNS(ctx, host)
	h.sendText(formatDigLikeDNSFallback(host, reason, result))
}

func lookupDigLikeDNS(ctx context.Context, host string) digLikeDNSResult {
	resolver := net.DefaultResolver
	var result digLikeDNSResult

	if ips, err := resolver.LookupIPAddr(ctx, host); err != nil {
		appendDNSLookupError(&result, "A/AAAA", err)
	} else {
		for _, ip := range ips {
			if ip.IP.To4() != nil {
				result.A = append(result.A, ip.IP.String())
			} else {
				result.AAAA = append(result.AAAA, ip.IP.String())
			}
		}
		sort.Strings(result.A)
		sort.Strings(result.AAAA)
	}

	if cname, err := resolver.LookupCNAME(ctx, host); err != nil {
		appendDNSLookupError(&result, "CNAME", err)
	} else if cname = strings.TrimSuffix(strings.TrimSpace(cname), "."); cname != "" && !strings.EqualFold(cname, strings.TrimSuffix(host, ".")) {
		result.CNAME = []string{cname}
	}

	if mxs, err := resolver.LookupMX(ctx, host); err != nil {
		appendDNSLookupError(&result, "MX", err)
	} else {
		sort.Slice(mxs, func(i, j int) bool {
			if mxs[i].Pref == mxs[j].Pref {
				return mxs[i].Host < mxs[j].Host
			}
			return mxs[i].Pref < mxs[j].Pref
		})
		for _, mx := range mxs {
			result.MX = append(result.MX, fmt.Sprintf("%d %s", mx.Pref, strings.TrimSuffix(mx.Host, ".")))
		}
	}

	if nss, err := resolver.LookupNS(ctx, host); err != nil {
		appendDNSLookupError(&result, "NS", err)
	} else {
		for _, ns := range nss {
			result.NS = append(result.NS, strings.TrimSuffix(ns.Host, "."))
		}
		sort.Strings(result.NS)
	}

	if txts, err := resolver.LookupTXT(ctx, host); err != nil {
		appendDNSLookupError(&result, "TXT", err)
	} else {
		for _, txt := range txts {
			result.TXT = append(result.TXT, truncateDNSValue(txt, 500))
		}
		sort.Strings(result.TXT)
	}

	return result
}

func formatDigLikeDNSFallback(host, reason string, result digLikeDNSResult) string {
	var sb strings.Builder
	sb.WriteString(reason)
	sb.WriteString("\n\n")
	sb.WriteString(fmt.Sprintf("DIG 查询结果（系统 DNS）：%s\n", host))

	appendDNSLookupSection(&sb, "A", result.A)
	appendDNSLookupSection(&sb, "AAAA", result.AAAA)
	appendDNSLookupSection(&sb, "CNAME", result.CNAME)
	appendDNSLookupSection(&sb, "MX", result.MX)
	appendDNSLookupSection(&sb, "NS", result.NS)
	appendDNSLookupSection(&sb, "TXT", result.TXT)

	if !result.hasRecords() {
		sb.WriteString("\n未查询到 A/AAAA/CNAME/MX/NS/TXT 记录。\n")
	}
	if len(result.Errors) > 0 {
		sb.WriteString("\n查询异常：\n")
		for _, errText := range result.Errors {
			sb.WriteString("- ")
			sb.WriteString(errText)
			sb.WriteString("\n")
		}
	}
	return strings.TrimSpace(sb.String())
}

func (r digLikeDNSResult) hasRecords() bool {
	return len(r.A)+len(r.AAAA)+len(r.CNAME)+len(r.MX)+len(r.NS)+len(r.TXT) > 0
}

func appendDNSLookupSection(sb *strings.Builder, title string, values []string) {
	if len(values) == 0 {
		return
	}
	sb.WriteString("\n")
	sb.WriteString(title)
	sb.WriteString(":\n")
	for _, value := range values {
		sb.WriteString("- ")
		sb.WriteString(value)
		sb.WriteString("\n")
	}
}

func appendDNSLookupError(result *digLikeDNSResult, recordType string, err error) {
	if err == nil {
		return
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
		return
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		result.Errors = append(result.Errors, fmt.Sprintf("%s: 查询超时", recordType))
		return
	}
	result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", recordType, err))
}

func truncateDNSValue(value string, maxRunes int) string {
	runes := []rune(value)
	if len(runes) <= maxRunes {
		return value
	}
	return string(runes[:maxRunes]) + "..."
}

// extractDomainOrHost 从用户输入中提取“可用于查 Cloudflare zone 的 host/domain”。
// 支持用户输入:
// - example.com
// - a.example.com
// - https://a.example.com/path
// - a.example.com:8443/path?q=1
// - http://a.example.com:8443
//
// 返回的 q:
// - 小写
// - 去掉末尾点
// - 去掉端口
// - 不包含路径/协议/查询参数
func extractDomainOrHost(input string) (string, error) {
	s := strings.TrimSpace(input)
	s = strings.Trim(s, `"'`) // 去掉用户可能带的引号
	if s == "" {
		return "", fmt.Errorf("empty input")
	}

	// 1) 如果看起来像 URL（带 scheme），优先 url.Parse
	if strings.Contains(s, "://") {
		u, err := url.Parse(s)
		if err != nil || u.Host == "" {
			return "", fmt.Errorf("无法解析 URL: %q", input)
		}
		host := u.Hostname() // 自动去端口，IPv6 也能处理
		return normalizeHost(host)
	}

	// 2) 不带 scheme，但可能是 host/path 或 host:port/path
	//    先去掉 fragment/query
	if i := strings.IndexAny(s, "?#"); i >= 0 {
		s = s[:i]
	}
	//    再只取 path 前面的那段
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return "", fmt.Errorf("无法从输入中提取域名: %q", input)
	}

	// 3) 如果带端口，拆掉端口
	//    注意：SplitHostPort 要求有端口且 IPv6 要带 []
	//    对于 "a.example.com:8443" 可以直接 split；对于 "a.example.com" 会失败，我们 fallback
	if strings.Contains(s, ":") {
		if host, port, err := net.SplitHostPort(s); err == nil && port != "" {
			return normalizeHost(host)
		}
		// 不是合法的 host:port（也可能只是域名里没有端口但包含 :，比如 IPv6 或者用户乱输）
	}

	return normalizeHost(s)
}

func normalizeHost(host string) (string, error) {
	h := strings.ToLower(strings.TrimSpace(host))
	h = strings.TrimSuffix(h, ".")
	if h == "" {
		return "", fmt.Errorf("empty host")
	}

	// 不支持 IP（Cloudflare zone 是域名，不是 IP）
	if ip := net.ParseIP(h); ip != nil {
		return "", fmt.Errorf("不支持 IP 地址，请输入域名或 URL")
	}

	// 过滤明显不合法的字符（粗过滤：只允许 a-z0-9.-）
	// 更严格可以上正则，但这里先确保不会把路径/奇怪字符带进去
	for _, ch := range h {
		if (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '.' || ch == '-' {
			continue
		}
		return "", fmt.Errorf("域名包含非法字符: %q", host)
	}

	// 必须至少包含一个点（例如 example.com）
	if !strings.Contains(h, ".") {
		return "", fmt.Errorf("请输入有效域名（例如 example.com），当前: %q", host)
	}

	return h, nil
}

// filterRecordsByNameOrSubtree：
// - q= a.example.com 时，匹配 a.example.com 以及 *.a.example.com / b.a.example.com ...
func filterRecordsByNameOrSubtree(records []cloudflare.DNSRecord, q string) []cloudflare.DNSRecord {
	q = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(q), "."))
	suffix := "." + q

	out := make([]cloudflare.DNSRecord, 0, len(records))
	for _, r := range records {
		name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(r.Name), "."))
		if name == q || strings.HasSuffix(name, suffix) {
			out = append(out, r)
		}
	}
	return out
}
