package reminder

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"
)

const (
	CertTypeCFOrigin = "cf_origin"
	CertTypeServed   = "served"
)

// IsReportableCertificate 表示该证书是否参与到期提醒和日报展示。
// 现在提醒系统以域名当前 HTTPS 访问证书为准；旧版本缓存中通过 Cloudflare
// Origin CA API 拉取到的源站证书只作为历史兼容数据，不再参与日报判断。
func IsReportableCertificate(cert CertificateRecord) bool {
	typ := strings.TrimSpace(cert.Type)
	if typ == "" {
		return true
	}
	return typ == CertTypeServed
}

func reportableCertificates(certs []CertificateRecord) []CertificateRecord {
	out := make([]CertificateRecord, 0, len(certs))
	for _, cert := range certs {
		if IsReportableCertificate(cert) {
			out = append(out, cert)
		}
	}
	return out
}

func certificateKey(cert CertificateRecord) string {
	if strings.TrimSpace(cert.Key) != "" {
		return cert.Key
	}
	typ := strings.TrimSpace(cert.Type)
	if typ == "" {
		typ = "cert"
	}
	id := strings.TrimSpace(cert.ID)
	if id == "" {
		id = strings.TrimSpace(cert.SerialNumber)
	}
	if id == "" {
		id = strings.Join(cert.Hostnames, ",") + "|" + cert.NotAfter
	}
	return typ + "|" + id
}

func mergeCertificates(existing []CertificateRecord, incoming []CertificateRecord) []CertificateRecord {
	byKey := map[string]CertificateRecord{}
	for _, cert := range existing {
		key := certificateKey(cert)
		if key == "" {
			continue
		}
		cert.Key = key
		byKey[key] = cert
	}

	for _, cert := range incoming {
		cert.Key = certificateKey(cert)
		old := byKey[cert.Key]
		if old.NotAfter == cert.NotAfter {
			cert.LastAlertDate = old.LastAlertDate
		}
		if strings.TrimSpace(cert.UpdatedAt) == "" {
			cert.UpdatedAt = time.Now().Format(time.RFC3339)
		}
		byKey[cert.Key] = cert
	}

	out := make([]CertificateRecord, 0, len(byKey))
	for _, cert := range byKey {
		out = append(out, cert)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Type == out[j].Type {
			return out[i].NotAfter < out[j].NotAfter
		}
		return out[i].Type < out[j].Type
	})
	return out
}

func servedCertificate(ctx context.Context, domain string, timeout time.Duration) (CertificateRecord, error) {
	domain = NormalizeDomain(domain)
	if domain == "" {
		return CertificateRecord{}, fmt.Errorf("域名为空")
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: timeout},
		Config: &tls.Config{
			ServerName:         domain,
			InsecureSkipVerify: true, // 只读取证书链，不在这里做信任校验。
			MinVersion:         tls.VersionTLS12,
		},
	}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(domain, "443"))
	if err != nil {
		return CertificateRecord{}, fmt.Errorf("读取访问证书失败: %w", err)
	}
	defer conn.Close()
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return CertificateRecord{}, fmt.Errorf("TLS 连接类型异常")
	}
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return CertificateRecord{}, fmt.Errorf("未读取到访问证书")
	}
	return certRecordFromX509(CertTypeServed, state.PeerCertificates[0]), nil
}

func certRecordFromX509(typ string, cert *x509.Certificate) CertificateRecord {
	if cert == nil {
		return CertificateRecord{}
	}
	hosts := append([]string(nil), cert.DNSNames...)
	sort.Strings(hosts)
	rec := CertificateRecord{
		Type:         typ,
		Hostnames:    hosts,
		Issuer:       cert.Issuer.String(),
		Subject:      cert.Subject.String(),
		SerialNumber: cert.SerialNumber.String(),
		NotBefore:    timeString(cert.NotBefore),
		NotAfter:     timeString(cert.NotAfter),
		UpdatedAt:    time.Now().Format(time.RFC3339),
	}
	rec.Key = certificateKey(rec)
	return rec
}

func hostnameMatchesDomain(host string, domain string) bool {
	host = NormalizeDomain(strings.TrimPrefix(strings.TrimSpace(host), "*."))
	domain = NormalizeDomain(domain)
	if host == "" || domain == "" {
		return false
	}
	return host == domain || strings.HasSuffix(host, "."+domain)
}
