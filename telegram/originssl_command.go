package telegram

import (
	// "bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"DomainC/config"

	"github.com/aws/aws-sdk-go-v2/aws"
	awscfg "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/acm"
)

func (h *CommandHandler) handleOriginSSLCommand(args []string) {
	// /ssl <domain> [aws-alias1] [aws-alias2]
	if len(args) < 1 {
		h.sendText(h.originSSLPromptText())
		return
	}

	domain := strings.TrimSpace(args[0])
	if domain == "" {
		h.sendText(h.originSSLPromptText())
		return
	}

	// 解析可选 aws aliases（最多 2 个）
	aliases := make([]string, 0, 2)
	seen := map[string]struct{}{}
	for _, a := range args[1:] {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		if _, ok := seen[a]; ok {
			continue
		}
		seen[a] = struct{}{}
		aliases = append(aliases, a)
		if len(aliases) == 2 {
			break
		}
	}

	ctx := context.Background()

	// 自动定位账号：domain 必须是某个账号下的 zone
	acc, err := h.findAccountByDomain(ctx, domain)
	if err != nil {
		h.sendText(fmt.Sprintf("无法定位域名所属账号：%v\n\n%s", err, h.originSSLPromptText()))
		return
	}

	// 固定生成：裸域 + 通配
	hostnames := []string{domain, "*." + domain}

	// 创建 15 年 Origin CA 证书
	cert, err := h.CFClient.CreateOriginCertificate(ctx, *acc, hostnames)
	if err != nil {
		h.sendText(fmt.Sprintf("创建源站证书失败: %v", err))
		return
	}
	if _, zone, zerr := h.findZone(strings.ToLower(strings.TrimSpace(domain))); zerr != nil {
		// 不阻断主流程
		h.sendText(fmt.Sprintf("⚠️ 已生成源站证书，但查询 Zone 失败，无法设置 SSL 模式为 Full (Strict): %v", zerr))
	} else {
		if serr := h.CFClient.SetZoneSSLFullStrict(ctx, *acc, zone.ID); serr != nil {
			// 不阻断主流程
			h.sendText(fmt.Sprintf("⚠️ 已生成源站证书，但设置 SSL 模式为 Full (Strict) 失败: %v", serr))
		} else {
			h.sendText("✅ 已将 Cloudflare SSL/TLS 加密模式设置为 Full (Strict)。")
		}
	}
	// 可选导入 ACM（0/1/2 个）
	type importResult struct {
		alias  string
		region string
		arn    string
		err    error
	}
	results := make([]importResult, 0, len(aliases))

	for _, awsAlias := range aliases {
		target, ok := config.Cfg.AWSTargets[awsAlias]
		if !ok {
			results = append(results, importResult{
				alias: awsAlias,
				err:   fmt.Errorf("未知 AWS 目标别名：%s", awsAlias),
			})
			continue
		}
		acmArn, e := importToACM(ctx, target, cert.CertificatePEM, cert.PrivateKeyPEM)
		results = append(results, importResult{
			alias:  awsAlias,
			region: target.Region,
			arn:    acmArn,
			err:    e,
		})
	}

	// 文本回执（生成 + 可选导入结果）
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("CF源站证书已生成：%s\n账号：%s\nHostnames: %s\n",
		domain, acc.Label, strings.Join(hostnames, ", "),
	))
	if !cert.ExpiresOn.IsZero() {
		sb.WriteString(fmt.Sprintf("到期：%s\n", cert.ExpiresOn.Format(time.RFC3339)))
	}
	if len(results) == 0 {
		sb.WriteString("\nACM：未导入（未提供 aws alias）。\n")
	} else {
		var okLines, failLines []string
		for _, r := range results {
			if r.err != nil {
				if r.region != "" {
					failLines = append(failLines, fmt.Sprintf("- %s (%s): %v", r.alias, r.region, r.err))
				} else {
					failLines = append(failLines, fmt.Sprintf("- %s: %v", r.alias, r.err))
				}
				continue
			}
			okLines = append(okLines, fmt.Sprintf("- %s (%s):\n %s", r.alias, r.region, r.arn))
		}
		sb.WriteString("\nACM 导入结果：\n")
		if len(okLines) > 0 {
			sb.WriteString("✅ 成功：\n```text\n" + strings.Join(okLines, "\n") + "\n```\n")
		}
		if len(failLines) > 0 {
			sb.WriteString("\n❌ 失败：\n```text\n" + strings.Join(failLines, "\n") + "\n```\n")
		}
	}
	h.sendText(sb.String())

	// --------- 发回两个文件：cert+csr 与 key ---------

	// (1) cert 文件：头信息 + CERT + CSR（不包含私钥）
	// var certOut bytes.Buffer
	// certOut.WriteString("### Cloudflare Origin CA Certificate\n")
	// certOut.WriteString(fmt.Sprintf("Account: %s\n", acc.Label))
	// certOut.WriteString(fmt.Sprintf("Zone: %s\n", domain))
	// certOut.WriteString(fmt.Sprintf("Hostnames: %s\n", strings.Join(hostnames, ", ")))
	// if cert.ID != "" {
	// 	certOut.WriteString(fmt.Sprintf("CertID: %s\n", cert.ID))
	// }
	// if !cert.ExpiresOn.IsZero() {
	// 	certOut.WriteString(fmt.Sprintf("ExpiresOn: %s\n", cert.ExpiresOn.Format(time.RFC3339)))
	// }
	// certOut.WriteString("\n")

	// certOut.WriteString("-----BEGIN CERTIFICATE-----\n")
	// certOut.WriteString(strings.TrimSpace(cert.CertificatePEM))
	// certOut.WriteString("\n-----END CERTIFICATE-----\n\n")

	// if strings.TrimSpace(cert.CSRPEM) != "" {
	// 	certOut.WriteString("-----BEGIN CERTIFICATE REQUEST-----\n")
	// 	certOut.WriteString(strings.TrimSpace(cert.CSRPEM))
	// 	certOut.WriteString("\n-----END CERTIFICATE REQUEST-----\n")
	// }

	// // (2) key 文件：仅私钥
	// var keyOut bytes.Buffer
	// keyOut.WriteString("-----BEGIN PRIVATE KEY-----\n")
	// keyOut.WriteString(strings.TrimSpace(cert.PrivateKeyPEM))
	// keyOut.WriteString("\n-----END PRIVATE KEY-----\n")

	// ts := time.Now().Format("20060102-150405")
	// certFilename := sanitizeFilename(fmt.Sprintf("origin-ca-%s-%s-cert.pem", domain, ts))
	// keyFilename := sanitizeFilename(fmt.Sprintf("origin-ca-%s-%s-key.pem", domain, ts))

	// certPath, err := writeTempAndMove(certFilename, certOut.Bytes(), 0644)
	// if err != nil {
	// 	h.sendText(fmt.Sprintf("写入证书文件失败: %v", err))
	// 	return
	// }
	// defer os.Remove(certPath)

	// keyPath, err := writeTempAndMove(keyFilename, keyOut.Bytes(), 0600)
	// if err != nil {
	// 	h.sendText(fmt.Sprintf("写入私钥文件失败: %v", err))
	// 	return
	// }
	// defer os.Remove(keyPath)

	// certCaption := "📄 Cloudflare Origin CA 证书（Certificate + CSR）"
	// if !cert.ExpiresOn.IsZero() {
	// 	certCaption = fmt.Sprintf("📄 Cloudflare Origin CA 证书（Certificate + CSR）\n到期：%s", cert.ExpiresOn.Format(time.RFC3339))
	// }
	// keyCaption := "🔐 Cloudflare Origin CA 私钥（Private Key）"

	// if err := h.Sender.SendDocumentPath(context.Background(), certPath, certCaption); err != nil {
	// 	h.sendText(fmt.Sprintf("发送证书文件失败: %v", err))
	// 	return
	// }
	// if err := h.Sender.SendDocumentPath(context.Background(), keyPath, keyCaption); err != nil {
	// 	h.sendText(fmt.Sprintf("发送私钥文件失败: %v", err))
	// 	return
	// }

	// h.sendText(fmt.Sprintf("✅ 源站证书处理完成：%s（账号：%s）", domain, acc.Label))
}

// 写临时文件并移动到 /tmp（最终路径），返回最终路径
func writeTempAndMove(filename string, data []byte, perm os.FileMode) (string, error) {
	tmpFile, err := os.CreateTemp("", "origin-ca-*.pem")
	if err != nil {
		return "", err
	}
	tmpPath := tmpFile.Name()

	defer func() {
		_ = tmpFile.Close()
		_ = os.Remove(tmpPath)
	}()

	_ = os.Chmod(tmpPath, perm)

	if _, err := tmpFile.Write(data); err != nil {
		return "", err
	}
	_ = tmpFile.Sync()

	finalPath := filepath.Join(os.TempDir(), filename)
	_ = os.Rename(tmpPath, finalPath)

	return finalPath, nil
}

// 提示文本
func (h *CommandHandler) originSSLPromptText() string {
	if len(h.Accounts) == 0 {
		return "未配置可用的 Cloudflare 账号，无法生成源站证书。"
	}

	var sb strings.Builder
	sb.WriteString("生成 Cloudflare Origin CA 源站证书（15年）。\n\n")
	sb.WriteString("/ssl <主域名> <aws-alias1> <aws-alias2>\n\n")
	sb.WriteString("示例：\n")
	sb.WriteString("/ssl example.com us-aws sg-aws\n\n")
	sb.WriteString("说明：该命令固定签发 example.com + \\*.example.com\n\n")
	sb.WriteString("可用账号：\n")
	for _, a := range h.Accounts {
		if strings.TrimSpace(a.Label) == "" {
			continue
		}
		sb.WriteString("- " + a.Label + "\n")
	}
	sb.WriteString("\n可用 AWS 目标：\n")
	for name, t := range config.Cfg.AWSTargets {
		if strings.TrimSpace(name) == "" {
			continue
		}
		sb.WriteString(fmt.Sprintf("- %s (%s)\n", name, t.Region))
	}
	return sb.String()
}

// 自动定位域名所属账号：domain 必须精确匹配某个账号下的 zone.Name
// - 命中 0：域名不在任何账号
// - 命中 1：返回该账号
// - 命中 >1：歧义（一般不该发生，但必须阻止）
func (h *CommandHandler) findAccountByDomain(ctx context.Context, domain string) (*config.CF, error) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return nil, fmt.Errorf("domain 为空")
	}

	var matched []*config.CF
	for i := range h.Accounts {
		acc := &h.Accounts[i]

		zones, err := h.CFClient.ListZones(ctx, *acc)
		if err != nil {
			// 单账号失败不阻断，继续尝试其他账号
			continue
		}
		for _, z := range zones {
			if strings.EqualFold(strings.TrimSpace(z.Name), domain) {
				matched = append(matched, acc)
				break
			}
		}
	}

	if len(matched) == 0 {
		return nil, fmt.Errorf("域名 %s 不在任何 Cloudflare 账号中", domain)
	}
	if len(matched) > 1 {
		return nil, fmt.Errorf("域名 %s 同时存在于多个 Cloudflare 账号中（歧义），请先清理重复 zone", domain)
	}
	return matched[0], nil
}

// 简单文件名清洗（避免 OS/Telegram 不兼容字符）
func sanitizeFilename(name string) string {
	name = strings.ReplaceAll(name, " ", "_")
	name = strings.ReplaceAll(name, "/", "_")
	name = strings.ReplaceAll(name, "\\", "_")
	name = strings.ReplaceAll(name, ":", "_")
	return name
}
func importToACM(ctx context.Context, target config.AWSTarget, certPEM, keyPEM string) (string, error) {
	if strings.TrimSpace(target.Region) == "" {
		return "", fmt.Errorf("aws target region 为空")
	}
	if strings.TrimSpace(target.Creds.AccessKeyID) == "" || strings.TrimSpace(target.Creds.SecretAccessKey) == "" {
		return "", fmt.Errorf("aws target creds 不完整")
	}

	cfg, err := awscfg.LoadDefaultConfig(
		ctx,
		awscfg.WithRegion(target.Region),
		awscfg.WithCredentialsProvider(
			aws.NewCredentialsCache(
				credentials.NewStaticCredentialsProvider(
					target.Creds.AccessKeyID,
					target.Creds.SecretAccessKey,
					target.Creds.SessionToken,
				),
			),
		),
	)
	if err != nil {
		return "", fmt.Errorf("load aws config: %w", err)
	}

	client := acm.NewFromConfig(cfg)

	certBody := []byte(strings.TrimSpace(certPEM) + "\n")
	privKey := []byte(strings.TrimSpace(keyPEM) + "\n")

	out, err := client.ImportCertificate(ctx, &acm.ImportCertificateInput{
		Certificate: certBody,
		PrivateKey:  privKey,
	})
	if err != nil {
		return "", fmt.Errorf("acm import certificate: %w", err)
	}
	return *out.CertificateArn, nil
}
