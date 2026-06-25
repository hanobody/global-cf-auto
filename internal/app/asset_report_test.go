package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"DomainC/reminder"
)

func TestBuildAssetSummaryAndNoAlertCSVReport(t *testing.T) {
	tmpDir := t.TempDir()
	store := reminder.NewFileStore(filepath.Join(tmpDir, "asset_cache.json"))
	if err := store.Save(reminder.Cache{Records: map[string]*reminder.Record{
		reminder.RecordKey("acc-a", "a.example.com"): {
			Domain: "a.example.com",
			Source: "acc-a",
			Certificates: []reminder.CertificateRecord{{
				Type:     reminder.CertTypeServed,
				NotAfter: "2026-07-01T00:00:00Z",
			}},
		},
		reminder.RecordKey("acc-a", "b.example.com"): {
			Domain: "b.example.com",
			Source: "acc-a",
		},
		reminder.RecordKey("acc-b", "c.example.com"): {
			Domain: "c.example.com",
			Source: "acc-b",
		},
		reminder.RecordKey("", "shared.example.com"): {
			Domain:  "shared.example.com",
			Sources: []string{"acc-a", "acc-b"},
		},
	}}); err != nil {
		t.Fatalf("save cache: %v", err)
	}

	summary, err := BuildAssetSummary(store)
	if err != nil {
		t.Fatalf("BuildAssetSummary returned error: %v", err)
	}
	if summary.TotalDomains != 4 {
		t.Fatalf("TotalDomains = %d, want 4", summary.TotalDomains)
	}
	if summary.TotalCertificates != 1 {
		t.Fatalf("TotalCertificates = %d, want 1", summary.TotalCertificates)
	}
	if summary.MultiAccountDomains != 1 || summary.TotalAccountLinks != 5 {
		t.Fatalf("unexpected multi-account summary: %+v", summary)
	}
	if len(summary.SourceCounts) != 2 || summary.SourceCounts[0].Source != "acc-a" || summary.SourceCounts[0].Domains != 3 {
		t.Fatalf("unexpected source counts: %+v", summary.SourceCounts)
	}

	now := time.Date(2026, 6, 25, 15, 0, 0, 0, time.UTC)
	msg := FormatAssetDailyMessageWithSummary(nil, summary, 7, now)
	for _, want := range []string{"当前缓存域名: 4 个", "账户归属: 5 条", "多账户域名: 1 个", "acc-a: 3 个域名", "acc-b: 2 个域名", "详细全量资产 CSV"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("message does not contain %q:\n%s", want, msg)
		}
	}

	path, caption, cleanup, err := BuildAssetReportFile(store, nil, 7, now)
	if err != nil {
		t.Fatalf("BuildAssetReportFile returned error: %v", err)
	}
	defer cleanup()
	if !strings.HasSuffix(path, ".csv") {
		t.Fatalf("report path = %q, want csv", path)
	}
	if !strings.Contains(caption, "全量资产 CSV") {
		t.Fatalf("caption = %q, want CSV caption", caption)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	if len(content) < 3 || content[0] != 0xEF || content[1] != 0xBB || content[2] != 0xBF {
		t.Fatalf("csv report does not start with UTF-8 BOM")
	}
	if !strings.Contains(string(content), "a.example.com") || !strings.Contains(string(content), "shared.example.com") || !strings.Contains(string(content), "账户数") {
		t.Fatalf("csv content missing expected data:\n%s", string(content))
	}
}
