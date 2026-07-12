package reminder

import (
	"path/filepath"
	"testing"
)

func TestReconcileCloudflareDomainsAddsAndMarksUnknown(t *testing.T) {
	store := NewFileStore(filepath.Join(t.TempDir(), "asset_cache.json"))
	if err := store.Save(Cache{Records: map[string]*Record{
		RecordKey("acc-a", "keep.example.com"): {
			Domain:       "keep.example.com",
			Source:       "acc-a",
			IsCF:         true,
			Status:       "active",
			DomainExpiry: "2027-01-01",
			Certificates: []CertificateRecord{{Type: CertTypeServed, NotAfter: "2027-01-01T00:00:00Z"}},
		},
		RecordKey("acc-a", "gone.example.com"): {
			Domain: "gone.example.com",
			Source: "acc-a",
			IsCF:   true,
			Status: "active",
		},
	}}); err != nil {
		t.Fatalf("save cache: %v", err)
	}

	refs, summary, err := store.ReconcileCloudflareDomains([]DomainChange{
		{Domain: "keep.example.com", Source: "acc-a", IsCF: true, Status: "active"},
		{Domain: "new.example.com", Source: "acc-a", IsCF: true, Status: "pending"},
	}, []string{"acc-a"}, []string{"acc-a"})
	if err != nil {
		t.Fatalf("ReconcileCloudflareDomains returned error: %v", err)
	}
	if summary.Added != 1 || summary.MarkedUnknown != 1 {
		t.Fatalf("unexpected summary: %+v", summary)
	}
	if len(refs) != 2 {
		t.Fatalf("queued refs = %d, want 2", len(refs))
	}

	cache, err := store.Load()
	if err != nil {
		t.Fatalf("load cache: %v", err)
	}
	newRec := cache.Records[RecordKey("acc-a", "new.example.com")]
	if newRec == nil || !newRec.PendingRefresh || newRec.Status != "pending" {
		t.Fatalf("new record not cached as pending refresh: %+v", newRec)
	}
	keepRec := cache.Records[RecordKey("acc-a", "keep.example.com")]
	if keepRec == nil || keepRec.DomainExpiry != "2027-01-01" || len(keepRec.Certificates) != 1 {
		t.Fatalf("existing record data was not preserved: %+v", keepRec)
	}
	goneRec := cache.Records[RecordKey("acc-a", "gone.example.com")]
	if goneRec == nil || goneRec.Status != StatusUnknownAccount || !goneRec.PendingRefresh {
		t.Fatalf("missing record was not marked unknown: %+v", goneRec)
	}
}

func TestReconcileCloudflareDomainsDoesNotMarkFailedAccountUnknown(t *testing.T) {
	store := NewFileStore(filepath.Join(t.TempDir(), "asset_cache.json"))
	if err := store.Save(Cache{Records: map[string]*Record{
		RecordKey("acc-a", "keep.example.com"): {
			Domain: "keep.example.com",
			Source: "acc-a",
			IsCF:   true,
			Status: "active",
		},
	}}); err != nil {
		t.Fatalf("save cache: %v", err)
	}

	_, summary, err := store.ReconcileCloudflareDomains(nil, nil, []string{"acc-a"})
	if err != nil {
		t.Fatalf("ReconcileCloudflareDomains returned error: %v", err)
	}
	if summary.MarkedUnknown != 0 {
		t.Fatalf("MarkedUnknown = %d, want 0", summary.MarkedUnknown)
	}
	cache, err := store.Load()
	if err != nil {
		t.Fatalf("load cache: %v", err)
	}
	rec := cache.Records[RecordKey("acc-a", "keep.example.com")]
	if rec == nil || rec.Status != "active" {
		t.Fatalf("record should stay active when account was not scanned successfully: %+v", rec)
	}
}

func TestReconcileCloudflareDomainsMergesSameDomainAcrossAccounts(t *testing.T) {
	store := NewFileStore(filepath.Join(t.TempDir(), "asset_cache.json"))

	refs, summary, err := store.ReconcileCloudflareDomains([]DomainChange{
		{Domain: "Shared.Example.com", Source: "acc-a", IsCF: true, ZoneID: "zone-a", Status: "active"},
		{Domain: "shared.example.com", Source: "acc-b", IsCF: true, ZoneID: "zone-b", Status: "active"},
	}, []string{"acc-a", "acc-b"}, []string{"acc-a", "acc-b"})
	if err != nil {
		t.Fatalf("ReconcileCloudflareDomains returned error: %v", err)
	}
	if summary.Added != 1 || summary.MergedMultiAccount != 1 {
		t.Fatalf("unexpected summary: %+v", summary)
	}
	if len(refs) != 1 {
		t.Fatalf("queued refs = %d, want 1", len(refs))
	}

	cache, err := store.Load()
	if err != nil {
		t.Fatalf("load cache: %v", err)
	}
	if len(cache.Records) != 1 {
		t.Fatalf("cache record count = %d, want 1", len(cache.Records))
	}
	rec := cache.Records[RecordKey("", "shared.example.com")]
	if rec == nil {
		t.Fatalf("merged record missing")
	}
	sources := RecordSources(*rec)
	if len(sources) != 2 || sources[0] != "acc-a" || sources[1] != "acc-b" {
		t.Fatalf("sources = %+v, want acc-a and acc-b", sources)
	}
	if got := RecordSourceDisplay(*rec); got != "acc-a, acc-b" {
		t.Fatalf("display source = %q", got)
	}
}
