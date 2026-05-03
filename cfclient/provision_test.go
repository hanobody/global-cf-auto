package cfclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"DomainC/config"
)

func newTestAPIClient(server *httptest.Server) *apiClient {
	return &apiClient{
		accountIDCache: make(map[string]string),
		baseURL:        server.URL,
		httpClient:     server.Client(),
	}
}

func writeCFResponse(t *testing.T, w http.ResponseWriter, status int, success bool, result any, messages ...string) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	var errors []cfAPIMessage
	if !success {
		for _, msg := range messages {
			errors = append(errors, cfAPIMessage{Message: msg})
		}
	}
	_ = json.NewEncoder(w).Encode(cfAPIEnvelope{
		Success: success,
		Errors:  errors,
		Result:  mustJSONRaw(t, result),
	})
}

func mustJSONRaw(t *testing.T, v any) json.RawMessage {
	t.Helper()
	if v == nil {
		return json.RawMessage("null")
	}
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal test result: %v", err)
	}
	return b
}

func TestProvisionCloudflareZoneCallsWAFSpeedRUMAfterCreate(t *testing.T) {
	var calls []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/zones":
			writeCFResponse(t, w, http.StatusOK, true, []provisionZoneResult{})
		case r.Method == http.MethodPost && r.URL.Path == "/zones":
			writeCFResponse(t, w, http.StatusOK, true, provisionZoneResult{ID: "zone1", Name: "example.com", NameServers: []string{"a.ns.cloudflare.com", "b.ns.cloudflare.com"}})
		case r.Method == http.MethodGet && r.URL.Path == "/zones/zone1/rulesets/phases/http_request_firewall_custom/entrypoint":
			writeCFResponse(t, w, http.StatusNotFound, false, nil, "entrypoint not found")
		case r.Method == http.MethodPost && r.URL.Path == "/zones/zone1/rulesets":
			writeCFResponse(t, w, http.StatusOK, true, map[string]any{"id": "rs1"})
		case r.Method == http.MethodPatch && r.URL.Path == "/zones/zone1/settings/speed_brain":
			writeCFResponse(t, w, http.StatusOK, true, map[string]any{"id": "speed_brain", "value": "on"})
		case r.Method == http.MethodPatch && r.URL.Path == "/zones/zone1/settings/brotli":
			writeCFResponse(t, w, http.StatusOK, true, map[string]any{"id": "brotli", "value": "on"})
		case r.Method == http.MethodGet && r.URL.Path == "/accounts/acct/rum/site_info/list":
			writeCFResponse(t, w, http.StatusOK, true, []rumSite{})
		case r.Method == http.MethodPost && r.URL.Path == "/accounts/acct/rum/site_info":
			writeCFResponse(t, w, http.StatusOK, true, map[string]any{"id": "rum1"})
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.String())
		}
	}))
	defer server.Close()

	client := newTestAPIClient(server)
	result, err := client.ProvisionCloudflareZone(context.Background(), config.CF{APIToken: "secret", AccountID: "acct"}, "example.com", ProvisionOptions{
		AccountID:           "acct",
		BlockCountries:      []string{"CN"},
		EnableSpeed:         true,
		EnableRUM:           true,
		ExtraZoneSettings:   map[string]any{"brotli": "on"},
		CreateZoneIfMissing: true,
	})
	if err != nil {
		t.Fatalf("ProvisionCloudflareZone returned error: %v", err)
	}
	if !result.ZoneCreated || result.ZoneID != "zone1" {
		t.Fatalf("unexpected zone result: %+v", result)
	}

	wantOrder := []string{
		"GET /zones",
		"POST /zones",
		"GET /zones/zone1/rulesets/phases/http_request_firewall_custom/entrypoint",
		"POST /zones/zone1/rulesets",
		"PATCH /zones/zone1/settings/speed_brain",
		"PATCH /zones/zone1/settings/brotli",
		"GET /accounts/acct/rum/site_info/list",
		"POST /accounts/acct/rum/site_info",
	}
	if strings.Join(calls, "\n") != strings.Join(wantOrder, "\n") {
		t.Fatalf("unexpected call order:\n%s", strings.Join(calls, "\n"))
	}
}

func TestNormalizeCountryCodes(t *testing.T) {
	got, err := NormalizeCountryCodes([]string{"cn, ru", "CN"})
	if err != nil {
		t.Fatalf("NormalizeCountryCodes returned error: %v", err)
	}
	if strings.Join(got, ",") != "CN,RU" {
		t.Fatalf("unexpected countries: %v", got)
	}
}

func TestNormalizeCountryCodesRejectsInvalid(t *testing.T) {
	_, err := NormalizeCountryCodes([]string{"china"})
	if err == nil || !strings.Contains(err.Error(), "2-letter") {
		t.Fatalf("expected clear invalid country error, got %v", err)
	}
}

func TestEnsureCountryBlockRuleCreatesRulesetWhenEntrypointMissing(t *testing.T) {
	var created bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet:
			writeCFResponse(t, w, http.StatusNotFound, false, nil, "missing")
		case r.Method == http.MethodPost && r.URL.Path == "/zones/zone1/rulesets":
			created = true
			var body struct {
				Rules []rulesetRule `json:"rules"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode body: %v", err)
			}
			if len(body.Rules) != 1 || body.Rules[0].Expression != `ip.src.country in {"CN" "RU"}` {
				t.Fatalf("unexpected ruleset body: %+v", body)
			}
			writeCFResponse(t, w, http.StatusOK, true, map[string]any{"id": "rs1"})
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	status, err := newTestAPIClient(server).EnsureCountryBlockRule(context.Background(), config.CF{APIToken: "secret"}, "zone1", []string{"cn", "ru"})
	if err != nil {
		t.Fatalf("EnsureCountryBlockRule returned error: %v", err)
	}
	if status != statusCreated || !created {
		t.Fatalf("expected created, got status=%s created=%v", status, created)
	}
}

func TestEnsureCountryBlockRuleDoesNotDuplicateExistingRule(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("unexpected duplicate write request: %s %s", r.Method, r.URL.Path)
		}
		writeCFResponse(t, w, http.StatusOK, true, rulesetEntryPoint{
			ID: "rs1",
			Rules: []rulesetRule{{
				ID:          "rule1",
				Description: countryBlockRuleDesc,
				Expression:  `ip.src.country in {"CN"}`,
				Action:      "block",
				Enabled:     true,
			}},
		})
	}))
	defer server.Close()

	status, err := newTestAPIClient(server).EnsureCountryBlockRule(context.Background(), config.CF{APIToken: "secret"}, "zone1", []string{"cn"})
	if err != nil {
		t.Fatalf("EnsureCountryBlockRule returned error: %v", err)
	}
	if status != statusAlreadyExists {
		t.Fatalf("expected already_exists, got %s", status)
	}
}

func TestEnableSpeedRecommendationsSpeedBrainEnabled(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPatch || r.URL.Path != "/zones/zone1/settings/speed_brain" {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		writeCFResponse(t, w, http.StatusOK, true, map[string]any{"id": "speed_brain"})
	}))
	defer server.Close()

	status := newTestAPIClient(server).EnableSpeedRecommendations(context.Background(), config.CF{APIToken: "secret"}, "zone1", nil)
	if status["speed_brain"] != statusEnabled {
		t.Fatalf("expected speed_brain enabled, got %+v", status)
	}
}

func TestProvisionRecordsExtraSettingFailureWithoutFailing(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/zones":
			writeCFResponse(t, w, http.StatusOK, true, []provisionZoneResult{{ID: "zone1", Name: "example.com"}})
		case r.Method == http.MethodPatch && r.URL.Path == "/zones/zone1/settings/speed_brain":
			writeCFResponse(t, w, http.StatusOK, true, map[string]any{"id": "speed_brain"})
		case r.Method == http.MethodPatch && r.URL.Path == "/zones/zone1/settings/brotli":
			writeCFResponse(t, w, http.StatusBadRequest, false, nil, "setting is not editable")
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	result, err := newTestAPIClient(server).ProvisionCloudflareZone(context.Background(), config.CF{APIToken: "secret", AccountID: "acct"}, "example.com", ProvisionOptions{
		AccountID:         "acct",
		EnableSpeed:       true,
		ExtraZoneSettings: map[string]any{"brotli": "on"},
	})
	if err != nil {
		t.Fatalf("ProvisionCloudflareZone returned error: %v", err)
	}
	if !strings.HasPrefix(result.SpeedStatus["brotli"], statusFailedPrefix) {
		t.Fatalf("expected brotli failure status, got %+v", result.SpeedStatus)
	}
}

func TestEnsureRUMAutoInstallUpdatesExistingSite(t *testing.T) {
	var updated bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/accounts/acct/rum/site_info/list":
			writeCFResponse(t, w, http.StatusOK, true, []rumSite{{ID: "site1", Host: "example.com", AutoInstall: false}})
		case r.Method == http.MethodPut && r.URL.Path == "/accounts/acct/rum/site_info/site1":
			updated = true
			writeCFResponse(t, w, http.StatusOK, true, map[string]any{"id": "site1"})
		case r.Method == http.MethodPost:
			t.Fatalf("should not create duplicate RUM site")
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	status, err := newTestAPIClient(server).EnsureRUMAutoInstall(context.Background(), config.CF{APIToken: "secret"}, "acct", "zone1", "example.com")
	if err != nil {
		t.Fatalf("EnsureRUMAutoInstall returned error: %v", err)
	}
	if status != statusUpdated || !updated {
		t.Fatalf("expected updated, got status=%s updated=%v", status, updated)
	}
}

func TestFormatProvisionResultDoesNotContainAPIToken(t *testing.T) {
	token := "secret-token"
	msg := FormatProvisionResult(ProvisionResult{
		Domain:             "example.com",
		ZoneID:             "zone1",
		CountryBlockStatus: statusSkipped,
		SpeedStatus:        map[string]string{"speed_brain": statusEnabled},
		RUMStatus:          statusSkipped,
	})
	if strings.Contains(msg, token) {
		t.Fatalf("formatted Telegram output leaked API token")
	}
}
