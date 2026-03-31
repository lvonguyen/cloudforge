package threatintel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestEnricher_Enrich_AllProviders(t *testing.T) {
	// EPSS server
	epssSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"status":"OK","data":[{"cve":"CVE-2024-1234","epss":"0.85","percentile":"0.97"}]}`))
	}))
	defer epssSrv.Close()

	// KEV server
	kevSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"catalogVersion":"2024.01","vulnerabilities":[{"cveID":"CVE-2024-1234","dateAdded":"2024-03-01","vendorProject":"Test","product":"TestProd","vulnerabilityName":"Test Vuln","shortDescription":"desc","requiredAction":"patch","dueDate":"2024-04-01","knownRansomwareCampaignUse":"Known","notes":""}]}`))
	}))
	defer kevSrv.Close()

	// GreyNoise server
	gnSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"ip":"1.2.3.4","noise":true,"riot":false,"classification":"malicious","name":"Scanner","last_seen":"2024-03-01"}`))
	}))
	defer gnSrv.Close()

	// HIBP server
	hibpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[{"Name":"B1","Domain":"d.com","BreachDate":"2024-01-01"},{"Name":"B2","Domain":"e.com","BreachDate":"2024-02-01"}]`))
	}))
	defer hibpSrv.Close()

	// OTX server
	otxSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"pulse_info":{"count":7,"pulses":[{"tags":["malware","c2"]},{"tags":["botnet"]}]}}`))
	}))
	defer otxSrv.Close()

	// ThreatFox server
	threatFoxSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"query_status":"ok","data":[{"ioc":"1.2.3.4:443","ioc_type":"ip:port","threat_type":"botnet_cc","malware":"win.cobalt_strike","malware_printable":"Cobalt Strike","confidence_level":75,"tags":["botnet","c2"]}]}`))
	}))
	defer threatFoxSrv.Close()

	epssClient := NewEPSSClientWithHTTP(patchHTTPClientURL(epssSrv.URL))
	kevCatalog := newKEVCatalogWithURL(kevSrv.URL)
	_ = kevCatalog.LoadCatalog()

	gnClient := NewGreyNoiseClient("test-key", WithBaseURL(gnSrv.URL+"/"), WithHTTPClient(gnSrv.Client()))
	hibpClient := NewHIBPClient("test-key", WithHIBPBaseURL(hibpSrv.URL+"/"), WithHIBPHTTPClient(hibpSrv.Client()))
	otxClient := NewOTXClient("test-key", WithOTXBaseURL(otxSrv.URL+"/"), WithOTXHTTPClient(otxSrv.Client()))
	threatFoxClient := NewThreatFoxClient("test-key", WithThreatFoxBaseURL(threatFoxSrv.URL), WithThreatFoxHTTPClient(threatFoxSrv.Client()))

	logger, _ := zap.NewDevelopment()
	enricher := NewEnricher(epssClient, kevCatalog, gnClient, hibpClient, otxClient, threatFoxClient, logger)

	result := enricher.Enrich(
		context.Background(),
		[]string{"CVE-2024-1234"},
		[]string{"1.2.3.4"},
		[]string{"victim@d.com"},
	)

	if result.EPSSScore < 0.8 {
		t.Errorf("expected EPSS score >= 0.8, got %f", result.EPSSScore)
	}
	if result.EPSSPercentile < 0.9 {
		t.Errorf("expected EPSS percentile >= 0.9, got %f", result.EPSSPercentile)
	}
	if !result.KEVExploited {
		t.Error("expected KEVExploited=true")
	}
	if result.KEVDateAdded != "2024-03-01" {
		t.Errorf("expected KEVDateAdded=2024-03-01, got %q", result.KEVDateAdded)
	}
	if result.GreyNoiseClass != "malicious" {
		t.Errorf("expected GreyNoiseClass=malicious, got %q", result.GreyNoiseClass)
	}
	if !result.GreyNoiseNoise {
		t.Error("expected GreyNoiseNoise=true")
	}
	if result.HIBPBreachCount != 2 {
		t.Errorf("expected HIBPBreachCount=2, got %d", result.HIBPBreachCount)
	}
	if result.OTXPulseCount != 7 {
		t.Errorf("expected OTXPulseCount=7, got %d", result.OTXPulseCount)
	}
	if result.ThreatFoxIOC != "1.2.3.4:443" {
		t.Errorf("expected ThreatFoxIOC=1.2.3.4:443, got %q", result.ThreatFoxIOC)
	}
	if result.ThreatFoxConfidence != 75 {
		t.Errorf("expected ThreatFoxConfidence=75, got %d", result.ThreatFoxConfidence)
	}
	if result.ThreatFoxMatchCount != 1 {
		t.Errorf("expected ThreatFoxMatchCount=1, got %d", result.ThreatFoxMatchCount)
	}
	if result.EnrichedAt.IsZero() {
		t.Error("expected non-zero EnrichedAt")
	}
}

func TestEnricher_NilClients(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	enricher := NewEnricher(nil, nil, nil, nil, nil, nil, logger)

	result := enricher.Enrich(context.Background(), []string{"CVE-2024-0001"}, []string{"1.1.1.1"}, []string{"a@b.com"})

	if result.EPSSScore != 0 {
		t.Errorf("expected 0 EPSS score with nil client, got %f", result.EPSSScore)
	}
	if result.KEVExploited {
		t.Error("expected KEVExploited=false with nil client")
	}
	if result.GreyNoiseClass != "" {
		t.Errorf("expected empty GreyNoiseClass with nil client, got %q", result.GreyNoiseClass)
	}
	if result.HIBPBreachCount != 0 {
		t.Errorf("expected 0 HIBP count with nil client, got %d", result.HIBPBreachCount)
	}
	if result.OTXPulseCount != 0 {
		t.Errorf("expected 0 OTX pulse count with nil client, got %d", result.OTXPulseCount)
	}
	if result.ThreatFoxMatchCount != 0 {
		t.Errorf("expected 0 ThreatFox match count with nil client, got %d", result.ThreatFoxMatchCount)
	}
	if result.EnrichedAt.IsZero() {
		t.Error("expected non-zero EnrichedAt even with nil clients")
	}
}

func TestEnricher_EmptyInputs(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	enricher := NewEnricher(NewEPSSClient(), NewKEVCatalog(), nil, nil, nil, nil, logger)

	result := enricher.Enrich(context.Background(), nil, nil, nil)

	if result.EPSSScore != 0 {
		t.Errorf("expected 0 with empty CVEs, got %f", result.EPSSScore)
	}
	if !result.EnrichedAt.Before(time.Now().Add(time.Minute)) {
		t.Error("EnrichedAt should be recent")
	}
}

func TestEnricher_CVEOnly(t *testing.T) {
	epssSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"status":"OK","data":[{"cve":"CVE-2024-5678","epss":"0.42","percentile":"0.78"}]}`))
	}))
	defer epssSrv.Close()

	epssClient := NewEPSSClientWithHTTP(patchHTTPClientURL(epssSrv.URL))
	logger, _ := zap.NewDevelopment()
	enricher := NewEnricher(epssClient, nil, nil, nil, nil, nil, logger)

	result := enricher.Enrich(context.Background(), []string{"CVE-2024-5678"}, nil, nil)

	if result.EPSSScore < 0.4 {
		t.Errorf("expected EPSS score >= 0.4, got %f", result.EPSSScore)
	}
	if result.KEVExploited {
		t.Error("expected KEVExploited=false when KEV client is nil")
	}
}
