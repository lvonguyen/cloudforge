package threatintel

import (
	"context"
	"time"

	"go.uber.org/zap"
)

// ThreatIntelEnrichment holds aggregated threat intelligence data for a finding.
type ThreatIntelEnrichment struct {
	EPSSScore       float64   `json:"epss_score"`
	EPSSPercentile  float64   `json:"epss_percentile"`
	KEVExploited    bool      `json:"kev_exploited"`
	KEVDateAdded    string    `json:"kev_date_added,omitempty"`
	GreyNoiseClass  string    `json:"greynoise_classification,omitempty"`
	GreyNoiseNoise  bool      `json:"greynoise_noise"`
	HIBPBreachCount int       `json:"hibp_breach_count,omitempty"`
	OTXPulseCount   int       `json:"otx_pulse_count,omitempty"`
	OTXTags         []string  `json:"otx_tags,omitempty"`
	EnrichedAt      time.Time `json:"enriched_at"`
}

// Enricher aggregates results from multiple threat intelligence providers.
// Each client field is nil-safe: if a client is nil (no API key), it is skipped.
type Enricher struct {
	epss      *EPSSClient
	kev       *KEVCatalog
	greynoise *GreyNoiseClient
	hibp      *HIBPClient
	otx       *OTXClient
	logger    *zap.Logger
}

// NewEnricher creates a threat intel enricher. Any client may be nil.
func NewEnricher(epss *EPSSClient, kev *KEVCatalog, greynoise *GreyNoiseClient, hibp *HIBPClient, otx *OTXClient, logger *zap.Logger) *Enricher {
	return &Enricher{
		epss:      epss,
		kev:       kev,
		greynoise: greynoise,
		hibp:      hibp,
		otx:       otx,
		logger:    logger,
	}
}

// Enrich queries all configured threat intel providers and returns aggregated results.
// Each provider is called independently — failures in one do not block others.
func (e *Enricher) Enrich(ctx context.Context, cves []string, ips []string, emails []string) *ThreatIntelEnrichment {
	result := &ThreatIntelEnrichment{
		EnrichedAt: time.Now().UTC(),
	}

	e.enrichEPSS(cves, result)
	e.enrichKEV(cves, result)
	e.enrichGreyNoise(ctx, ips, result)
	e.enrichHIBP(ctx, emails, result)
	e.enrichOTX(ctx, ips, result)

	return result
}

func (e *Enricher) enrichEPSS(cves []string, result *ThreatIntelEnrichment) {
	if e.epss == nil || len(cves) == 0 {
		return
	}
	for _, cve := range cves {
		score, percentile, err := e.epss.GetScoreWithPercentile(cve)
		if err != nil {
			e.logger.Warn("EPSS lookup failed", zap.String("cve", cve), zap.Error(err))
			continue
		}
		if score > result.EPSSScore {
			result.EPSSScore = score
			result.EPSSPercentile = percentile
		}
	}
}

func (e *Enricher) enrichKEV(cves []string, result *ThreatIntelEnrichment) {
	if e.kev == nil || len(cves) == 0 {
		return
	}
	_ = e.kev.RefreshIfStale()
	for _, cve := range cves {
		if e.kev.IsKnownExploited(cve) {
			result.KEVExploited = true
			if entry := e.kev.GetEntry(cve); entry != nil {
				result.KEVDateAdded = entry.DateAdded
			}
			break
		}
	}
}

func (e *Enricher) enrichGreyNoise(ctx context.Context, ips []string, result *ThreatIntelEnrichment) {
	if e.greynoise == nil || len(ips) == 0 {
		return
	}
	gnResult, err := e.greynoise.ClassifyIP(ctx, ips[0])
	if err != nil {
		e.logger.Warn("GreyNoise lookup failed", zap.String("ip", ips[0]), zap.Error(err))
		return
	}
	result.GreyNoiseClass = gnResult.Classification
	result.GreyNoiseNoise = gnResult.Noise
}

func (e *Enricher) enrichHIBP(ctx context.Context, emails []string, result *ThreatIntelEnrichment) {
	if e.hibp == nil || len(emails) == 0 {
		return
	}
	count, err := e.hibp.GetBreachCount(ctx, emails[0])
	if err != nil {
		e.logger.Warn("HIBP lookup failed", zap.String("email", emails[0]), zap.Error(err))
		return
	}
	result.HIBPBreachCount = count
}

func (e *Enricher) enrichOTX(ctx context.Context, ips []string, result *ThreatIntelEnrichment) {
	if e.otx == nil || len(ips) == 0 {
		return
	}
	indicator, err := e.otx.GetIndicator(ctx, OTXTypeIPv4, ips[0])
	if err != nil {
		e.logger.Warn("OTX lookup failed", zap.String("ip", ips[0]), zap.Error(err))
		return
	}
	result.OTXPulseCount = indicator.PulseCount
	result.OTXTags = indicator.Tags
}
