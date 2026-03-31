package threatintel

import (
	"context"
	"net"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
)

// providerTimeout caps each threat intel provider call block to prevent
// one slow upstream from consuming the entire request budget.
const providerTimeout = 6 * time.Second

// ThreatIntelEnrichment holds aggregated threat intelligence data for a finding.
type ThreatIntelEnrichment struct {
	EPSSScore           float64   `json:"epss_score"`
	EPSSPercentile      float64   `json:"epss_percentile"`
	KEVExploited        bool      `json:"kev_exploited"`
	KEVDateAdded        string    `json:"kev_date_added,omitempty"`
	GreyNoiseClass      string    `json:"greynoise_classification,omitempty"`
	GreyNoiseNoise      bool      `json:"greynoise_noise"`
	HIBPBreachCount     int       `json:"hibp_breach_count,omitempty"`
	OTXPulseCount       int       `json:"otx_pulse_count,omitempty"`
	OTXTags             []string  `json:"otx_tags,omitempty"`
	ThreatFoxIOC        string    `json:"threatfox_ioc,omitempty"`
	ThreatFoxIOCType    string    `json:"threatfox_ioc_type,omitempty"`
	ThreatFoxThreatType string    `json:"threatfox_threat_type,omitempty"`
	ThreatFoxMalware    string    `json:"threatfox_malware,omitempty"`
	ThreatFoxConfidence int       `json:"threatfox_confidence,omitempty"`
	ThreatFoxMatchCount int       `json:"threatfox_match_count,omitempty"`
	ThreatFoxTags       []string  `json:"threatfox_tags,omitempty"`
	EnrichedAt          time.Time `json:"enriched_at"`
}

// Enricher aggregates results from multiple threat intelligence providers.
// Each client field is nil-safe: if a client is nil (no API key), it is skipped.
type Enricher struct {
	epss      *EPSSClient
	kev       *KEVCatalog
	greynoise *GreyNoiseClient
	hibp      *HIBPClient
	otx       *OTXClient
	threatfox *ThreatFoxClient
	logger    *zap.Logger
}

// NewEnricher creates a threat intel enricher. Any client may be nil.
func NewEnricher(epss *EPSSClient, kev *KEVCatalog, greynoise *GreyNoiseClient, hibp *HIBPClient, otx *OTXClient, threatfox *ThreatFoxClient, logger *zap.Logger) *Enricher {
	return &Enricher{
		epss:      epss,
		kev:       kev,
		greynoise: greynoise,
		hibp:      hibp,
		otx:       otx,
		threatfox: threatfox,
		logger:    logger,
	}
}

// Enrich queries all configured threat intel providers in parallel and returns
// aggregated results. Each provider writes to disjoint fields on the result struct,
// so concurrent access is safe without synchronization. Invalid IPs are filtered
// before reaching external APIs (SA-016).
func (e *Enricher) Enrich(ctx context.Context, cves []string, ips []string, emails []string) *ThreatIntelEnrichment {
	result := &ThreatIntelEnrichment{
		EnrichedAt: time.Now().UTC(),
	}

	// Validate IPs before passing to external providers (SA-016).
	validIPs := make([]string, 0, len(ips))
	for _, ip := range ips {
		if net.ParseIP(ip) != nil {
			validIPs = append(validIPs, ip)
		}
	}

	g, gCtx := errgroup.WithContext(ctx)
	g.Go(func() error { e.enrichEPSSTraced(gCtx, cves, result); return nil })
	g.Go(func() error { e.enrichKEVTraced(gCtx, cves, result); return nil })
	g.Go(func() error { e.enrichGreyNoise(gCtx, validIPs, result); return nil })
	g.Go(func() error { e.enrichHIBP(gCtx, emails, result); return nil })
	g.Go(func() error { e.enrichOTX(gCtx, validIPs, result); return nil })
	g.Go(func() error { e.enrichThreatFox(gCtx, validIPs, result); return nil })
	_ = g.Wait()

	return result
}

func (e *Enricher) enrichEPSSTraced(ctx context.Context, cves []string, result *ThreatIntelEnrichment) {
	ctx, cancel := context.WithTimeout(ctx, providerTimeout)
	defer cancel()
	_, span := otel.Tracer("aegis.threatintel").Start(ctx, "threatintel.epss")
	defer span.End()
	span.SetAttributes(
		attribute.String("feed", "epss"),
		attribute.Int("input.cve_count", len(cves)),
	)
	e.enrichEPSS(ctx, cves, result)
	span.SetAttributes(attribute.Bool("cache.hit", result.EPSSScore > 0))
}

func (e *Enricher) enrichKEVTraced(ctx context.Context, cves []string, result *ThreatIntelEnrichment) {
	ctx, cancel := context.WithTimeout(ctx, providerTimeout)
	defer cancel()
	_, span := otel.Tracer("aegis.threatintel").Start(ctx, "threatintel.kev")
	defer span.End()
	span.SetAttributes(
		attribute.String("feed", "kev"),
		attribute.Int("input.cve_count", len(cves)),
	)
	e.enrichKEV(ctx, cves, result)
	span.SetAttributes(attribute.Bool("kev.exploited", result.KEVExploited))
}

func (e *Enricher) enrichEPSS(_ context.Context, cves []string, result *ThreatIntelEnrichment) {
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

func (e *Enricher) enrichKEV(_ context.Context, cves []string, result *ThreatIntelEnrichment) {
	if e.kev == nil || len(cves) == 0 {
		return
	}
	if err := e.kev.RefreshIfStale(); err != nil {
		e.logger.Warn("KEV refresh failed", zap.Error(err))
	}
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
	ctx, cancel := context.WithTimeout(ctx, providerTimeout)
	defer cancel()
	ctx, span := otel.Tracer("aegis.threatintel").Start(ctx, "threatintel.greynoise")
	defer span.End()
	span.SetAttributes(
		attribute.String("feed", "greynoise"),
		attribute.Int("input.ip_count", len(ips)),
	)
	classRank := map[string]int{"malicious": 3, "suspicious": 2, "benign": 1, "unknown": 0}
	bestRank := -1
	limit := len(ips)
	if limit > 5 {
		limit = 5
	}
	for _, ip := range ips[:limit] {
		gnResult, err := e.greynoise.ClassifyIP(ctx, ip)
		if err != nil {
			e.logger.Warn("GreyNoise lookup failed", zap.String("ip", ip), zap.Error(err))
			continue
		}
		rank, known := classRank[gnResult.Classification]
		if !known {
			e.logger.Warn("unrecognized GreyNoise classification",
				zap.String("classification", gnResult.Classification), zap.String("ip", ip))
			rank = 0 // treat unrecognized as "unknown" to preserve signal
		}
		if rank > bestRank {
			bestRank = rank
			result.GreyNoiseClass = gnResult.Classification
			result.GreyNoiseNoise = gnResult.Noise
		}
	}
}

func (e *Enricher) enrichHIBP(ctx context.Context, emails []string, result *ThreatIntelEnrichment) {
	if e.hibp == nil || len(emails) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, providerTimeout)
	defer cancel()
	ctx, span := otel.Tracer("aegis.threatintel").Start(ctx, "threatintel.hibp")
	defer span.End()
	span.SetAttributes(
		attribute.String("feed", "hibp"),
		attribute.Int("input.email_count", len(emails)),
	)
	limit := len(emails)
	if limit > 5 {
		limit = 5
	}
	for _, email := range emails[:limit] {
		count, err := e.hibp.GetBreachCount(ctx, email)
		if err != nil {
			e.logger.Warn("HIBP lookup failed", zap.String("email", email), zap.Error(err))
			continue
		}
		result.HIBPBreachCount += count
	}
}

func (e *Enricher) enrichOTX(ctx context.Context, ips []string, result *ThreatIntelEnrichment) {
	if e.otx == nil || len(ips) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, providerTimeout)
	defer cancel()
	ctx, span := otel.Tracer("aegis.threatintel").Start(ctx, "threatintel.otx")
	defer span.End()
	span.SetAttributes(
		attribute.String("feed", "otx"),
		attribute.Int("input.ip_count", len(ips)),
	)
	limit := len(ips)
	if limit > 5 {
		limit = 5
	}
	for _, ip := range ips[:limit] {
		indicator, err := e.otx.GetIndicator(ctx, OTXTypeIPv4, ip)
		if err != nil {
			e.logger.Warn("OTX lookup failed", zap.String("ip", ip), zap.Error(err))
			continue
		}
		if indicator.PulseCount > result.OTXPulseCount {
			result.OTXPulseCount = indicator.PulseCount
			result.OTXTags = indicator.Tags
		}
	}
}

func (e *Enricher) enrichThreatFox(ctx context.Context, ips []string, result *ThreatIntelEnrichment) {
	if e.threatfox == nil || len(ips) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, providerTimeout)
	defer cancel()
	ctx, span := otel.Tracer("aegis.threatintel").Start(ctx, "threatintel.threatfox")
	defer span.End()
	span.SetAttributes(
		attribute.String("feed", "threatfox"),
		attribute.Int("input.ip_count", len(ips)),
	)
	limit := len(ips)
	if limit > 5 {
		limit = 5
	}
	bestConfidence := -1
	for _, ip := range ips[:limit] {
		match, err := e.threatfox.SearchIOC(ctx, ip)
		if err != nil {
			e.logger.Warn("ThreatFox lookup failed", zap.String("ip", ip), zap.Error(err))
			continue
		}
		if match == nil {
			continue
		}
		result.ThreatFoxMatchCount++
		if match.ConfidenceLevel > bestConfidence {
			bestConfidence = match.ConfidenceLevel
			result.ThreatFoxIOC = match.IOC
			result.ThreatFoxIOCType = match.IOCType
			result.ThreatFoxThreatType = match.ThreatType
			result.ThreatFoxMalware = match.MalwarePrintable
			if result.ThreatFoxMalware == "" {
				result.ThreatFoxMalware = match.Malware
			}
			result.ThreatFoxConfidence = match.ConfidenceLevel
			result.ThreatFoxTags = match.Tags
		}
	}
}
