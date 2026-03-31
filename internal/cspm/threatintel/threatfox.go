package threatintel

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"sync"
	"time"
)

const (
	threatFoxBaseURL  = "https://threatfox-api.abuse.ch/api/v1/"
	threatFoxCacheTTL = 12 * time.Hour
)

// ThreatFoxMatch is the subset of ThreatFox IOC metadata used in enrichment.
type ThreatFoxMatch struct {
	IOC              string   `json:"ioc"`
	IOCType          string   `json:"ioc_type"`
	ThreatType       string   `json:"threat_type"`
	Malware          string   `json:"malware"`
	MalwarePrintable string   `json:"malware_printable"`
	ConfidenceLevel  int      `json:"confidence_level"`
	Tags             []string `json:"tags"`
}

type threatFoxAPIResponse struct {
	QueryStatus string           `json:"query_status"`
	Data        []ThreatFoxMatch `json:"data"`
}

type threatFoxEntry struct {
	match    *ThreatFoxMatch
	cachedAt time.Time
}

func (e threatFoxEntry) isExpired() bool {
	return time.Since(e.cachedAt) > threatFoxCacheTTL
}

// ThreatFoxOption configures a ThreatFoxClient.
type ThreatFoxOption func(*ThreatFoxClient)

// WithThreatFoxHTTPClient sets a custom HTTP client for testing.
func WithThreatFoxHTTPClient(client *http.Client) ThreatFoxOption {
	return func(c *ThreatFoxClient) { c.httpClient = client }
}

// WithThreatFoxBaseURL overrides the default ThreatFox API URL for testing.
func WithThreatFoxBaseURL(url string) ThreatFoxOption {
	return func(c *ThreatFoxClient) { c.baseURL = url }
}

// ThreatFoxClient fetches and caches abuse.ch ThreatFox IOC matches.
type ThreatFoxClient struct {
	httpClient *http.Client
	authKey    string
	baseURL    string
	mu         sync.RWMutex
	cache      map[string]threatFoxEntry
}

// NewThreatFoxClient creates a new ThreatFox client with the given Auth-Key.
func NewThreatFoxClient(authKey string, opts ...ThreatFoxOption) *ThreatFoxClient {
	c := &ThreatFoxClient{
		httpClient: &http.Client{Timeout: 30 * time.Second},
		authKey:    authKey,
		baseURL:    threatFoxBaseURL,
		cache:      make(map[string]threatFoxEntry),
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// SearchIOC returns the highest-confidence ThreatFox match for the exact IOC.
func (c *ThreatFoxClient) SearchIOC(ctx context.Context, term string) (*ThreatFoxMatch, error) {
	c.mu.RLock()
	if entry, ok := c.cache[term]; ok && !entry.isExpired() {
		c.mu.RUnlock()
		return entry.match, nil
	}
	c.mu.RUnlock()

	match, err := c.fetchIOC(ctx, term)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	c.cache[term] = threatFoxEntry{match: match, cachedAt: time.Now()}
	c.mu.Unlock()

	return match, nil
}

func (c *ThreatFoxClient) fetchIOC(ctx context.Context, term string) (*ThreatFoxMatch, error) {
	body, err := json.Marshal(map[string]any{
		"query":       "search_ioc",
		"search_term": term,
		"exact_match": true,
	})
	if err != nil {
		return nil, fmt.Errorf("threatfox: encoding request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("threatfox: building request for %s: %w", term, err)
	}
	req.Header.Set("Auth-Key", c.authKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("threatfox: searching %s: %w", term, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests {
		c.mu.RLock()
		if entry, ok := c.cache[term]; ok {
			c.mu.RUnlock()
			return entry.match, nil
		}
		c.mu.RUnlock()
		return nil, nil
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("threatfox: searching %s: API returned status %d", term, resp.StatusCode)
	}

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 5<<20))
	if err != nil {
		return nil, fmt.Errorf("threatfox: reading response for %s: %w", term, err)
	}

	var raw threatFoxAPIResponse
	if err := json.Unmarshal(respBody, &raw); err != nil {
		return nil, fmt.Errorf("threatfox: parsing response for %s: %w", term, err)
	}
	if raw.QueryStatus == "no_result" || len(raw.Data) == 0 {
		return nil, nil
	}
	if raw.QueryStatus != "ok" {
		return nil, fmt.Errorf("threatfox: search for %s returned %q", term, raw.QueryStatus)
	}

	best := raw.Data[0]
	for _, candidate := range raw.Data[1:] {
		if candidate.ConfidenceLevel > best.ConfidenceLevel || (candidate.ConfidenceLevel == best.ConfidenceLevel && candidate.IOC < best.IOC) {
			best = candidate
		}
	}
	best.Tags = uniqueSortedStrings(best.Tags)
	return &best, nil
}

func uniqueSortedStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		set[value] = struct{}{}
	}
	if len(set) == 0 {
		return nil
	}
	result := make([]string, 0, len(set))
	for value := range set {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

// InvalidateCache removes all cached entries, forcing fresh fetches on next call.
func (c *ThreatFoxClient) InvalidateCache() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache = make(map[string]threatFoxEntry)
}
