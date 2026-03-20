package threatintel

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"sync"
	"time"
)

const (
	otxBaseURL  = "https://otx.alienvault.com/api/v1/"
	otxCacheTTL = 12 * time.Hour
)

// OTXIndicatorType is the type of indicator to query.
type OTXIndicatorType string

const (
	OTXTypeIPv4     OTXIndicatorType = "IPv4"
	OTXTypeDomain   OTXIndicatorType = "domain"
	OTXTypeHostname OTXIndicatorType = "hostname"
)

// OTXIndicator holds the pulse match data for an indicator.
type OTXIndicator struct {
	PulseCount int      `json:"pulse_count"`
	Tags       []string `json:"tags,omitempty"`
}

// otxAPIResponse is the raw JSON shape from the OTX general endpoint.
type otxAPIResponse struct {
	PulseInfo struct {
		Count  int `json:"count"`
		Pulses []struct {
			Tags []string `json:"tags"`
		} `json:"pulses"`
	} `json:"pulse_info"`
}

// otxEntry is a cached OTX result with expiry.
type otxEntry struct {
	indicator *OTXIndicator
	cachedAt  time.Time
}

func (e otxEntry) isExpired() bool {
	return time.Since(e.cachedAt) > otxCacheTTL
}

// OTXOption configures an OTXClient.
type OTXOption func(*OTXClient)

// WithOTXHTTPClient sets a custom HTTP client (for testing).
func WithOTXHTTPClient(client *http.Client) OTXOption {
	return func(c *OTXClient) { c.httpClient = client }
}

// WithOTXBaseURL overrides the default OTX API base URL (for testing).
func WithOTXBaseURL(url string) OTXOption {
	return func(c *OTXClient) { c.baseURL = url }
}

// OTXClient fetches and caches indicator data from AlienVault OTX.
type OTXClient struct {
	httpClient *http.Client
	apiKey     string
	baseURL    string
	mu         sync.RWMutex
	cache      map[string]otxEntry
}

// NewOTXClient creates a new OTX client with the given API key.
func NewOTXClient(apiKey string, opts ...OTXOption) *OTXClient {
	c := &OTXClient{
		httpClient: &http.Client{Timeout: 30 * time.Second},
		apiKey:     apiKey,
		baseURL:    otxBaseURL,
		cache:      make(map[string]otxEntry),
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// GetIndicator returns OTX pulse match data for the given indicator.
func (c *OTXClient) GetIndicator(ctx context.Context, iocType OTXIndicatorType, value string) (*OTXIndicator, error) {
	cacheKey := string(iocType) + ":" + value

	c.mu.RLock()
	if entry, ok := c.cache[cacheKey]; ok && !entry.isExpired() {
		c.mu.RUnlock()
		return entry.indicator, nil
	}
	c.mu.RUnlock()

	indicator, err := c.fetchIndicator(ctx, iocType, value)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	c.cache[cacheKey] = otxEntry{indicator: indicator, cachedAt: time.Now()}
	c.mu.Unlock()

	return indicator, nil
}

func (c *OTXClient) fetchIndicator(ctx context.Context, iocType OTXIndicatorType, value string) (*OTXIndicator, error) {
	reqURL := fmt.Sprintf("%sindicators/%s/%s/general", c.baseURL, iocType, url.PathEscape(value))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("otx: building request: %w", err)
	}
	req.Header.Set("X-OTX-API-KEY", c.apiKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("otx: request for %s/%s: %w", iocType, value, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return &OTXIndicator{}, nil
	}

	if resp.StatusCode == http.StatusTooManyRequests {
		c.mu.RLock()
		if entry, ok := c.cache[string(iocType)+":"+value]; ok {
			c.mu.RUnlock()
			return entry.indicator, nil
		}
		c.mu.RUnlock()
		return &OTXIndicator{}, nil
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("otx: API returned status %d for %s/%s", resp.StatusCode, iocType, value)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 5<<20)) // 5 MB cap
	if err != nil {
		return nil, fmt.Errorf("otx: reading response: %w", err)
	}

	var raw otxAPIResponse
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("otx: parsing response: %w", err)
	}

	// Collect unique tags across all pulses, sorted for deterministic output
	tagSet := make(map[string]bool)
	for _, pulse := range raw.PulseInfo.Pulses {
		for _, tag := range pulse.Tags {
			tagSet[tag] = true
		}
	}
	tags := make([]string, 0, len(tagSet))
	for tag := range tagSet {
		tags = append(tags, tag)
	}
	sort.Strings(tags)

	return &OTXIndicator{
		PulseCount: raw.PulseInfo.Count,
		Tags:       tags,
	}, nil
}

// InvalidateCache removes all cached entries, forcing fresh fetches on next call.
func (c *OTXClient) InvalidateCache() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache = make(map[string]otxEntry)
}
