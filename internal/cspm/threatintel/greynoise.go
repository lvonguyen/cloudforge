package threatintel

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"
)

const (
	greynoiseBaseURL  = "https://api.greynoise.io/v3/community/"
	greynoiseCacheTTL = 12 * time.Hour
	greynoiseSemSize  = 5 // max concurrent API calls for batch
)

// GreyNoiseResult holds the classification data for a single IP address.
type GreyNoiseResult struct {
	IP             string `json:"ip"`
	Noise          bool   `json:"noise"`
	Riot           bool   `json:"riot"`
	Classification string `json:"classification"` // benign, malicious, unknown
	Name           string `json:"name"`
	LastSeen       string `json:"last_seen"`
}

// greynoiseEntry is a cached GreyNoise result with expiry.
type greynoiseEntry struct {
	result   *GreyNoiseResult
	cachedAt time.Time
}

func (e greynoiseEntry) isExpired() bool {
	return time.Since(e.cachedAt) > greynoiseCacheTTL
}

// Option configures a GreyNoiseClient.
type Option func(*GreyNoiseClient)

// WithHTTPClient sets a custom HTTP client (for testing).
func WithHTTPClient(client *http.Client) Option {
	return func(c *GreyNoiseClient) {
		c.httpClient = client
	}
}

// WithBaseURL overrides the default GreyNoise API base URL (for testing).
func WithBaseURL(url string) Option {
	return func(c *GreyNoiseClient) {
		c.baseURL = url
	}
}

// GreyNoiseClient fetches and caches IP classifications from the GreyNoise Community API.
type GreyNoiseClient struct {
	httpClient *http.Client
	apiKey     string
	baseURL    string
	mu         sync.RWMutex
	cache      map[string]greynoiseEntry
}

// NewGreyNoiseClient creates a new GreyNoise client with the given API key.
func NewGreyNoiseClient(apiKey string, opts ...Option) *GreyNoiseClient {
	c := &GreyNoiseClient{
		httpClient: &http.Client{Timeout: 30 * time.Second},
		apiKey:     apiKey,
		baseURL:    greynoiseBaseURL,
		cache:      make(map[string]greynoiseEntry),
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// ClassifyIP returns the GreyNoise classification for a single IP address.
// Uses cached results when available and not expired.
func (c *GreyNoiseClient) ClassifyIP(ctx context.Context, ip string) (*GreyNoiseResult, error) {
	// Check cache
	c.mu.RLock()
	if entry, ok := c.cache[ip]; ok && !entry.isExpired() {
		c.mu.RUnlock()
		return entry.result, nil
	}
	c.mu.RUnlock()

	result, err := c.fetchIP(ctx, ip)
	if err != nil {
		return nil, err
	}

	// Cache the result
	c.mu.Lock()
	c.cache[ip] = greynoiseEntry{result: result, cachedAt: time.Now()}
	c.mu.Unlock()

	return result, nil
}

// BatchClassify returns GreyNoise classifications for multiple IPs with bounded concurrency.
func (c *GreyNoiseClient) BatchClassify(ctx context.Context, ips []string) (map[string]*GreyNoiseResult, error) {
	if len(ips) == 0 {
		return make(map[string]*GreyNoiseResult), nil
	}

	results := make(map[string]*GreyNoiseResult, len(ips))
	var toFetch []string

	// Check cache for each IP
	c.mu.RLock()
	for _, ip := range ips {
		if entry, ok := c.cache[ip]; ok && !entry.isExpired() {
			results[ip] = entry.result
		} else {
			toFetch = append(toFetch, ip)
		}
	}
	c.mu.RUnlock()

	if len(toFetch) == 0 {
		return results, nil
	}

	// Fetch uncached IPs with bounded concurrency
	type ipResult struct {
		ip  string
		res *GreyNoiseResult
		err error
	}

	sem := make(chan struct{}, greynoiseSemSize)
	ch := make(chan ipResult, len(toFetch))

	for _, ip := range toFetch {
		sem <- struct{}{}
		go func(addr string) {
			defer func() { <-sem }()
			res, err := c.fetchIP(ctx, addr)
			ch <- ipResult{ip: addr, res: res, err: err}
		}(ip)
	}

	var firstErr error
	for range toFetch {
		r := <-ch
		if r.err != nil {
			if firstErr == nil {
				firstErr = r.err
			}
			continue
		}
		results[r.ip] = r.res
		c.mu.Lock()
		c.cache[r.ip] = greynoiseEntry{result: r.res, cachedAt: time.Now()}
		c.mu.Unlock()
	}

	if firstErr != nil {
		return results, firstErr
	}
	return results, nil
}

// fetchIP makes a single HTTP request to the GreyNoise Community API.
// On 429 (rate limit), returns cached data if available or a zero-value result.
func (c *GreyNoiseClient) fetchIP(ctx context.Context, ip string) (*GreyNoiseResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+url.PathEscape(ip), nil)
	if err != nil {
		return nil, fmt.Errorf("greynoise: building request for %s: %w", ip, err)
	}
	req.Header.Set("key", c.apiKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("greynoise: classifying %s: %w", ip, err)
	}
	defer resp.Body.Close()

	// Rate limited — return cached or zero-value
	if resp.StatusCode == http.StatusTooManyRequests {
		c.mu.RLock()
		if entry, ok := c.cache[ip]; ok {
			c.mu.RUnlock()
			return entry.result, nil
		}
		c.mu.RUnlock()
		return &GreyNoiseResult{IP: ip, Classification: "unknown"}, nil
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("greynoise: classifying %s: API returned status %d", ip, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MB cap
	if err != nil {
		return nil, fmt.Errorf("greynoise: reading response for %s: %w", ip, err)
	}

	var result GreyNoiseResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("greynoise: parsing response for %s: %w", ip, err)
	}

	return &result, nil
}

// InvalidateCache removes all cached entries, forcing fresh fetches on next call.
func (c *GreyNoiseClient) InvalidateCache() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache = make(map[string]greynoiseEntry)
}
