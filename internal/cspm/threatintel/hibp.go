package threatintel

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

const (
	hibpBaseURL  = "https://haveibeenpwned.com/api/v3/"
	hibpCacheTTL = 24 * time.Hour
	hibpMinDelay = 6 * time.Second // 10 req/min = 1 per 6s
)

// HIBPBreach represents a single breach record from HIBP.
type HIBPBreach struct {
	Name       string `json:"Name"`
	Domain     string `json:"Domain"`
	BreachDate string `json:"BreachDate"`
}

// hibpEntry is a cached HIBP result with expiry.
type hibpEntry struct {
	breachCount int
	cachedAt    time.Time
}

func (e hibpEntry) isExpired() bool {
	return time.Since(e.cachedAt) > hibpCacheTTL
}

// HIBPOption configures a HIBPClient.
type HIBPOption func(*HIBPClient)

// WithHIBPHTTPClient sets a custom HTTP client (for testing).
func WithHIBPHTTPClient(client *http.Client) HIBPOption {
	return func(c *HIBPClient) { c.httpClient = client }
}

// WithHIBPBaseURL overrides the default HIBP API base URL (for testing).
func WithHIBPBaseURL(url string) HIBPOption {
	return func(c *HIBPClient) { c.baseURL = url }
}

// HIBPClient fetches and caches breach counts from the Have I Been Pwned API.
type HIBPClient struct {
	httpClient *http.Client
	apiKey     string
	baseURL    string
	mu         sync.RWMutex
	cache      map[string]hibpEntry

	// Rate limiting
	rateMu   sync.Mutex
	lastCall time.Time
}

// NewHIBPClient creates a new HIBP client with the given API key.
func NewHIBPClient(apiKey string, opts ...HIBPOption) *HIBPClient {
	c := &HIBPClient{
		httpClient: &http.Client{Timeout: 30 * time.Second},
		apiKey:     apiKey,
		baseURL:    hibpBaseURL,
		cache:      make(map[string]hibpEntry),
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// GetBreachCount returns the number of known breaches for the given email.
// Returns 0 if the email has not been found in any breach.
func (c *HIBPClient) GetBreachCount(ctx context.Context, email string) (int, error) {
	c.mu.RLock()
	if entry, ok := c.cache[email]; ok && !entry.isExpired() {
		c.mu.RUnlock()
		return entry.breachCount, nil
	}
	c.mu.RUnlock()

	// Rate limit: wait if last call was less than hibpMinDelay ago
	c.rateMu.Lock()
	elapsed := time.Since(c.lastCall)
	if elapsed < hibpMinDelay {
		wait := hibpMinDelay - elapsed
		c.rateMu.Unlock()
		select {
		case <-time.After(wait):
		case <-ctx.Done():
			return 0, ctx.Err()
		}
		c.rateMu.Lock()
	}
	c.lastCall = time.Now()
	c.rateMu.Unlock()

	count, err := c.fetchBreachCount(ctx, email)
	if err != nil {
		return 0, err
	}

	c.mu.Lock()
	c.cache[email] = hibpEntry{breachCount: count, cachedAt: time.Now()}
	c.mu.Unlock()

	return count, nil
}

func (c *HIBPClient) fetchBreachCount(ctx context.Context, email string) (int, error) {
	reqURL := c.baseURL + "breachedaccount/" + email + "?truncateResponse=true"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return 0, fmt.Errorf("hibp: building request: %w", err)
	}
	req.Header.Set("hibp-api-key", c.apiKey)
	req.Header.Set("User-Agent", "CloudAegis-ThreatIntel")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("hibp: request for %s: %w", email, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return 0, nil
	}

	if resp.StatusCode == http.StatusTooManyRequests {
		c.mu.RLock()
		if entry, ok := c.cache[email]; ok {
			c.mu.RUnlock()
			return entry.breachCount, nil
		}
		c.mu.RUnlock()
		return 0, nil
	}

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("hibp: API returned status %d for %s", resp.StatusCode, email)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MB cap
	if err != nil {
		return 0, fmt.Errorf("hibp: reading response: %w", err)
	}

	var breaches []HIBPBreach
	if err := json.Unmarshal(body, &breaches); err != nil {
		return 0, fmt.Errorf("hibp: parsing response: %w", err)
	}

	return len(breaches), nil
}

// InvalidateCache removes all cached entries, forcing fresh fetches on next call.
func (c *HIBPClient) InvalidateCache() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache = make(map[string]hibpEntry)
}
