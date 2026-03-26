package webhooks

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// memoryEngine is an in-memory webhook engine for development and testing.
type memoryEngine struct {
	mu         sync.RWMutex
	endpoints  map[string]*Endpoint
	deliveries []Delivery
	client     *http.Client
	logger     *zap.Logger
}

// NewMemoryEngine creates an in-memory webhook engine.
func NewMemoryEngine(logger *zap.Logger) Engine {
	return &memoryEngine{
		endpoints:  make(map[string]*Endpoint),
		deliveries: make([]Delivery, 0),
		client: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				DialContext: safeDialContext,
			},
		},
		logger: logger,
	}
}

func (e *memoryEngine) RegisterEndpoint(_ context.Context, req RegisterEndpointRequest) (*Endpoint, error) {
	if req.URL == "" {
		return nil, fmt.Errorf("url is required")
	}

	if err := validateWebhookURL(req.URL); err != nil {
		return nil, fmt.Errorf("invalid webhook URL: %w", err)
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	ep := &Endpoint{
		ID:        uuid.New().String(),
		URL:       req.URL,
		Secret:    req.Secret,
		Events:    req.Events,
		Active:    true,
		CreatedAt: time.Now().UTC(),
	}
	e.endpoints[ep.ID] = ep
	e.logger.Info("webhook endpoint registered", zap.String("id", ep.ID), zap.String("url", req.URL))
	return ep, nil
}

func (e *memoryEngine) ListEndpoints(_ context.Context) ([]Endpoint, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	result := make([]Endpoint, 0, len(e.endpoints))
	for _, ep := range e.endpoints {
		result = append(result, *ep)
	}
	return result, nil
}

func (e *memoryEngine) DeleteEndpoint(_ context.Context, id string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if _, ok := e.endpoints[id]; !ok {
		return fmt.Errorf("endpoint %q not found", id)
	}
	delete(e.endpoints, id)
	e.logger.Info("webhook endpoint deleted", zap.String("id", id))
	return nil
}

func (e *memoryEngine) DeliverAsync(_ context.Context, event Event) {
	e.mu.RLock()
	targets := make([]*Endpoint, 0)
	for _, ep := range e.endpoints {
		if !ep.Active {
			continue
		}
		if len(ep.Events) == 0 || containsEvent(ep.Events, string(event.Type)) {
			targets = append(targets, ep)
		}
	}
	e.mu.RUnlock()

	for _, ep := range targets {
		go e.deliver(ep, event)
	}
}

func (e *memoryEngine) deliver(ep *Endpoint, event Event) {
	start := time.Now()
	d := Delivery{
		ID:          uuid.New().String(),
		EndpointID:  ep.ID,
		EventID:     event.ID,
		EventType:   event.Type,
		Status:      DeliveryPending,
		AttemptedAt: start,
	}

	body, err := json.Marshal(event)
	if err != nil {
		d.Status = DeliveryFailed
		d.Error = fmt.Sprintf("marshal: %v", err)
		e.recordDelivery(d)
		return
	}

	req, err := http.NewRequest(http.MethodPost, ep.URL, bytes.NewReader(body))
	if err != nil {
		d.Status = DeliveryFailed
		d.Error = fmt.Sprintf("request: %v", err)
		e.recordDelivery(d)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Aegis-Event", string(event.Type))

	if ep.Secret != "" {
		mac := hmac.New(sha256.New, []byte(ep.Secret))
		mac.Write(body)
		sig := hex.EncodeToString(mac.Sum(nil))
		req.Header.Set("X-Aegis-Signature", sig)
	}

	resp, err := e.client.Do(req)
	d.DurationMs = time.Since(start).Milliseconds()
	if err != nil {
		d.Status = DeliveryFailed
		d.Error = err.Error()
		e.recordDelivery(d)
		return
	}
	defer resp.Body.Close()

	d.StatusCode = resp.StatusCode
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		d.Status = DeliverySuccess
	} else {
		d.Status = DeliveryFailed
		d.Error = fmt.Sprintf("HTTP %d", resp.StatusCode)
	}
	e.recordDelivery(d)
}

func (e *memoryEngine) recordDelivery(d Delivery) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.deliveries = append(e.deliveries, d)
	if d.Status == DeliveryFailed {
		e.logger.Warn("webhook delivery failed",
			zap.String("endpoint_id", d.EndpointID),
			zap.String("error", d.Error),
		)
	}
}

func (e *memoryEngine) ListDeliveries(_ context.Context, endpointID string) ([]Delivery, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var result []Delivery
	for _, d := range e.deliveries {
		if d.EndpointID == endpointID {
			result = append(result, d)
		}
	}
	return result, nil
}

func containsEvent(events []string, target string) bool {
	for _, e := range events {
		if e == target {
			return true
		}
	}
	return false
}

// safeDialContext wraps net.Dialer with a Control callback that rejects private/internal IPs
// after DNS resolution, preventing DNS rebinding attacks on webhook delivery.
func safeDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	d := &net.Dialer{
		Timeout: 10 * time.Second,
		Control: func(network, address string, c syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			ip := net.ParseIP(host)
			if ip == nil {
				return nil
			}
			if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.Equal(net.ParseIP("169.254.169.254")) {
				return fmt.Errorf("webhook delivery to private IP %s blocked", ip)
			}
			return nil
		},
	}
	return d.DialContext(ctx, network, addr)
}

// validateWebhookURL rejects URLs that target internal/private networks (SSRF protection).
func validateWebhookURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("malformed URL: %w", err)
	}

	scheme := strings.ToLower(u.Scheme)
	if scheme != "https" {
		return fmt.Errorf("unsupported scheme %q: webhook URLs must use https", scheme)
	}

	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("missing hostname")
	}

	// Block well-known internal hostnames
	lower := strings.ToLower(host)
	if lower == "localhost" || lower == "metadata.google.internal" {
		return fmt.Errorf("internal hostname %q is not allowed", host)
	}

	ip := net.ParseIP(host)
	if ip != nil {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			return fmt.Errorf("private/internal IP %s is not allowed", ip)
		}
		// Block AWS metadata endpoint
		if ip.Equal(net.ParseIP("169.254.169.254")) {
			return fmt.Errorf("metadata endpoint %s is not allowed", ip)
		}
	}

	return nil
}
