package integrations

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// MockProvider is an in-memory TicketProvider for development and testing.
type MockProvider struct {
	mu      sync.RWMutex
	tickets map[string]*Ticket // keyed by externalID
	logger  *zap.Logger
}

// NewMockProvider creates a new in-memory ticket provider.
func NewMockProvider(logger *zap.Logger) *MockProvider {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &MockProvider{
		tickets: make(map[string]*Ticket),
		logger:  logger,
	}
}

func (m *MockProvider) Name() string { return "mock" }

func (m *MockProvider) CreateTicket(_ context.Context, req CreateTicketRequest) (*Ticket, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now().UTC()
	extID := "MOCK-" + uuid.New().String()[:8]

	t := &Ticket{
		ID:         uuid.New().String(),
		ExternalID: extID,
		Provider:   "mock",
		FindingID:  req.FindingID,
		Title:      req.Title,
		Status:     TicketStatusOpen,
		Priority:   req.Priority,
		Assignee:   req.Assignee,
		URL:        fmt.Sprintf("https://mock.local/tickets/%s", extID),
		CreatedAt:  now,
		UpdatedAt:  now,
		Metadata:   req.Metadata,
	}
	m.tickets[extID] = t
	m.logger.Info("mock ticket created",
		zap.String("external_id", extID),
		zap.String("finding_id", req.FindingID),
	)
	return t, nil
}

func (m *MockProvider) GetTicket(_ context.Context, externalID string) (*Ticket, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	t, ok := m.tickets[externalID]
	if !ok {
		return nil, fmt.Errorf("ticket %q not found", externalID)
	}
	return t, nil
}

func (m *MockProvider) AddComment(_ context.Context, externalID, body string) (*CommentSync, error) {
	m.mu.RLock()
	_, ok := m.tickets[externalID]
	m.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("ticket %q not found", externalID)
	}

	return &CommentSync{
		ID:         uuid.New().String(),
		ExternalID: "comment-" + uuid.New().String()[:8],
		Body:       body,
		Author:     "aegis-bot",
		CreatedAt:  time.Now().UTC(),
	}, nil
}

func (m *MockProvider) SyncStatus(_ context.Context, externalID string) (TicketStatus, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	t, ok := m.tickets[externalID]
	if !ok {
		return "", fmt.Errorf("ticket %q not found", externalID)
	}
	return t.Status, nil
}

// GetTicketByFindingID looks up a ticket by finding ID (test helper).
func (m *MockProvider) GetTicketByFindingID(findingID string) (*Ticket, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, t := range m.tickets {
		if t.FindingID == findingID {
			return t, true
		}
	}
	return nil, false
}
