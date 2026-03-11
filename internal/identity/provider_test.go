package identity

import (
	"context"
	"errors"
	"testing"
)

// Verify both mocks satisfy the SessionProvider interface at compile time.
var _ SessionProvider = (*MockOktaProvider)(nil)
var _ SessionProvider = (*MockEntraIDProvider)(nil)

// =============================================================================
// OktaProvider tests
// =============================================================================

func TestMockOktaProvider_GetUser_ReturnsExpectedStructure(t *testing.T) {
	p := NewMockOktaProvider()
	ctx := context.Background()

	u, err := p.GetUser(ctx, "00u1a2b3c4d5e6f7g8h9")
	if err != nil {
		t.Fatalf("GetUser returned unexpected error: %v", err)
	}
	if u.Email != "alice@example.com" {
		t.Errorf("expected Email=%q, got %q", "alice@example.com", u.Email)
	}
	if u.Status != "active" {
		t.Errorf("expected Status=active, got %q", u.Status)
	}
	if !u.MFAEnabled {
		t.Error("expected MFAEnabled=true")
	}
	if len(u.Groups) == 0 {
		t.Error("expected at least one group membership")
	}
	if u.Attributes["provider"] != "okta" {
		t.Errorf("expected provider=okta, got %q", u.Attributes["provider"])
	}
}

func TestMockOktaProvider_GetUser_NotFound(t *testing.T) {
	p := NewMockOktaProvider()
	ctx := context.Background()

	_, err := p.GetUser(ctx, "nonexistent-id")
	if err == nil {
		t.Fatal("expected error for unknown user ID, got nil")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestMockOktaProvider_ListGroupMemberships_AdminUser(t *testing.T) {
	p := NewMockOktaProvider()
	ctx := context.Background()

	memberships, err := p.ListGroupMemberships(ctx, "00u1a2b3c4d5e6f7g8h9")
	if err != nil {
		t.Fatalf("ListGroupMemberships returned unexpected error: %v", err)
	}
	if len(memberships) == 0 {
		t.Fatal("expected at least one group membership")
	}

	hasAdmin := false
	for _, m := range memberships {
		if m.GroupName == "cloudforge-admin" {
			hasAdmin = true
			if m.Role != "admin" {
				t.Errorf("expected Role=admin for cloudforge-admin, got %q", m.Role)
			}
		}
		if m.GroupID == "" {
			t.Error("expected non-empty GroupID")
		}
	}
	if !hasAdmin {
		t.Error("expected alice to be in cloudforge-admin group")
	}
}

func TestMockOktaProvider_ValidateSession_ValidToken(t *testing.T) {
	p := NewMockOktaProvider()
	ctx := context.Background()

	// Mock treats user ID as token.
	u, err := p.ValidateSession(ctx, "00u1a2b3c4d5e6f7g8h9")
	if err != nil {
		t.Fatalf("ValidateSession returned unexpected error: %v", err)
	}
	if u.Email != "alice@example.com" {
		t.Errorf("expected Email=%q, got %q", "alice@example.com", u.Email)
	}
}

func TestMockOktaProvider_ValidateSession_InvalidToken(t *testing.T) {
	p := NewMockOktaProvider()
	ctx := context.Background()

	_, err := p.ValidateSession(ctx, "invalid-token")
	if err == nil {
		t.Fatal("expected error for invalid token, got nil")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestMockOktaProvider_ValidateSession_EmptyTokenError(t *testing.T) {
	p := NewMockOktaProvider()
	ctx := context.Background()

	_, err := p.ValidateSession(ctx, "")
	if err == nil {
		t.Fatal("expected error for empty token, got nil")
	}
}

// =============================================================================
// EntraIDProvider tests
// =============================================================================

func TestMockEntraIDProvider_GetUser_ReturnsExpectedStructure(t *testing.T) {
	p := NewMockEntraIDProvider()
	ctx := context.Background()

	u, err := p.GetUser(ctx, "a1b2c3d4-e5f6-7890-abcd-ef1234567890")
	if err != nil {
		t.Fatalf("GetUser returned unexpected error: %v", err)
	}
	if u.Email != "carol@example.com" {
		t.Errorf("expected Email=%q, got %q", "carol@example.com", u.Email)
	}
	if u.Status != "active" {
		t.Errorf("expected Status=active, got %q", u.Status)
	}
	if u.Attributes["provider"] != "entra_id" {
		t.Errorf("expected provider=entra_id, got %q", u.Attributes["provider"])
	}
	if len(u.Groups) == 0 {
		t.Error("expected at least one group membership")
	}
}

func TestMockEntraIDProvider_GetUser_NotFound(t *testing.T) {
	p := NewMockEntraIDProvider()
	ctx := context.Background()

	_, err := p.GetUser(ctx, "nonexistent-uuid")
	if err == nil {
		t.Fatal("expected error for unknown user ID, got nil")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestMockEntraIDProvider_ListGroupMemberships_AdminUser(t *testing.T) {
	p := NewMockEntraIDProvider()
	ctx := context.Background()

	memberships, err := p.ListGroupMemberships(ctx, "a1b2c3d4-e5f6-7890-abcd-ef1234567890")
	if err != nil {
		t.Fatalf("ListGroupMemberships returned unexpected error: %v", err)
	}
	if len(memberships) == 0 {
		t.Fatal("expected at least one group membership")
	}

	hasAdmin := false
	for _, m := range memberships {
		if m.GroupName == "sg-cloudforge-admin" {
			hasAdmin = true
			if m.Role != "admin" {
				t.Errorf("expected Role=admin for sg-cloudforge-admin, got %q", m.Role)
			}
			// Entra ID groups should have UUID-format IDs.
			if len(m.GroupID) < 10 {
				t.Errorf("expected UUID-format GroupID, got %q", m.GroupID)
			}
		}
	}
	if !hasAdmin {
		t.Error("expected carol to be in sg-cloudforge-admin group")
	}
}

func TestMockEntraIDProvider_ValidateSession_ValidToken(t *testing.T) {
	p := NewMockEntraIDProvider()
	ctx := context.Background()

	u, err := p.ValidateSession(ctx, "a1b2c3d4-e5f6-7890-abcd-ef1234567890")
	if err != nil {
		t.Fatalf("ValidateSession returned unexpected error: %v", err)
	}
	if u.Email != "carol@example.com" {
		t.Errorf("expected Email=%q, got %q", "carol@example.com", u.Email)
	}
}

func TestMockEntraIDProvider_ValidateSession_InvalidToken(t *testing.T) {
	p := NewMockEntraIDProvider()
	ctx := context.Background()

	_, err := p.ValidateSession(ctx, "not-a-real-token")
	if err == nil {
		t.Fatal("expected error for invalid token, got nil")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

// =============================================================================
// Cross-provider tests
// =============================================================================

func TestBothProviders_ProviderNames_Distinct(t *testing.T) {
	okta := NewMockOktaProvider()
	entra := NewMockEntraIDProvider()

	if okta.Name() == entra.Name() {
		t.Errorf("expected distinct provider names, both returned %q", okta.Name())
	}
	if okta.Name() != "okta" {
		t.Errorf("expected okta, got %q", okta.Name())
	}
	if entra.Name() != "entra_id" {
		t.Errorf("expected entra_id, got %q", entra.Name())
	}
}

func TestBothProviders_ProviderSpecificGroupFormats(t *testing.T) {
	okta := NewMockOktaProvider()
	entra := NewMockEntraIDProvider()
	ctx := context.Background()

	oktaGroups, _ := okta.ListGroups(ctx, GroupFilter{})
	entraGroups, _ := entra.ListGroups(ctx, GroupFilter{})

	for _, g := range oktaGroups {
		if len(g.ID) == 0 {
			t.Error("okta group has empty ID")
		}
	}
	for _, g := range entraGroups {
		// Entra IDs are UUID-formatted (36 chars including hyphens).
		if len(g.ID) != 36 {
			t.Errorf("entra group ID %q does not look like a UUID (len=%d)", g.ID, len(g.ID))
		}
	}
}
