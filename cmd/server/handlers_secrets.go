package main

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
)

func (s *Server) listSecrets(w http.ResponseWriter, r *http.Request) {
	ctx, span := otel.Tracer("aegis.api").Start(r.Context(), "handler.listSecrets")
	defer span.End()
	r = r.WithContext(ctx)

	provider := s.secretsProvider
	prefix := r.URL.Query().Get("prefix")

	paths, err := provider.ListSecrets(r.Context(), prefix)
	if err != nil {
		s.writeInternalError(w, err, "list secrets")
		return
	}

	span.SetAttributes(attribute.Int("secrets.count", len(paths)))

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"provider": provider.Name(),
		"paths":    paths,
		"count":    len(paths),
	})
}

func (s *Server) getSecret(w http.ResponseWriter, r *http.Request) {
	ctx, span := otel.Tracer("aegis.api").Start(r.Context(), "handler.getSecret")
	defer span.End()
	r = r.WithContext(ctx)

	vars := mux.Vars(r)
	path := vars["path"]
	span.SetAttributes(attribute.Int("secret.path_length", len(path)))

	provider := s.secretsProvider
	secret, err := provider.GetSecret(r.Context(), path)
	if err != nil {
		writeErrorResponse(w, "secret not found", http.StatusNotFound)
		return
	}

	// Never expose Value in API response
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"path":     secret.Path,
		"version":  secret.Version,
		"metadata": secret.Metadata,
		"created":  secret.CreatedAt,
		"updated":  secret.UpdatedAt,
	})
}

// validSecretTypes enumerates the secret categories the upload endpoint accepts.
var validSecretTypes = map[string]bool{
	"api_token":        true,
	"ssh_keypair":      true,
	"oauth_secret":     true,
	"aws_access_key":   true,
	"azure_spn":        true,
	"gcp_sa_key":       true,
	"generic_password": true,
	"certificate_pem":  true,
}

// uploadSuspectedSecret accepts a suspected secret for ephemeral analysis.
// Security invariants:
//   - TLS required (direct or via X-Forwarded-Proto)
//   - Raw content is NEVER logged or persisted to disk/DB
//   - Content reference is cleared immediately after scanning
//   - 64KB size limit to prevent abuse
func (s *Server) uploadSuspectedSecret(w http.ResponseWriter, r *http.Request) {
	ctx, span := otel.Tracer("aegis.api").Start(r.Context(), "handler.uploadSuspectedSecret")
	defer span.End()
	r = r.WithContext(ctx)

	// Enforce TLS — reject plaintext uploads of suspected secrets.
	if r.TLS == nil && r.Header.Get("X-Forwarded-Proto") != "https" {
		span.SetAttributes(attribute.Bool("security.tls_rejected", true))
		writeErrorResponse(w, "TLS required for secret upload", http.StatusForbidden)
		return
	}

	var body struct {
		SecretType string `json:"secret_type"`
		Content    string `json:"content"`
	}
	if !s.decodeJSONBody(w, r, &body) {
		return
	}

	if body.Content == "" {
		writeErrorResponse(w, "content field is required", http.StatusBadRequest)
		return
	}
	if body.SecretType == "" {
		writeErrorResponse(w, "secret_type field is required", http.StatusBadRequest)
		return
	}
	if !validSecretTypes[body.SecretType] {
		writeErrorResponse(w, "invalid secret_type", http.StatusBadRequest)
		return
	}
	// 64KB ceiling — suspected secrets shouldn't be larger than this.
	if len(body.Content) > 65536 {
		writeErrorResponse(w, "content exceeds 64KB limit", http.StatusRequestEntityTooLarge)
		return
	}

	// Scan content — ephemeral, never persisted to disk or database.
	findings := s.secretsManager.ScanForSecrets(body.Content)

	// [SECURITY] Clear the content reference immediately.
	// Go strings are immutable so we can't zero the backing array, but
	// nilling the reference allows GC to reclaim the memory promptly.
	body.Content = ""

	span.SetAttributes(
		attribute.Int("scan.findings_count", len(findings)),
		attribute.String("scan.secret_type", body.SecretType),
	)
	// [SECURITY] Never log body.Content — only metadata attributes above.

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"secret_type": body.SecretType,
		"findings":    findings,
		"count":       len(findings),
		"ephemeral":   true,
	})
}

func (s *Server) scanSecrets(w http.ResponseWriter, r *http.Request) {
	ctx, span := otel.Tracer("aegis.api").Start(r.Context(), "handler.scanSecrets")
	defer span.End()
	r = r.WithContext(ctx)

	var body struct {
		Content string `json:"content"`
	}
	if !s.decodeJSONBody(w, r, &body) {
		return
	}
	if body.Content == "" {
		writeErrorResponse(w, "content field is required", http.StatusBadRequest)
		return
	}

	mgr := s.secretsManager
	findings := mgr.ScanForSecrets(body.Content)

	span.SetAttributes(attribute.Int("scan.findings_count", len(findings)))

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"findings": findings,
		"count":    len(findings),
	})
}
