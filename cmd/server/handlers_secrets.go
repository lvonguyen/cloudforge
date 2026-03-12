package main

import (
	"encoding/json"
	"net/http"

	"cloudforge/internal/secrets"

	"github.com/gorilla/mux"
)

func (s *Server) listSecrets(w http.ResponseWriter, r *http.Request) {
	provider := secrets.NewMemoryProvider("demo")
	prefix := r.URL.Query().Get("prefix")

	paths, err := provider.ListSecrets(r.Context(), prefix)
	if err != nil {
		s.writeInternalError(w, err, "list secrets")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"provider": provider.Name(),
		"paths":    paths,
		"count":    len(paths),
	})
}

func (s *Server) getSecret(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	path := vars["path"]

	provider := secrets.NewMemoryProvider("demo")
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

func (s *Server) scanSecrets(w http.ResponseWriter, r *http.Request) {
	mgr := secrets.NewManager(s.logger)
	content := r.URL.Query().Get("content")
	if content == "" {
		writeErrorResponse(w, "content query parameter is required", http.StatusBadRequest)
		return
	}

	findings := mgr.ScanForSecrets(content)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"findings": findings,
		"count":    len(findings),
	})
}
