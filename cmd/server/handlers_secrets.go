package main

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
)

func (s *Server) listSecrets(w http.ResponseWriter, r *http.Request) {
	provider := s.secretsProvider
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

func (s *Server) scanSecrets(w http.ResponseWriter, r *http.Request) {
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

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"findings": findings,
		"count":    len(findings),
	})
}
