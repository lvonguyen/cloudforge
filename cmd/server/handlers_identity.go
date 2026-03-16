package main

import (
	"encoding/json"
	"errors"
	"net/http"

	"cloudforge/internal/identity"

	"github.com/gorilla/mux"
)

func (s *Server) listIdentityUsers(w http.ResponseWriter, r *http.Request) {
	provider := r.URL.Query().Get("provider")
	if provider == "" {
		provider = "okta"
	}

	p, ok := s.identityProviders[provider]
	if !ok {
		writeErrorResponse(w, "unsupported provider: use okta or entra_id", http.StatusBadRequest)
		return
	}

	users, err := p.ListUsers(r.Context(), identity.UserFilter{})
	if err != nil {
		s.writeInternalError(w, err, "list identity users")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"provider": p.Name(),
		"users":    users,
		"count":    len(users),
	})
}

func (s *Server) getIdentityUserRisk(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userID := vars["id"]

	provider := r.URL.Query().Get("provider")
	if provider == "" {
		provider = "okta"
	}

	p, ok := s.identityProviders[provider]
	if !ok {
		writeErrorResponse(w, "unsupported provider", http.StatusBadRequest)
		return
	}

	risk, err := p.GetUserRiskScore(r.Context(), userID)
	if err != nil {
		// ErrNotFound is returned by mock providers; real providers (Okta/Entra)
		// return nil error with a low-risk assessment for unknown users.
		if errors.Is(err, identity.ErrNotFound) {
			writeErrorResponse(w, "user not found", http.StatusNotFound)
			return
		}
		s.writeInternalError(w, err, "get user risk score")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(risk)
}
