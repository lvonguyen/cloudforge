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

	users, providerName, err := s.identitySvc.ListUsers(r.Context(), provider, identity.UserFilter{})
	if err != nil {
		writeErrorResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"provider": providerName,
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

	risk, err := s.identitySvc.GetUserRiskScore(r.Context(), provider, userID)
	if err != nil {
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
