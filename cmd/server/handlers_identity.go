package main

import (
	"encoding/json"
	"errors"
	"net/http"

	"aegis/internal/identity"

	"github.com/gorilla/mux"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
)

func (s *Server) listIdentityUsers(w http.ResponseWriter, r *http.Request) {
	ctx, span := otel.Tracer("aegis.api").Start(r.Context(), "handler.listIdentityUsers")
	defer span.End()
	r = r.WithContext(ctx)

	provider := r.URL.Query().Get("provider")
	if provider == "" {
		provider = "okta"
	}
	span.SetAttributes(attribute.String("identity.provider", provider))

	users, providerName, err := s.identitySvc.ListUsers(r.Context(), provider, identity.UserFilter{})
	if err != nil {
		writeErrorResponse(w, "failed to list users", http.StatusBadRequest)
		return
	}

	span.SetAttributes(attribute.Int("identity.users_count", len(users)))

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"provider": providerName,
		"users":    users,
		"count":    len(users),
	})
}

func (s *Server) getIdentityUserRisk(w http.ResponseWriter, r *http.Request) {
	ctx, span := otel.Tracer("aegis.api").Start(r.Context(), "handler.getIdentityUserRisk")
	defer span.End()
	r = r.WithContext(ctx)

	vars := mux.Vars(r)
	userID := vars["id"]
	span.SetAttributes(attribute.String("identity.user_id", userID))

	provider := r.URL.Query().Get("provider")
	if provider == "" {
		provider = "okta"
	}
	span.SetAttributes(attribute.String("identity.provider", provider))

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
