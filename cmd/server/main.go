package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	"github.com/yourusername/cloudforge/internal/grc"
)

// Config holds application configuration
type Config struct {
	Port        string
	GRCProvider grc.ProviderType
}

// Server holds the application state
type Server struct {
	config      Config
	grcProvider grc.GRCProvider
	router      *mux.Router
}

func main() {
	// Load configuration
	cfg := Config{
		Port:        getEnv("PORT", "8080"),
		GRCProvider: grc.ProviderType(getEnv("GRC_PROVIDER", "memory")),
	}

	// Initialize GRC provider
	grcProvider, err := grc.NewProvider(grc.Config{
		Type: cfg.GRCProvider,
	})
	if err != nil {
		log.Fatalf("Failed to initialize GRC provider: %v", err)
	}

	// Create server
	srv := &Server{
		config:      cfg,
		grcProvider: grcProvider,
		router:      mux.NewRouter(),
	}

	// Setup routes
	srv.setupRoutes()

	// Create HTTP server
	httpServer := &http.Server{
		Addr:         fmt.Sprintf(":%s", cfg.Port),
		Handler:      srv.router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server in goroutine
	go func() {
		log.Printf("CloudForge API server starting on port %s", cfg.Port)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down server...")

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := httpServer.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	log.Println("Server stopped")
}

func (s *Server) setupRoutes() {
	// Health check
	s.router.HandleFunc("/health", s.healthCheck).Methods("GET")

	// API v1 routes
	api := s.router.PathPrefix("/api/v1").Subrouter()

	// Exception management
	api.HandleFunc("/exceptions", s.createException).Methods("POST")
	api.HandleFunc("/exceptions/{id}", s.getException).Methods("GET")
	api.HandleFunc("/exceptions/{id}/approve", s.submitApproval).Methods("POST")
	api.HandleFunc("/exceptions/pending", s.getPendingApprovals).Methods("GET")
	api.HandleFunc("/exceptions/expiring", s.getExpiringExceptions).Methods("GET")
	api.HandleFunc("/applications/{appId}/exceptions", s.getExceptionsByApp).Methods("GET")

	// Policy validation (called by Terraform/provisioning)
	api.HandleFunc("/validate/exception", s.validateException).Methods("POST")
}

func (s *Server) healthCheck(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "healthy",
		"version": "0.1.0",
	})
}

func (s *Server) createException(w http.ResponseWriter, r *http.Request) {
	var req grc.ExceptionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	created, err := s.grcProvider.CreateException(r.Context(), &req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(created)
}

func (s *Server) getException(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	exc, err := s.grcProvider.GetException(r.Context(), id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(exc)
}

func (s *Server) submitApproval(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	var approver grc.Approver
	if err := json.NewDecoder(r.Body).Decode(&approver); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := s.grcProvider.SubmitApproval(r.Context(), id, approver); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "approval recorded"})
}

func (s *Server) getPendingApprovals(w http.ResponseWriter, r *http.Request) {
	email := r.URL.Query().Get("approver_email")
	if email == "" {
		http.Error(w, "approver_email query parameter required", http.StatusBadRequest)
		return
	}

	pending, err := s.grcProvider.GetPendingApprovals(r.Context(), email)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(pending)
}

func (s *Server) getExpiringExceptions(w http.ResponseWriter, r *http.Request) {
	expiring, err := s.grcProvider.GetExpiringExceptions(r.Context(), 30)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(expiring)
}

func (s *Server) getExceptionsByApp(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	appID := vars["appId"]

	exceptions, err := s.grcProvider.GetExceptionsByApplication(r.Context(), appID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(exceptions)
}

// ValidateExceptionRequest is the request body for exception validation
type ValidateExceptionRequest struct {
	ApplicationID string `json:"application_id"`
	PolicyCode    string `json:"policy_code"`
}

func (s *Server) validateException(w http.ResponseWriter, r *http.Request) {
	var req ValidateExceptionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	validation, err := s.grcProvider.ValidateException(r.Context(), req.ApplicationID, req.PolicyCode)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(validation)
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
