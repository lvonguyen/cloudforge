package main

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"cloudforge/internal/api"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
)

// FindingComment represents a comment on a finding.
type FindingComment struct {
	ID        string    `json:"id"`
	FindingID string    `json:"finding_id"`
	Author    string    `json:"author"`
	Body      string    `json:"body"`
	CreatedAt time.Time `json:"created_at"`
}

// CommentsStore is a thread-safe in-memory store for finding comments.
type CommentsStore struct {
	mu       sync.RWMutex
	comments map[string][]FindingComment // keyed by finding ID
}

// NewCommentsStore creates an empty comments store.
func NewCommentsStore() *CommentsStore {
	return &CommentsStore{comments: make(map[string][]FindingComment)}
}

// maxCommentBodyLen caps the comment body length.
const maxCommentBodyLen = 4096

// listComments returns all comments for a finding.
func (s *Server) listComments(w http.ResponseWriter, r *http.Request) {
	ctx, span := otel.Tracer("cloudforge.api").Start(r.Context(), "handler.listComments")
	defer span.End()
	r = r.WithContext(ctx)

	findingID := mux.Vars(r)["id"]
	span.SetAttributes(attribute.String("finding.id", findingID))

	s.comments.mu.RLock()
	comments := s.comments.comments[findingID]
	s.comments.mu.RUnlock()

	if comments == nil {
		comments = []FindingComment{}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(comments)
}

// addComment creates a new comment on a finding.
func (s *Server) addComment(w http.ResponseWriter, r *http.Request) {
	ctx, span := otel.Tracer("cloudforge.api").Start(r.Context(), "handler.addComment")
	defer span.End()
	r = r.WithContext(ctx)

	findingID := mux.Vars(r)["id"]
	span.SetAttributes(attribute.String("finding.id", findingID))

	claims, ok := api.GetClaimsFromContext(r.Context())
	if !ok || claims.Subject == "" {
		writeErrorResponse(w, "authentication required", http.StatusUnauthorized)
		return
	}

	var body struct {
		Body string `json:"body"`
	}
	if !s.decodeJSONBody(w, r, &body) {
		return
	}
	if body.Body == "" {
		writeErrorResponse(w, "comment body is required", http.StatusBadRequest)
		return
	}
	if len(body.Body) > maxCommentBodyLen {
		writeErrorResponse(w, "comment body exceeds maximum length", http.StatusBadRequest)
		return
	}

	comment := FindingComment{
		ID:        uuid.New().String(),
		FindingID: findingID,
		Author:    claims.Subject,
		Body:      body.Body,
		CreatedAt: time.Now().UTC(),
	}

	s.comments.mu.Lock()
	s.comments.comments[findingID] = append(s.comments.comments[findingID], comment)
	s.comments.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(comment)
}

// deleteComment removes a comment by ID. Admin only.
func (s *Server) deleteComment(w http.ResponseWriter, r *http.Request) {
	ctx, span := otel.Tracer("cloudforge.api").Start(r.Context(), "handler.deleteComment")
	defer span.End()
	r = r.WithContext(ctx)

	vars := mux.Vars(r)
	findingID := vars["id"]
	commentID := vars["commentId"]
	span.SetAttributes(
		attribute.String("finding.id", findingID),
		attribute.String("comment.id", commentID),
	)

	claims, ok := api.GetClaimsFromContext(r.Context())
	if !ok {
		writeErrorResponse(w, "authentication required", http.StatusUnauthorized)
		return
	}
	if api.RoleFromClaims(claims) != api.RoleAdmin {
		writeErrorResponse(w, "admin role required", http.StatusForbidden)
		return
	}

	s.comments.mu.Lock()
	defer s.comments.mu.Unlock()

	comments := s.comments.comments[findingID]
	for i, c := range comments {
		if c.ID == commentID {
			s.comments.comments[findingID] = append(comments[:i], comments[i+1:]...)
			w.WriteHeader(http.StatusNoContent)
			return
		}
	}

	writeErrorResponse(w, "comment not found", http.StatusNotFound)
}
