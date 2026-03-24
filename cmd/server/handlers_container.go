package main

import (
	"encoding/json"
	"net/http"
	"regexp"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
)

// validImageRef matches OCI-compliant image references.
var validImageRef = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._\-/:]*$`)

func validateImageRef(image string) bool {
	return len(image) <= 255 && validImageRef.MatchString(image)
}

func (s *Server) scanContainer(w http.ResponseWriter, r *http.Request) {
	ctx, span := otel.Tracer("aegis.api").Start(r.Context(), "handler.scanContainer")
	defer span.End()
	r = r.WithContext(ctx)

	image := r.URL.Query().Get("image")
	if image == "" {
		writeErrorResponse(w, "image query parameter is required", http.StatusBadRequest)
		return
	}
	if !validateImageRef(image) {
		writeErrorResponse(w, "invalid image reference", http.StatusBadRequest)
		return
	}
	tag := r.URL.Query().Get("tag")
	if tag == "" {
		tag = "latest"
	}

	span.SetAttributes(
		attribute.String("container.image", image),
		attribute.String("container.tag", tag),
	)

	scanner := s.containerScanner
	result, err := scanner.ScanImage(r.Context(), image, tag)
	if err != nil {
		s.writeInternalError(w, err, "container scan")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(result)
}

func (s *Server) checkAdmission(w http.ResponseWriter, r *http.Request) {
	ctx, span := otel.Tracer("aegis.api").Start(r.Context(), "handler.checkAdmission")
	defer span.End()
	r = r.WithContext(ctx)

	image := r.URL.Query().Get("image")
	if image == "" {
		writeErrorResponse(w, "image query parameter is required", http.StatusBadRequest)
		return
	}
	if !validateImageRef(image) {
		writeErrorResponse(w, "invalid image reference", http.StatusBadRequest)
		return
	}
	tag := r.URL.Query().Get("tag")
	if tag == "" {
		tag = "latest"
	}
	namespace := r.URL.Query().Get("namespace")
	if namespace == "" {
		namespace = "default"
	}

	span.SetAttributes(
		attribute.String("container.image", image),
		attribute.String("container.tag", tag),
		attribute.String("container.namespace", namespace),
	)

	scanner := s.containerScanner
	decision, err := scanner.CheckAdmission(r.Context(), image, tag, namespace)
	if err != nil {
		s.writeInternalError(w, err, "admission check")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(decision)
}
