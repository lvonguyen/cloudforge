package main

import (
	"encoding/json"
	"net/http"
	"os"
	"regexp"
)

// validImageRef matches OCI-compliant image references.
var validImageRef = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._\-/:]*$`)

func validateImageRef(image string) bool {
	return len(image) <= 255 && validImageRef.MatchString(image)
}

func containerScannerProvider() string {
	if p := os.Getenv("CONTAINER_SCANNER"); p != "" {
		return p
	}
	return "memory"
}

func (s *Server) scanContainer(w http.ResponseWriter, r *http.Request) {
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

	scanner := s.containerScanner
	decision, err := scanner.CheckAdmission(r.Context(), image, tag, namespace)
	if err != nil {
		s.writeInternalError(w, err, "admission check")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(decision)
}
