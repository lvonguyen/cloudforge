package main

import (
	"encoding/json"
	"net/http"

	"cloudforge/internal/container"
)

func (s *Server) scanContainer(w http.ResponseWriter, r *http.Request) {
	image := r.URL.Query().Get("image")
	if image == "" {
		writeErrorResponse(w, "image query parameter is required", http.StatusBadRequest)
		return
	}
	tag := r.URL.Query().Get("tag")
	if tag == "" {
		tag = "latest"
	}

	scanner := container.NewScanner("memory")
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
	tag := r.URL.Query().Get("tag")
	if tag == "" {
		tag = "latest"
	}
	namespace := r.URL.Query().Get("namespace")
	if namespace == "" {
		namespace = "default"
	}

	scanner := container.NewScanner("memory")
	decision, err := scanner.CheckAdmission(r.Context(), image, tag, namespace)
	if err != nil {
		s.writeInternalError(w, err, "admission check")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(decision)
}
