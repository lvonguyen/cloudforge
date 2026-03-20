package main

import (
	"encoding/json"
	"net/http"

	"aegis/internal/compliance"

	"github.com/gorilla/mux"
)

// getCompliancePosture returns all registered frameworks with control counts.
func (s *Server) getCompliancePosture(w http.ResponseWriter, r *http.Request) {
	type frameworkSummary struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		Version     string `json:"version"`
		Description string `json:"description"`
		Sector      string `json:"sector"`
		Controls    int    `json:"controls"`
	}

	frameworks := s.complianceMgr.GetFrameworksForSector(compliance.SectorGeneral)
	result := make([]frameworkSummary, 0, len(frameworks))
	for _, fw := range frameworks {
		result = append(result, frameworkSummary{
			ID:          fw.ID,
			Name:        fw.Name,
			Version:     fw.Version,
			Description: fw.Description,
			Sector:      string(fw.Sector),
			Controls:    len(fw.Controls),
		})
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(result)
}

// getComplianceControls returns the controls for a specific framework.
func (s *Server) getComplianceControls(w http.ResponseWriter, r *http.Request) {
	fwID := mux.Vars(r)["fw"]
	fw, ok := s.complianceMgr.GetFramework(fwID)
	if !ok {
		writeErrorResponse(w, "framework not found", http.StatusNotFound)
		return
	}

	type controlResponse struct {
		ID          string   `json:"id"`
		Title       string   `json:"title"`
		Description string   `json:"description"`
		Section     string   `json:"section"`
		Category    string   `json:"category"`
		Severity    string   `json:"severity"`
		Keywords    []string `json:"keywords"`
	}

	controls := make([]controlResponse, 0, len(fw.Controls))
	for _, c := range fw.Controls {
		controls = append(controls, controlResponse{
			ID:          c.ID,
			Title:       c.Title,
			Description: c.Description,
			Section:     c.Section,
			Category:    c.Category,
			Severity:    c.Severity,
			Keywords:    c.Keywords,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(controls)
}
