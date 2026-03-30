package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/lib/pq"
)

type postgresFindingRow struct {
	ID                  string
	Source              string
	SourceFindingID     sql.NullString
	Type                string
	Title               string
	Description         sql.NullString
	ResourceType        sql.NullString
	ResourceID          sql.NullString
	ResourceName        sql.NullString
	ResourceARN         sql.NullString
	Platform            sql.NullString
	CloudProvider       string
	Region              sql.NullString
	AccountID           sql.NullString
	AccountName         sql.NullString
	EnvironmentType     sql.NullString
	StaticSeverity      string
	Severity            string
	AIRiskScore         sql.NullFloat64
	AIRiskLevel         sql.NullString
	AIRiskRationale     sql.NullString
	AIContextualFactors pq.StringArray
	CVSS                sql.NullFloat64
	CVSSVector          sql.NullString
	EPSS                sql.NullFloat64
	ExploitAvailable    bool
	CVEsRaw             []byte
	MITRETactics        pq.StringArray
	MITRETechniques     pq.StringArray
	ComplianceRaw       []byte
	Remediation         sql.NullString
	AutoRemediatable    bool
	Category            sql.NullString
	Status              string
	WorkflowStatus      sql.NullString
	Suppressed          bool
	ServiceName         sql.NullString
	LineOfBusiness      sql.NullString
	FirstFoundAt        time.Time
	LastSeenAt          sql.NullTime
	SLABreachDate       sql.NullTime
	DueDate             sql.NullTime
	DeduplicationKey    sql.NullString
	CanonicalRuleID     sql.NullString
}

func loadFindingsFromPostgres(ctx context.Context, db *sql.DB) ([]Finding, error) {
	const query = `
		SELECT
			id,
			source,
			source_finding_id,
			type,
			title,
			description,
			resource_type,
			resource_id,
			resource_name,
			resource_arn,
			COALESCE(platform, 'cloud') AS platform,
			cloud_provider,
			region,
			account_id,
			account_name,
			environment_type,
			static_severity,
			severity,
			ai_risk_score,
			ai_risk_level,
			ai_risk_rationale,
			COALESCE(ai_contextual_factors, ARRAY[]::text[]) AS ai_contextual_factors,
			cvss,
			cvss_vector,
			epss,
			COALESCE(exploit_available, FALSE) AS exploit_available,
			COALESCE(cves, '[]'::jsonb) AS cves,
			COALESCE(mitre_tactics, ARRAY[]::text[]) AS mitre_tactics,
			COALESCE(mitre_techniques, ARRAY[]::text[]) AS mitre_techniques,
			COALESCE(compliance_mappings, '[]'::jsonb) AS compliance_mappings,
			remediation,
			COALESCE(auto_remediatable, FALSE) AS auto_remediatable,
			category,
			status,
			workflow_status,
			COALESCE(suppressed, FALSE) AS suppressed,
			service_name,
			line_of_business,
			first_found_at,
			last_seen_at,
			sla_breach_date,
			due_date,
			deduplication_key,
			canonical_rule_id
		FROM findings
		ORDER BY first_found_at DESC, id ASC
	`

	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("query findings: %w", err)
	}
	defer rows.Close()

	findings := make([]Finding, 0, 1024)
	for rows.Next() {
		var row postgresFindingRow
		if err := rows.Scan(
			&row.ID,
			&row.Source,
			&row.SourceFindingID,
			&row.Type,
			&row.Title,
			&row.Description,
			&row.ResourceType,
			&row.ResourceID,
			&row.ResourceName,
			&row.ResourceARN,
			&row.Platform,
			&row.CloudProvider,
			&row.Region,
			&row.AccountID,
			&row.AccountName,
			&row.EnvironmentType,
			&row.StaticSeverity,
			&row.Severity,
			&row.AIRiskScore,
			&row.AIRiskLevel,
			&row.AIRiskRationale,
			pq.Array(&row.AIContextualFactors),
			&row.CVSS,
			&row.CVSSVector,
			&row.EPSS,
			&row.ExploitAvailable,
			&row.CVEsRaw,
			pq.Array(&row.MITRETactics),
			pq.Array(&row.MITRETechniques),
			&row.ComplianceRaw,
			&row.Remediation,
			&row.AutoRemediatable,
			&row.Category,
			&row.Status,
			&row.WorkflowStatus,
			&row.Suppressed,
			&row.ServiceName,
			&row.LineOfBusiness,
			&row.FirstFoundAt,
			&row.LastSeenAt,
			&row.SLABreachDate,
			&row.DueDate,
			&row.DeduplicationKey,
			&row.CanonicalRuleID,
		); err != nil {
			return nil, fmt.Errorf("scan finding row: %w", err)
		}

		finding, err := row.toFinding()
		if err != nil {
			return nil, err
		}
		findings = append(findings, finding)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate finding rows: %w", err)
	}

	return findings, nil
}

func (r postgresFindingRow) toFinding() (Finding, error) {
	cves := []CVE{}
	if len(r.CVEsRaw) > 0 {
		if err := json.Unmarshal(r.CVEsRaw, &cves); err != nil {
			return Finding{}, fmt.Errorf("decode cves for finding %s: %w", r.ID, err)
		}
	}

	complianceMappings := []ComplianceMapping{}
	if len(r.ComplianceRaw) > 0 {
		if err := json.Unmarshal(r.ComplianceRaw, &complianceMappings); err != nil {
			return Finding{}, fmt.Errorf("decode compliance mappings for finding %s: %w", r.ID, err)
		}
	}

	finding := Finding{
		ID:                  r.ID,
		Source:              r.Source,
		SourceFindingID:     nullString(r.SourceFindingID),
		Type:                r.Type,
		Title:               r.Title,
		Description:         nullString(r.Description),
		ResourceType:        nullString(r.ResourceType),
		ResourceID:          nullString(r.ResourceID),
		ResourceName:        nullString(r.ResourceName),
		ResourceARN:         nullString(r.ResourceARN),
		Platform:            nullStringWithDefault(r.Platform, "cloud"),
		CloudProvider:       r.CloudProvider,
		Region:              nullString(r.Region),
		AccountID:           nullString(r.AccountID),
		AccountName:         nullString(r.AccountName),
		EnvironmentType:     nullString(r.EnvironmentType),
		StaticSeverity:      r.StaticSeverity,
		Severity:            r.Severity,
		AIRiskLevel:         nullString(r.AIRiskLevel),
		AIRiskRationale:     nullString(r.AIRiskRationale),
		AIContextualFactors: append([]string(nil), []string(r.AIContextualFactors)...),
		CVSSVector:          nullString(r.CVSSVector),
		ExploitAvailable:    r.ExploitAvailable,
		CVEs:                cves,
		MITRETactics:        append([]string(nil), []string(r.MITRETactics)...),
		MITRETechniques:     append([]string(nil), []string(r.MITRETechniques)...),
		ComplianceMappings:  complianceMappings,
		Remediation:         nullString(r.Remediation),
		AutoRemediatable:    r.AutoRemediatable,
		Category:            nullString(r.Category),
		Status:              r.Status,
		WorkflowStatus:      nullString(r.WorkflowStatus),
		Suppressed:          r.Suppressed,
		ServiceName:         nullString(r.ServiceName),
		LineOfBusiness:      nullString(r.LineOfBusiness),
		FirstFoundAt:        r.FirstFoundAt.UTC().Format(time.RFC3339),
		LastSeenAt:          formatNullTime(r.LastSeenAt),
		SLABreachDate:       formatNullTime(r.SLABreachDate),
		DueDate:             formatNullTime(r.DueDate),
		DeduplicationKey:    nullString(r.DeduplicationKey),
		CanonicalRuleID:     nullString(r.CanonicalRuleID),
	}

	if r.AIRiskScore.Valid {
		finding.AIRiskScore = r.AIRiskScore.Float64
	}
	if r.CVSS.Valid {
		cvss := r.CVSS.Float64
		finding.CVSS = &cvss
	}
	if r.EPSS.Valid {
		epss := r.EPSS.Float64
		finding.EPSS = &epss
	}

	finding.IntegrityHash = finding.ComputeIntegrityHash()
	return finding, nil
}

func nullString(ns sql.NullString) string {
	if ns.Valid {
		return ns.String
	}
	return ""
}

func nullStringWithDefault(ns sql.NullString, fallback string) string {
	if ns.Valid && ns.String != "" {
		return ns.String
	}
	return fallback
}

func formatNullTime(nt sql.NullTime) string {
	if nt.Valid {
		return nt.Time.UTC().Format(time.RFC3339)
	}
	return ""
}
