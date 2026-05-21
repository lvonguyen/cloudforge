package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"aegis/internal/api"

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
	AIContextualFactors []string
	CVSS                sql.NullFloat64
	CVSSVector          sql.NullString
	EPSS                sql.NullFloat64
	ExploitAvailable    bool
	CVEsRaw             []byte
	MITRETactics        []string
	MITRETechniques     []string
	ComplianceRaw       []byte
	Remediation         sql.NullString
	AutoRemediatable    bool
	Category            sql.NullString
	Status              string
	WorkflowStatus      sql.NullString
	AssigneeRaw         []byte
	Suppressed          bool
	TechnicalContactRaw []byte
	BusinessOwnerRaw    []byte
	ServiceName         sql.NullString
	LineOfBusiness      sql.NullString
	Team                sql.NullString
	FirstFoundAt        time.Time
	LastSeenAt          sql.NullTime
	SLABreachDate       sql.NullTime
	DueDate             sql.NullTime
	DeduplicationKey    sql.NullString
	CanonicalRuleID     sql.NullString
}

const postgresFindingSelectColumns = `
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
			COALESCE(assignee, 'null'::jsonb) AS assignee,
			COALESCE(suppressed, FALSE) AS suppressed,
			COALESCE(technical_contact, 'null'::jsonb) AS technical_contact,
			COALESCE(business_owner, 'null'::jsonb) AS business_owner,
			service_name,
			line_of_business,
			team,
			first_found_at,
			last_seen_at,
			sla_breach_date,
			due_date,
			deduplication_key,
			canonical_rule_id
`

type postgresFindingStore struct {
	db *sql.DB
}

type postgresFindingListFilter struct {
	Severity  string
	Provider  string
	Status    string
	SortField string
	SortOrder string
	Scope     *api.ResourceScope
}

func newPostgresFindingStore(db *sql.DB) *postgresFindingStore {
	if db == nil {
		return nil
	}
	return &postgresFindingStore{db: db}
}

func newPostgresFindingStoreForSource(findingsSource string, db *sql.DB) *postgresFindingStore {
	if !strings.EqualFold(strings.TrimSpace(findingsSource), "postgres") {
		return nil
	}
	return newPostgresFindingStore(db)
}

func loadFindingsFromPostgres(ctx context.Context, db *sql.DB) ([]Finding, error) {
	query := `SELECT` + postgresFindingSelectColumns + `
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
		finding, err := scanPostgresFinding(rows)
		if err != nil {
			return nil, fmt.Errorf("scan finding row: %w", err)
		}
		findings = append(findings, finding)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate finding rows: %w", err)
	}

	return findings, nil
}

func (store *postgresFindingStore) List(ctx context.Context, filter postgresFindingListFilter, page, perPage int) (paginatedResponse, error) {
	if store == nil || store.db == nil {
		return paginatedResponse{Data: []Finding{}, Page: 1, PerPage: perPage, TotalPages: 1}, nil
	}
	if page <= 0 {
		page = 1
	}
	if perPage <= 0 {
		perPage = 50
	}
	if perPage > 200 {
		perPage = 200
	}

	whereSQL, args := buildPostgresFindingWhereClause(filter)
	//nolint:gosec // G202: WHERE fragments are allowlisted and values are bound args.
	countQuery := `SELECT COUNT(*) FROM findings` + whereSQL

	var total int
	if err := store.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return paginatedResponse{}, fmt.Errorf("count findings: %w", err)
	}

	totalPages := (total + perPage - 1) / perPage
	if totalPages == 0 {
		totalPages = 1
	}
	if page > totalPages {
		page = totalPages
	}

	offset := (page - 1) * perPage
	args = append(args, perPage, offset)
	limitArg := len(args) - 1
	offsetArg := len(args)

	//nolint:gosec // G202: WHERE/ORDER fragments are allowlisted and values are bound args.
	listQuery := `SELECT` + postgresFindingSelectColumns + `
		FROM findings` + whereSQL + buildPostgresFindingSortClause(filter) + fmt.Sprintf(`
		LIMIT $%d OFFSET $%d
	`, limitArg, offsetArg)

	rows, err := store.db.QueryContext(ctx, listQuery, args...)
	if err != nil {
		return paginatedResponse{}, fmt.Errorf("list findings: %w", err)
	}
	defer rows.Close()

	capacity := total
	if capacity > perPage {
		capacity = perPage
	}
	findings := make([]Finding, 0, capacity)
	for rows.Next() {
		finding, err := scanPostgresFinding(rows)
		if err != nil {
			return paginatedResponse{}, fmt.Errorf("scan finding row: %w", err)
		}
		findings = append(findings, finding)
	}
	if err := rows.Err(); err != nil {
		return paginatedResponse{}, fmt.Errorf("iterate finding rows: %w", err)
	}
	if findings == nil {
		findings = []Finding{}
	}

	return paginatedResponse{
		Data:       findings,
		Page:       page,
		PerPage:    perPage,
		Total:      total,
		TotalPages: totalPages,
	}, nil
}

func buildPostgresFindingWhereClause(filter postgresFindingListFilter) (string, []any) {
	clauses := make([]string, 0, 8)
	args := make([]any, 0, 8)
	add := func(clause string, value any) {
		args = append(args, value)
		clauses = append(clauses, fmt.Sprintf(clause, len(args)))
	}

	if severity := strings.ToUpper(strings.TrimSpace(filter.Severity)); severity != "" {
		add("severity = $%d", severity)
	}
	if provider := strings.ToLower(strings.TrimSpace(filter.Provider)); provider != "" {
		add("cloud_provider = $%d", provider)
	}
	if status := strings.ToLower(strings.TrimSpace(filter.Status)); status != "" {
		add("status = $%d", status)
	}
	if filter.Scope != nil {
		if len(filter.Scope.AccountIDs) > 0 {
			add("account_id = ANY($%d)", pq.Array(filter.Scope.AccountIDs))
		}
		if len(filter.Scope.Regions) > 0 {
			add("LOWER(COALESCE(region, '')) = ANY($%d)", pq.Array(normalizePostgresFindingScopeValues(filter.Scope.Regions)))
		}
		if len(filter.Scope.Environments) > 0 {
			add("LOWER(COALESCE(environment_type, '')) = ANY($%d)", pq.Array(normalizePostgresFindingScopeValues(filter.Scope.Environments)))
		}
		if len(filter.Scope.BusinessUnits) > 0 {
			add("LOWER(COALESCE(line_of_business, '')) = ANY($%d)", pq.Array(normalizePostgresFindingScopeValues(filter.Scope.BusinessUnits)))
		}
	}

	if len(clauses) == 0 {
		return "", args
	}
	return " WHERE " + strings.Join(clauses, " AND "), args
}

func buildPostgresFindingSortClause(filter postgresFindingListFilter) string {
	order := "ASC"
	if strings.EqualFold(strings.TrimSpace(filter.SortOrder), "desc") {
		order = "DESC"
	}

	switch strings.ToLower(strings.TrimSpace(filter.SortField)) {
	case "":
		return " ORDER BY first_found_at DESC, id ASC"
	case "severity":
		return fmt.Sprintf(` ORDER BY CASE UPPER(severity)
			WHEN 'CRITICAL' THEN 4
			WHEN 'HIGH' THEN 3
			WHEN 'MEDIUM' THEN 2
			WHEN 'LOW' THEN 1
			WHEN 'INFO' THEN 0
			ELSE 0
		END %s, first_found_at DESC, id ASC`, order)
	case "ai_risk", "ai_risk_score":
		return fmt.Sprintf(" ORDER BY COALESCE(ai_risk_score, 0) %s, first_found_at DESC, id ASC", order)
	case "first_found_at":
		return fmt.Sprintf(" ORDER BY first_found_at %s, id ASC", order)
	case "title":
		return fmt.Sprintf(" ORDER BY LOWER(title) %s, first_found_at DESC, id ASC", order)
	case "status":
		return fmt.Sprintf(" ORDER BY status %s, first_found_at DESC, id ASC", order)
	default:
		return " ORDER BY first_found_at DESC, id ASC"
	}
}

func normalizePostgresFindingScopeValues(values []string) []string {
	normalized := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" {
			continue
		}
		normalized = append(normalized, value)
	}
	return normalized
}

type postgresFindingScanner interface {
	Scan(dest ...any) error
}

func scanPostgresFinding(scanner postgresFindingScanner) (Finding, error) {
	var row postgresFindingRow
	if err := scanner.Scan(
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
		&row.AssigneeRaw,
		&row.Suppressed,
		&row.TechnicalContactRaw,
		&row.BusinessOwnerRaw,
		&row.ServiceName,
		&row.LineOfBusiness,
		&row.Team,
		&row.FirstFoundAt,
		&row.LastSeenAt,
		&row.SLABreachDate,
		&row.DueDate,
		&row.DeduplicationKey,
		&row.CanonicalRuleID,
	); err != nil {
		return Finding{}, err
	}

	finding, err := row.toFinding()
	if err != nil {
		return Finding{}, err
	}
	return finding, nil
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

	assignee, err := decodeFindingAssignee(r.ID, r.AssigneeRaw)
	if err != nil {
		return Finding{}, err
	}
	technicalContact, err := decodeFindingContact(r.ID, "technical_contact", r.TechnicalContactRaw)
	if err != nil {
		return Finding{}, err
	}
	businessOwner, err := decodeFindingContact(r.ID, "business_owner", r.BusinessOwnerRaw)
	if err != nil {
		return Finding{}, err
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
		AIContextualFactors: append([]string(nil), r.AIContextualFactors...),
		CVSSVector:          nullString(r.CVSSVector),
		ExploitAvailable:    r.ExploitAvailable,
		CVEs:                cves,
		MITRETactics:        append([]string(nil), r.MITRETactics...),
		MITRETechniques:     append([]string(nil), r.MITRETechniques...),
		ComplianceMappings:  complianceMappings,
		Remediation:         nullString(r.Remediation),
		AutoRemediatable:    r.AutoRemediatable,
		Category:            nullString(r.Category),
		Status:              r.Status,
		WorkflowStatus:      nullString(r.WorkflowStatus),
		Assignee:            assignee,
		Suppressed:          r.Suppressed,
		TechnicalContact:    technicalContact,
		BusinessOwner:       businessOwner,
		ServiceName:         nullString(r.ServiceName),
		LineOfBusiness:      nullString(r.LineOfBusiness),
		Team:                nullString(r.Team),
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

func decodeFindingAssignee(findingID string, raw []byte) (*FindingAssignee, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}

	var assignee FindingAssignee
	if err := json.Unmarshal(raw, &assignee); err != nil {
		return nil, fmt.Errorf("decode assignee for finding %s: %w", findingID, err)
	}
	if assignee == (FindingAssignee{}) {
		return nil, nil
	}
	return &assignee, nil
}

func decodeFindingContact(findingID, field string, raw []byte) (*FindingContact, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}

	var contact FindingContact
	if err := json.Unmarshal(raw, &contact); err != nil {
		return nil, fmt.Errorf("decode %s for finding %s: %w", field, findingID, err)
	}
	if contact == (FindingContact{}) {
		return nil, nil
	}
	return &contact, nil
}
