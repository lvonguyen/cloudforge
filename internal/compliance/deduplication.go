// Package compliance provides compliance framework mapping and assessment
package compliance

import (
	"sort"
	"strings"
)

// Deduplicator handles finding deduplication logic
type Deduplicator struct {
	ruleHierarchy  map[string]int       // rule ID -> priority (lower = more specific)
	ruleEquivalence map[string][]string // canonical rule -> equivalent rules
}

// NewDeduplicator creates a new deduplicator
func NewDeduplicator() *Deduplicator {
	d := &Deduplicator{
		ruleHierarchy:   make(map[string]int),
		ruleEquivalence: make(map[string][]string),
	}
	d.loadBuiltInMappings()
	return d
}

// loadBuiltInMappings loads built-in rule equivalence mappings
func (d *Deduplicator) loadBuiltInMappings() {
	// AWS Security Hub / Config Rules equivalences
	d.ruleEquivalence["s3-bucket-public-access"] = []string{
		"S3.1", "S3.2", "S3.3", // AWS Security Hub
		"s3-bucket-public-read-prohibited",
		"s3-bucket-public-write-prohibited",
		"s3-bucket-level-public-access-prohibited",
		"s3-account-level-public-access-blocks",
		"CKV_AWS_19", "CKV_AWS_20", "CKV_AWS_21", // Checkov
		"AC_AWS_0134", "AC_AWS_0135", // Accurics
	}

	d.ruleEquivalence["ec2-security-group-open"] = []string{
		"EC2.19", "EC2.2", // Security Hub
		"restricted-ssh",
		"restricted-common-ports",
		"vpc-sg-open-only-to-authorized-ports",
		"CKV_AWS_23", "CKV_AWS_24", "CKV_AWS_25", // Checkov
	}

	d.ruleEquivalence["iam-root-access-key"] = []string{
		"IAM.4",
		"iam-root-access-key-check",
		"CKV_AWS_41",
	}

	d.ruleEquivalence["iam-mfa-enabled"] = []string{
		"IAM.5", "IAM.6",
		"iam-user-mfa-enabled",
		"mfa-enabled-for-iam-console-access",
		"root-account-mfa-enabled",
		"CKV_AWS_9",
	}

	d.ruleEquivalence["encryption-at-rest"] = []string{
		"S3.4", "RDS.3", "EBS.1", "EC2.3",
		"s3-bucket-server-side-encryption-enabled",
		"rds-storage-encrypted",
		"encrypted-volumes",
		"CKV_AWS_3", "CKV_AWS_16", "CKV_AWS_17",
	}

	d.ruleEquivalence["encryption-in-transit"] = []string{
		"S3.5", "ELB.2", "ES.3",
		"s3-bucket-ssl-requests-only",
		"elb-tls-https-listeners-only",
		"CKV_AWS_2",
	}

	d.ruleEquivalence["logging-enabled"] = []string{
		"CloudTrail.1", "S3.9", "ELB.5",
		"cloud-trail-log-file-validation-enabled",
		"s3-bucket-logging-enabled",
		"elb-logging-enabled",
		"CKV_AWS_36", "CKV_AWS_67",
	}

	// GCP equivalences
	d.ruleEquivalence["gcp-bucket-public"] = []string{
		"1.1", "5.1", // GCP CIS
		"storage-bucket-not-public",
		"CKV_GCP_28", "CKV_GCP_29",
	}

	d.ruleEquivalence["gcp-firewall-open"] = []string{
		"3.6", "3.7", // GCP CIS
		"compute-network-firewall-ingress-deny",
		"CKV_GCP_2", "CKV_GCP_3",
	}

	// Azure equivalences
	d.ruleEquivalence["azure-storage-public"] = []string{
		"NS-2", "DP-2", // MCSB
		"storage-account-public-access-disabled",
		"CKV_AZURE_34", "CKV_AZURE_35",
	}

	d.ruleEquivalence["azure-nsg-open"] = []string{
		"NS-1", "NS-4", // MCSB
		"network-security-group-not-allowing-rdp",
		"network-security-group-not-allowing-ssh",
		"CKV_AZURE_9", "CKV_AZURE_10",
	}

	// Set rule hierarchy (lower = more specific/preferred)
	// Security Hub rules are generally preferred as canonical
	d.ruleHierarchy["S3.1"] = 1
	d.ruleHierarchy["S3.2"] = 2
	d.ruleHierarchy["S3.3"] = 3
	d.ruleHierarchy["EC2.19"] = 1
	d.ruleHierarchy["IAM.4"] = 1
	d.ruleHierarchy["IAM.5"] = 1

	// Checkov rules are secondary
	for ruleID := range d.ruleHierarchy {
		if strings.HasPrefix(ruleID, "CKV_") {
			d.ruleHierarchy[ruleID] = 10
		}
	}
}

// Deduplicate determines if a finding should be kept or is a duplicate
// Returns the finding (possibly modified) and whether it should be kept
func (d *Deduplicator) Deduplicate(finding *Finding, existingFindings []*Finding) (*Finding, bool) {
	// Generate deduplication key
	finding.DeduplicationKey = finding.GenerateDeduplicationKey()

	// Find canonical rule ID
	finding.CanonicalRuleID = d.getCanonicalRule(finding.Source, finding.SourceFindingID)

	// Check for exact duplicates by dedup key
	for _, existing := range existingFindings {
		if existing.DeduplicationKey == finding.DeduplicationKey {
			// Exact duplicate - skip
			return finding, false
		}
	}

	// Check for rule-based duplicates (same resource, equivalent rules)
	for _, existing := range existingFindings {
		if d.isEquivalentFinding(finding, existing) {
			// Determine which one to keep based on priority
			if d.shouldReplaceExisting(finding, existing) {
				// Mark the new finding as canonical, link to the old one
				finding.RelatedRules = append(finding.RelatedRules, existing.SourceFindingID)
				// Return true to keep this finding, caller should remove existing
				return finding, true
			}
			// Keep existing, mark this as duplicate
			finding.DuplicateOf = existing.ID
			return finding, false
		}
	}

	// Not a duplicate
	return finding, true
}

// getCanonicalRule finds the canonical rule ID for a source finding
func (d *Deduplicator) getCanonicalRule(source, findingID string) string {
	// Check if this finding ID maps to a canonical rule
	for canonical, equivalents := range d.ruleEquivalence {
		for _, eq := range equivalents {
			if eq == findingID {
				return canonical
			}
		}
	}
	// If no mapping found, use the source:findingID as canonical
	return source + ":" + findingID
}

// isEquivalentFinding checks if two findings are about the same issue
func (d *Deduplicator) isEquivalentFinding(f1, f2 *Finding) bool {
	// Must be same resource
	if f1.ResourceID != f2.ResourceID {
		return false
	}

	// Check if rules are equivalent
	return d.areRulesEquivalent(f1.SourceFindingID, f2.SourceFindingID)
}

// areRulesEquivalent checks if two rules are equivalent
func (d *Deduplicator) areRulesEquivalent(rule1, rule2 string) bool {
	// Same rule
	if rule1 == rule2 {
		return true
	}

	// Check equivalence mappings
	for _, equivalents := range d.ruleEquivalence {
		hasRule1 := false
		hasRule2 := false
		for _, eq := range equivalents {
			if eq == rule1 {
				hasRule1 = true
			}
			if eq == rule2 {
				hasRule2 = true
			}
		}
		if hasRule1 && hasRule2 {
			return true
		}
	}

	return false
}

// shouldReplaceExisting determines if new finding should replace existing
func (d *Deduplicator) shouldReplaceExisting(newFinding, existing *Finding) bool {
	// Get priorities (lower = more preferred)
	newPriority := d.getRulePriority(newFinding.SourceFindingID)
	existingPriority := d.getRulePriority(existing.SourceFindingID)

	// Prefer lower priority (more specific) rules
	if newPriority < existingPriority {
		return true
	}
	if newPriority > existingPriority {
		return false
	}

	// Same priority - prefer more recent
	return newFinding.FirstFoundAt.After(existing.FirstFoundAt)
}

// getRulePriority returns the priority for a rule
func (d *Deduplicator) getRulePriority(ruleID string) int {
	if priority, ok := d.ruleHierarchy[ruleID]; ok {
		return priority
	}
	return 100 // Default low priority
}

// DeduplicateBatch deduplicates a batch of findings
func (d *Deduplicator) DeduplicateBatch(findings []*Finding) []*Finding {
	// Sort by rule priority (most specific first)
	sort.Slice(findings, func(i, j int) bool {
		pi := d.getRulePriority(findings[i].SourceFindingID)
		pj := d.getRulePriority(findings[j].SourceFindingID)
		return pi < pj
	})

	seen := make(map[string]*Finding)
	var deduplicated []*Finding

	for _, finding := range findings {
		finding.DeduplicationKey = finding.GenerateDeduplicationKey()
		finding.CanonicalRuleID = d.getCanonicalRule(finding.Source, finding.SourceFindingID)

		// Check for resource+canonical rule combo
		key := finding.ResourceID + "|" + finding.CanonicalRuleID

		if existing, ok := seen[key]; ok {
			// Add to related rules of the kept finding
			existing.RelatedRules = append(existing.RelatedRules, finding.SourceFindingID)
			finding.DuplicateOf = existing.ID
		} else {
			seen[key] = finding
			deduplicated = append(deduplicated, finding)
		}
	}

	return deduplicated
}

// AddRuleEquivalence adds a custom rule equivalence mapping
func (d *Deduplicator) AddRuleEquivalence(canonical string, equivalents []string) {
	d.ruleEquivalence[canonical] = equivalents
}

// AddRulePriority adds a custom rule priority
func (d *Deduplicator) AddRulePriority(ruleID string, priority int) {
	d.ruleHierarchy[ruleID] = priority
}

