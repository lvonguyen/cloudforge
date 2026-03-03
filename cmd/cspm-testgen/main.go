// Command testgen generates realistic CSPM findings for all three cloud
// providers. It produces 3000 findings per CSP (9000 total) in both raw
// provider-native format and the normalized schema used by the aggregator.
//
// Usage:
//
//	go run ./cmd/testgen                        # default 3000/provider
//	go run ./cmd/testgen -count 500             # 500/provider
//	go run ./cmd/testgen -out ./testdata        # custom output dir
//	go run ./cmd/testgen -seed 42               # deterministic output
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"time"
)

// --- Severity / env / tier distributions (tuned to look realistic) ---------

var severities = []weightedChoice{
	{"CRITICAL", 8}, {"HIGH", 22}, {"MEDIUM", 45}, {"LOW", 25},
}

var envTypes = []weightedChoice{
	{"prod", 35}, {"staging", 20}, {"dev", 30}, {"sandbox", 15},
}

var assetTiers = []weightedChoice{
	{"Tier1-Prod", 20}, {"Tier2-NonProd", 40}, {"Tier3-Dev", 40},
}

var dataClassifications = []weightedChoice{
	{"Internal", 50}, {"PCI", 10}, {"PII", 15}, {"PHI", 5}, {"Public", 20},
}

var cbus = []weightedChoice{
	{"HMA", 25}, {"GMA", 20}, {"PVD", 15}, {"CTO", 10}, {"Platform", 15}, {"Data", 15},
}

// --- AWS templates ---------------------------------------------------------

type awsFindingTemplate struct {
	GeneratorID  string
	Title        string
	Description  string
	ResourceType string
	Standard     string
}

var awsTemplates = []awsFindingTemplate{
	{"aws-foundational-security-best-practices/v/1.0.0/S3.1", "S3 buckets should have server-side encryption enabled", "This control checks that S3 bucket has server-side encryption enabled.", "AwsS3Bucket", "aws-foundational-security-best-practices"},
	{"aws-foundational-security-best-practices/v/1.0.0/S3.2", "S3 buckets should prohibit public read access", "This control checks whether S3 buckets allow public read access.", "AwsS3Bucket", "aws-foundational-security-best-practices"},
	{"aws-foundational-security-best-practices/v/1.0.0/S3.3", "S3 buckets should prohibit public write access", "This control checks whether S3 buckets allow public write access.", "AwsS3Bucket", "aws-foundational-security-best-practices"},
	{"aws-foundational-security-best-practices/v/1.0.0/S3.8", "S3 Block Public Access setting should be enabled at the bucket level", "This control checks whether S3 buckets have bucket-level public access blocks applied.", "AwsS3Bucket", "aws-foundational-security-best-practices"},
	{"aws-foundational-security-best-practices/v/1.0.0/EC2.8", "EC2 instances should use Instance Metadata Service Version 2 (IMDSv2)", "This control checks whether EC2 instance metadata is configured to require IMDSv2.", "AwsEc2Instance", "aws-foundational-security-best-practices"},
	{"aws-foundational-security-best-practices/v/1.0.0/EC2.18", "Security groups should only allow unrestricted incoming traffic for authorized ports", "This control checks whether security groups allow unrestricted incoming traffic.", "AwsEc2SecurityGroup", "aws-foundational-security-best-practices"},
	{"aws-foundational-security-best-practices/v/1.0.0/EC2.19", "Security groups should not allow unrestricted access to high risk ports", "This control checks whether unrestricted incoming traffic for security groups is accessible to specified ports that have the highest risk.", "AwsEc2SecurityGroup", "aws-foundational-security-best-practices"},
	{"aws-foundational-security-best-practices/v/1.0.0/IAM.1", "IAM policies should not allow full '*' administrative privileges", "This control checks whether the default version of IAM policies have administrator access.", "AwsIamPolicy", "aws-foundational-security-best-practices"},
	{"aws-foundational-security-best-practices/v/1.0.0/IAM.6", "Hardware MFA should be enabled for the root user", "This control checks whether the root user has a hardware MFA device.", "AwsAccount", "aws-foundational-security-best-practices"},
	{"aws-foundational-security-best-practices/v/1.0.0/CloudTrail.1", "CloudTrail should be enabled and configured with at least one multi-Region trail", "This control checks that there is at least one multi-region CloudTrail trail.", "AwsAccount", "aws-foundational-security-best-practices"},
	{"aws-foundational-security-best-practices/v/1.0.0/CloudTrail.2", "CloudTrail should have encryption at rest enabled", "This control checks whether CloudTrail is configured to use KMS encryption.", "AwsCloudTrailTrail", "aws-foundational-security-best-practices"},
	{"aws-foundational-security-best-practices/v/1.0.0/RDS.1", "RDS snapshot should be private", "This control checks whether RDS DB snapshots are public.", "AwsRdsDbSnapshot", "aws-foundational-security-best-practices"},
	{"aws-foundational-security-best-practices/v/1.0.0/RDS.2", "RDS DB instances should prohibit public access", "This control checks whether RDS instances are publicly accessible.", "AwsRdsDbInstance", "aws-foundational-security-best-practices"},
	{"aws-foundational-security-best-practices/v/1.0.0/RDS.3", "RDS DB instances should have encryption at rest enabled", "This control checks whether storage encryption is enabled for RDS DB instances.", "AwsRdsDbInstance", "aws-foundational-security-best-practices"},
	{"aws-foundational-security-best-practices/v/1.0.0/Lambda.1", "Lambda function policies should prohibit public access", "This control checks whether the Lambda function resource-based policy prohibits public access.", "AwsLambdaFunction", "aws-foundational-security-best-practices"},
	{"aws-foundational-security-best-practices/v/1.0.0/ELBv2.1", "Application Load Balancer should be configured to redirect HTTP requests to HTTPS", "This control checks whether HTTP to HTTPS redirection is configured.", "AwsElbv2LoadBalancer", "aws-foundational-security-best-practices"},
	{"aws-foundational-security-best-practices/v/1.0.0/KMS.3", "AWS KMS keys should not be unintentionally deleted", "This control checks whether KMS keys are scheduled for deletion.", "AwsKmsKey", "aws-foundational-security-best-practices"},
	{"cis-aws-foundations-benchmark/v/1.4.0/1.4", "Ensure no root user account access key exists", "The root user account is the most privileged user in an AWS account.", "AwsIamUser", "cis-aws-foundations-benchmark"},
	{"cis-aws-foundations-benchmark/v/1.4.0/2.1.1", "Ensure S3 Bucket Policy is set to deny HTTP requests", "At the S3 bucket level, you can configure permissions through a bucket policy.", "AwsS3Bucket", "cis-aws-foundations-benchmark"},
	{"cis-aws-foundations-benchmark/v/1.4.0/3.1", "Ensure CloudTrail is enabled in all regions", "CloudTrail is a web service that records AWS API calls for your account.", "AwsAccount", "cis-aws-foundations-benchmark"},
	{"aws-foundational-security-best-practices/v/1.0.0/ECR.1", "ECR private repositories should have image scanning configured", "This control checks whether a private ECR repository has image scanning configured.", "AwsEcrRepository", "aws-foundational-security-best-practices"},
	{"aws-foundational-security-best-practices/v/1.0.0/ECS.1", "Amazon ECS task definitions should have secure networking modes and user definitions", "This control checks whether an ECS task definition has a specific networking mode and user definition.", "AwsEcsTaskDefinition", "aws-foundational-security-best-practices"},
	{"aws-foundational-security-best-practices/v/1.0.0/SNS.1", "SNS topics should be encrypted at rest using AWS KMS", "This control checks whether an SNS topic is encrypted at rest using AWS KMS.", "AwsSnsTopic", "aws-foundational-security-best-practices"},
	{"aws-foundational-security-best-practices/v/1.0.0/SQS.1", "Amazon SQS queues should be encrypted at rest", "This control checks whether Amazon SQS queues are encrypted at rest.", "AwsSqsQueue", "aws-foundational-security-best-practices"},
	{"inspector/CVE-2024-6387", "CVE-2024-6387 - OpenSSH regreSSHion Remote Code Execution", "A signal handler race condition was found in OpenSSH server (sshd) that could allow unauthenticated remote code execution.", "AwsEc2Instance", "inspector"},
}

// --- Azure templates -------------------------------------------------------

type azureFindingTemplate struct {
	AssessmentKey string
	Title         string
	Description   string
	ResourceType  string
	Standard      string
}

var azureTemplates = []azureFindingTemplate{
	{"1f3afdf9-7b2b-4c14-9f6e-1234abcd0001", "Storage accounts should restrict network access", "Network access to your storage account should be restricted.", "Microsoft.Storage/storageAccounts", "Microsoft cloud security benchmark"},
	{"1f3afdf9-7b2b-4c14-9f6e-1234abcd0002", "Secure transfer to storage accounts should be enabled", "Audit requirement of Secure transfer in your storage account.", "Microsoft.Storage/storageAccounts", "Microsoft cloud security benchmark"},
	{"1f3afdf9-7b2b-4c14-9f6e-1234abcd0003", "Storage account public access should be disallowed", "Anonymous public read access to containers and blobs in Azure Storage is a convenient way to share data but might present security risks.", "Microsoft.Storage/storageAccounts", "Microsoft cloud security benchmark"},
	{"1f3afdf9-7b2b-4c14-9f6e-1234abcd0004", "Virtual machines should have vulnerability findings resolved", "Monitors vulnerability assessment scan results and recommendations for how to remediate virtual machine vulnerabilities.", "Microsoft.Compute/virtualMachines", "Microsoft cloud security benchmark"},
	{"1f3afdf9-7b2b-4c14-9f6e-1234abcd0005", "Management ports should be closed on your virtual machines", "Open remote management ports are exposing your VM to a high level of risk from Internet-based attacks.", "Microsoft.Compute/virtualMachines", "Microsoft cloud security benchmark"},
	{"1f3afdf9-7b2b-4c14-9f6e-1234abcd0006", "MFA should be enabled on accounts with owner permissions on your subscription", "Multi-Factor Authentication (MFA) should be enabled for all subscription accounts with owner permissions.", "Microsoft.Authorization/roleAssignments", "Microsoft cloud security benchmark"},
	{"1f3afdf9-7b2b-4c14-9f6e-1234abcd0007", "Azure Defender for SQL should be enabled for unprotected SQL Managed Instances", "Enable Azure Defender for SQL on each of your SQL Managed Instances.", "Microsoft.Sql/managedInstances", "Microsoft cloud security benchmark"},
	{"1f3afdf9-7b2b-4c14-9f6e-1234abcd0008", "Transparent Data Encryption on SQL databases should be enabled", "Transparent data encryption should be enabled to protect the database at rest.", "Microsoft.Sql/servers/databases", "Microsoft cloud security benchmark"},
	{"1f3afdf9-7b2b-4c14-9f6e-1234abcd0009", "SQL databases should have vulnerability findings resolved", "Monitor vulnerability assessment scan results and recommendations for how to remediate database vulnerabilities.", "Microsoft.Sql/servers/databases", "Microsoft cloud security benchmark"},
	{"1f3afdf9-7b2b-4c14-9f6e-1234abcd0010", "Diagnostic logs in Key Vault should be enabled", "Enable logs and retain them up to a year for investigation.", "Microsoft.KeyVault/vaults", "Microsoft cloud security benchmark"},
	{"1f3afdf9-7b2b-4c14-9f6e-1234abcd0011", "Key Vault should use a virtual network service endpoint", "This policy audits any Key Vault not configured to use a virtual network service endpoint.", "Microsoft.KeyVault/vaults", "Microsoft cloud security benchmark"},
	{"1f3afdf9-7b2b-4c14-9f6e-1234abcd0012", "Network Security Groups on the subnet level should be enabled", "Protect your subnet from potential threats by restricting access to it with a Network Security Group.", "Microsoft.Network/virtualNetworks/subnets", "Microsoft cloud security benchmark"},
	{"1f3afdf9-7b2b-4c14-9f6e-1234abcd0013", "Subnets should be associated with a Network Security Group", "Enable network security group to filter network traffic to and from Azure resources.", "Microsoft.Network/virtualNetworks/subnets", "Microsoft cloud security benchmark"},
	{"1f3afdf9-7b2b-4c14-9f6e-1234abcd0014", "Web Application Firewall should be enabled for Application Gateway", "Deploy Azure Web Application Firewall (WAF) in front of public facing web applications.", "Microsoft.Network/applicationGateways", "Microsoft cloud security benchmark"},
	{"1f3afdf9-7b2b-4c14-9f6e-1234abcd0015", "Kubernetes Services should be upgraded to a non-vulnerable Kubernetes version", "Upgrade your Kubernetes service cluster to a later Kubernetes version.", "Microsoft.ContainerService/managedClusters", "Microsoft cloud security benchmark"},
	{"1f3afdf9-7b2b-4c14-9f6e-1234abcd0016", "Container registries should have vulnerability findings resolved", "Container image vulnerability assessment scans your registry for security vulnerabilities.", "Microsoft.ContainerRegistry/registries", "Microsoft cloud security benchmark"},
	{"1f3afdf9-7b2b-4c14-9f6e-1234abcd0017", "App Service apps should use managed identity", "Use a managed identity for enhanced authentication security.", "Microsoft.Web/sites", "Microsoft cloud security benchmark"},
	{"1f3afdf9-7b2b-4c14-9f6e-1234abcd0018", "Function apps should use managed identity", "Use a managed identity for enhanced authentication security.", "Microsoft.Web/sites", "Microsoft cloud security benchmark"},
	{"1f3afdf9-7b2b-4c14-9f6e-1234abcd0019", "App Service apps should require HTTPS only", "Use of HTTPS ensures server/service authentication and protects data in transit.", "Microsoft.Web/sites", "Microsoft cloud security benchmark"},
	{"1f3afdf9-7b2b-4c14-9f6e-1234abcd0020", "Azure Cosmos DB accounts should use customer-managed keys to encrypt data at rest", "Use customer-managed keys to manage the encryption at rest of your Azure Cosmos DB.", "Microsoft.DocumentDB/databaseAccounts", "Microsoft cloud security benchmark"},
}

// --- GCP templates ---------------------------------------------------------

type gcpFindingTemplate struct {
	Category     string
	Description  string
	ResourceType string
	Standard     string
}

var gcpTemplates = []gcpFindingTemplate{
	{"PUBLIC_BUCKET_ACL", "A Cloud Storage bucket is publicly accessible.", "storage.googleapis.com/Bucket", "CIS GCP Foundations"},
	{"BUCKET_LOGGING_DISABLED", "Logging is not enabled for a Cloud Storage bucket.", "storage.googleapis.com/Bucket", "CIS GCP Foundations"},
	{"BUCKET_POLICY_ONLY_DISABLED", "Uniform bucket-level access is not enabled.", "storage.googleapis.com/Bucket", "CIS GCP Foundations"},
	{"OPEN_FIREWALL", "A firewall rule allows traffic from all IP addresses.", "compute.googleapis.com/Firewall", "CIS GCP Foundations"},
	{"OPEN_SSH_PORT", "A firewall rule allows access to SSH port 22 from the internet.", "compute.googleapis.com/Firewall", "CIS GCP Foundations"},
	{"OPEN_RDP_PORT", "A firewall rule allows access to RDP port 3389 from the internet.", "compute.googleapis.com/Firewall", "CIS GCP Foundations"},
	{"COMPUTE_SECURE_BOOT_DISABLED", "Shielded VM secure boot is not enabled.", "compute.googleapis.com/Instance", "CIS GCP Foundations"},
	{"IP_FORWARDING_ENABLED", "IP forwarding is enabled on an instance.", "compute.googleapis.com/Instance", "CIS GCP Foundations"},
	{"DEFAULT_SERVICE_ACCOUNT_USED", "A default service account is used.", "compute.googleapis.com/Instance", "CIS GCP Foundations"},
	{"FULL_API_ACCESS", "An instance is configured to use the default service account with full access to all Cloud APIs.", "compute.googleapis.com/Instance", "CIS GCP Foundations"},
	{"SQL_PUBLIC_IP", "Cloud SQL instance has a public IP address.", "sqladmin.googleapis.com/Instance", "CIS GCP Foundations"},
	{"SQL_NO_ROOT_PASSWORD", "A Cloud SQL database instance does not have a root password set.", "sqladmin.googleapis.com/Instance", "CIS GCP Foundations"},
	{"SQL_CROSS_DB_OWNERSHIP_CHAINING", "The cross db ownership chaining database flag for a Cloud SQL for SQL Server instance is on.", "sqladmin.googleapis.com/Instance", "CIS GCP Foundations"},
	{"AUDIT_LOGGING_DISABLED", "Audit logging has been disabled for this resource.", "cloudresourcemanager.googleapis.com/Project", "CIS GCP Foundations"},
	{"KMS_KEY_NOT_ROTATED", "A Cloud KMS key has not been rotated in the last 90 days.", "cloudkms.googleapis.com/CryptoKey", "CIS GCP Foundations"},
	{"OVER_PRIVILEGED_SERVICE_ACCOUNT_USER", "A user has the Service Account User or Service Account Token Creator role at project level.", "iam.googleapis.com/ServiceAccount", "CIS GCP Foundations"},
	{"PRIMITIVE_ROLES_USED", "A user has been granted a basic (primitive) role (Owner, Editor, or Viewer).", "cloudresourcemanager.googleapis.com/Project", "CIS GCP Foundations"},
	{"GKE_NODE_POOL_SECURE_BOOT_DISABLED", "Secure Boot is not enabled for a GKE node pool.", "container.googleapis.com/Cluster", "CIS GCP Foundations"},
	{"CLUSTER_PRIVATE_GOOGLE_ACCESS_DISABLED", "Private Google Access is not enabled on a cluster subnet.", "container.googleapis.com/Cluster", "CIS GCP Foundations"},
	{"MASTER_AUTHORIZED_NETWORKS_DISABLED", "Master Authorized Networks is not enabled on a GKE cluster.", "container.googleapis.com/Cluster", "CIS GCP Foundations"},
}

// --- Weighted random selection ---------------------------------------------

type weightedChoice struct {
	Value  string
	Weight int
}

func pickWeighted(rng *rand.Rand, choices []weightedChoice) string {
	total := 0
	for _, c := range choices {
		total += c.Weight
	}
	n := rng.Intn(total)
	for _, c := range choices {
		n -= c.Weight
		if n < 0 {
			return c.Value
		}
	}
	return choices[len(choices)-1].Value
}

func pickString(rng *rand.Rand, choices []string) string {
	return choices[rng.Intn(len(choices))]
}

func shortHash(parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		h.Write([]byte(p))
		h.Write([]byte("|"))
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// --- AWS ASFF format -------------------------------------------------------

type asffFinding struct {
	SchemaVersion string          `json:"SchemaVersion"`
	ID            string          `json:"Id"`
	ProductARN    string          `json:"ProductArn"`
	GeneratorID   string          `json:"GeneratorId"`
	AWSAccountID  string          `json:"AwsAccountId"`
	Types         []string        `json:"Types"`
	CreatedAt     string          `json:"CreatedAt"`
	UpdatedAt     string          `json:"UpdatedAt"`
	Severity      asffSeverity    `json:"Severity"`
	Title         string          `json:"Title"`
	Description   string          `json:"Description"`
	Resources     []asffResource  `json:"Resources"`
	Workflow      asffWorkflow    `json:"Workflow"`
	RecordState   string          `json:"RecordState"`
	Region        string          `json:"Region"`
	Compliance    *asffCompliance `json:"Compliance,omitempty"`
}

type asffSeverity struct {
	Label      string `json:"Label"`
	Normalized int    `json:"Normalized"`
}

type asffResource struct {
	Type   string `json:"Type"`
	ID     string `json:"Id"`
	Region string `json:"Region"`
}

type asffWorkflow struct {
	Status string `json:"Status"`
}

type asffCompliance struct {
	Status string `json:"Status"`
}

func severityToNormalized(sev string) int {
	switch sev {
	case "CRITICAL":
		return 90
	case "HIGH":
		return 70
	case "MEDIUM":
		return 40
	case "LOW":
		return 1
	default:
		return 0
	}
}

// --- Azure Resource Graph format -------------------------------------------

type azureAssessment struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	SubscriptionID string `json:"subscriptionId"`
	ResourceGroup  string `json:"resourceGroup"`
	Severity       string `json:"severity"`
	Title          string `json:"title"`
	Description    string `json:"description"`
	ResourceID     string `json:"resourceId"`
	Control        string `json:"control"`
	Standard       string `json:"standard"`
	Status         string `json:"status"`
}

// --- GCP SCC format --------------------------------------------------------

type sccFinding struct {
	Name             string            `json:"name"`
	Parent           string            `json:"parent"`
	Category         string            `json:"category"`
	ResourceName     string            `json:"resourceName"`
	State            string            `json:"state"`
	Severity         string            `json:"severity"`
	Description      string            `json:"description"`
	CreateTime       string            `json:"createTime"`
	EventTime        string            `json:"eventTime"`
	SourceProperties map[string]string `json:"sourceProperties"`
}

// --- Normalized finding (matches normalizer.Finding) -----------------------

type normalizedFinding struct {
	FindingID      string `json:"finding_id"`
	FindingIDShort string `json:"finding_id_short"`
	CSP            string `json:"csp"`
	AccountID      string `json:"account_id"`
	ResourceID     string `json:"resource_id"`
	Title          string `json:"title"`
	Description    string `json:"description"`
	Severity       string `json:"severity"`
	Status         string `json:"status"`
	ControlID      string `json:"control_id"`
	Standard       string `json:"standard"`
	CBU            string `json:"cbu"`
	Tier           string `json:"tier"`
	EnvType        string `json:"env_type"`
	Owner          string `json:"owner"`
	FirstSeen      string `json:"first_seen"`
	LastSeen       string `json:"last_seen"`
	DeltaStatus    string `json:"delta_status"`
	DaysOpen       int    `json:"days_open"`
}

// --- Main ------------------------------------------------------------------

func main() {
	count := flag.Int("count", 3000, "findings per CSP")
	outDir := flag.String("out", "./testdata", "output directory")
	seed := flag.Int64("seed", 42, "random seed for deterministic output")
	flag.Parse()

	rng := rand.New(rand.NewSource(*seed))
	now := time.Now()

	fmt.Printf("[*] Generating %d findings per CSP (%d total)\n", *count, *count*3)
	fmt.Printf("[*] Seed: %d\n", *seed)
	fmt.Printf("[*] Output: %s\n", *outDir)

	// AWS accounts
	awsAccounts := []string{"431330216246", "501000277851", "452439730827", "190630619251"}
	awsRegions := []string{"us-west-2", "us-east-1", "eu-west-1", "ap-southeast-1"}

	// Azure subscriptions
	azureSubs := []string{
		"21763a7f-a7d3-4a7d-943a-02eea6f62462",
		"b8c4e9d1-3f2a-4b5c-9e8d-7a6b5c4d3e2f",
		"c9d5e0f2-4g3b-5c6d-0f9e-8b7c6d5e4f3g",
	}
	azureRGs := []string{"rg-infra-prod", "rg-app-prod", "rg-data-prod", "rg-infra-dev", "rg-app-dev", "rg-security"}

	// GCP projects
	gcpProjects := []string{"lvn-dev-483106", "lvn-backup", "lvn-cloudflare", "prj-cmn-mgmt-aggregate-logging"}
	gcpOrg := "123456789"

	owners := []string{"platform-team", "security-team", "app-team-alpha", "app-team-bravo", "data-engineering", "sre-team"}

	// ------- Generate AWS findings -------
	fmt.Print("[/] Generating AWS Security Hub findings... ")
	awsRaw := make([]asffFinding, 0, *count)
	awsNorm := make([]normalizedFinding, 0, *count)

	for i := 0; i < *count; i++ {
		tmpl := awsTemplates[rng.Intn(len(awsTemplates))]
		sev := pickWeighted(rng, severities)
		acct := pickString(rng, awsAccounts)
		region := pickString(rng, awsRegions)
		envType := pickWeighted(rng, envTypes)
		tier := pickWeighted(rng, assetTiers)
		cbu := pickWeighted(rng, cbus)
		owner := pickString(rng, owners)
		dataClass := pickWeighted(rng, dataClassifications)
		_ = dataClass // reserved for scoring enrichment

		daysAgo := rng.Intn(90) + 1
		created := now.AddDate(0, 0, -daysAgo)
		resourceSuffix := fmt.Sprintf("%s-%04d", region, rng.Intn(9999))
		resourceID := fmt.Sprintf("arn:aws:%s:%s:%s:%s",
			resourceTypeToService(tmpl.ResourceType), region, acct, resourceSuffix)

		findingID := fmt.Sprintf("arn:aws:securityhub:%s:%s:finding/%s", region, acct, shortHash(tmpl.GeneratorID, resourceID, acct))

		awsRaw = append(awsRaw, asffFinding{
			SchemaVersion: "2018-10-08",
			ID:            findingID,
			ProductARN:    fmt.Sprintf("arn:aws:securityhub:%s:%s:product/%s/default", region, acct, acct),
			GeneratorID:   tmpl.GeneratorID,
			AWSAccountID:  acct,
			Types:         []string{"Software and Configuration Checks/AWS Security Best Practices"},
			CreatedAt:     created.Format(time.RFC3339),
			UpdatedAt:     now.Format(time.RFC3339),
			Severity:      asffSeverity{Label: sev, Normalized: severityToNormalized(sev)},
			Title:         tmpl.Title,
			Description:   tmpl.Description,
			Resources:     []asffResource{{Type: tmpl.ResourceType, ID: resourceID, Region: region}},
			Workflow:      asffWorkflow{Status: "NEW"},
			RecordState:   "ACTIVE",
			Region:        region,
			Compliance:    &asffCompliance{Status: "FAILED"},
		})

		awsNorm = append(awsNorm, normalizedFinding{
			FindingID:      findingID,
			FindingIDShort: shortHash("aws", acct, tmpl.GeneratorID, resourceID),
			CSP:            "aws",
			AccountID:      acct,
			ResourceID:     resourceID,
			Title:          tmpl.Title,
			Description:    tmpl.Description,
			Severity:       sev,
			Status:         "ACTIVE",
			ControlID:      tmpl.GeneratorID,
			Standard:       tmpl.Standard,
			CBU:            cbu,
			Tier:           tier,
			EnvType:        envType,
			Owner:          owner,
			FirstSeen:      created.Format(time.RFC3339),
			LastSeen:       now.Format(time.RFC3339),
			DeltaStatus:    "NEW",
			DaysOpen:       daysAgo,
		})
	}
	fmt.Printf("%d done\n", len(awsRaw))

	// ------- Generate Azure findings -------
	fmt.Print("[/] Generating Azure Defender findings... ")
	azureRaw := make([]azureAssessment, 0, *count)
	azureNorm := make([]normalizedFinding, 0, *count)

	for i := 0; i < *count; i++ {
		tmpl := azureTemplates[rng.Intn(len(azureTemplates))]
		sev := pickWeighted(rng, severities)
		sub := pickString(rng, azureSubs)
		rg := pickString(rng, azureRGs)
		envType := pickWeighted(rng, envTypes)
		tier := pickWeighted(rng, assetTiers)
		cbu := pickWeighted(rng, cbus)
		owner := pickString(rng, owners)

		daysAgo := rng.Intn(90) + 1
		created := now.AddDate(0, 0, -daysAgo)
		resourceName := fmt.Sprintf("resource-%04d", rng.Intn(9999))
		resourceID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/%s/%s",
			sub, rg, tmpl.ResourceType, resourceName)
		assessmentID := fmt.Sprintf("/subscriptions/%s/providers/Microsoft.Security/assessments/%s/resourceDetails/%s",
			sub, tmpl.AssessmentKey, shortHash(resourceID))

		// Azure severity uses title case
		azSev := sev
		switch sev {
		case "CRITICAL":
			azSev = "High" // Azure Defender doesn't have CRITICAL, maps to High
		case "HIGH":
			azSev = "High"
		case "MEDIUM":
			azSev = "Medium"
		case "LOW":
			azSev = "Low"
		}

		azureRaw = append(azureRaw, azureAssessment{
			ID:             assessmentID,
			Name:           tmpl.AssessmentKey,
			SubscriptionID: sub,
			ResourceGroup:  rg,
			Severity:       azSev,
			Title:          tmpl.Title,
			Description:    tmpl.Description,
			ResourceID:     resourceID,
			Control:        tmpl.AssessmentKey,
			Standard:       tmpl.Standard,
			Status:         "Unhealthy",
		})

		azureNorm = append(azureNorm, normalizedFinding{
			FindingID:      assessmentID,
			FindingIDShort: shortHash("azure", sub, tmpl.AssessmentKey, resourceID),
			CSP:            "azure",
			AccountID:      sub,
			ResourceID:     resourceID,
			Title:          tmpl.Title,
			Description:    tmpl.Description,
			Severity:       sev,
			Status:         "ACTIVE",
			ControlID:      tmpl.AssessmentKey,
			Standard:       tmpl.Standard,
			CBU:            cbu,
			Tier:           tier,
			EnvType:        envType,
			Owner:          owner,
			FirstSeen:      created.Format(time.RFC3339),
			LastSeen:       now.Format(time.RFC3339),
			DeltaStatus:    "NEW",
			DaysOpen:       daysAgo,
		})
	}
	fmt.Printf("%d done\n", len(azureRaw))

	// ------- Generate GCP findings -------
	fmt.Print("[/] Generating GCP SCC findings... ")
	gcpRaw := make([]sccFinding, 0, *count)
	gcpNorm := make([]normalizedFinding, 0, *count)

	for i := 0; i < *count; i++ {
		tmpl := gcpTemplates[rng.Intn(len(gcpTemplates))]
		sev := pickWeighted(rng, severities)
		proj := pickString(rng, gcpProjects)
		envType := pickWeighted(rng, envTypes)
		tier := pickWeighted(rng, assetTiers)
		cbu := pickWeighted(rng, cbus)
		owner := pickString(rng, owners)

		daysAgo := rng.Intn(90) + 1
		created := now.AddDate(0, 0, -daysAgo)
		resourceSuffix := fmt.Sprintf("%04d", rng.Intn(9999))
		resourceName := fmt.Sprintf("//%.s/projects/%s/%s-%s",
			tmpl.ResourceType, proj, tmpl.Category, resourceSuffix)
		findingName := fmt.Sprintf("organizations/%s/sources/1234567890/findings/%s",
			gcpOrg, shortHash(tmpl.Category, proj, resourceSuffix))

		gcpRaw = append(gcpRaw, sccFinding{
			Name:         findingName,
			Parent:       fmt.Sprintf("organizations/%s/sources/1234567890", gcpOrg),
			Category:     tmpl.Category,
			ResourceName: resourceName,
			State:        "ACTIVE",
			Severity:     sev,
			Description:  tmpl.Description,
			CreateTime:   created.Format(time.RFC3339),
			EventTime:    now.Format(time.RFC3339),
			SourceProperties: map[string]string{
				"ResourceType": tmpl.ResourceType,
				"ProjectId":    proj,
				"Explanation":  tmpl.Description,
			},
		})

		gcpNorm = append(gcpNorm, normalizedFinding{
			FindingID:      findingName,
			FindingIDShort: shortHash("gcp", proj, tmpl.Category, resourceName),
			CSP:            "gcp",
			AccountID:      proj,
			ResourceID:     resourceName,
			Title:          tmpl.Category,
			Description:    tmpl.Description,
			Severity:       sev,
			Status:         "ACTIVE",
			ControlID:      tmpl.Category,
			Standard:       tmpl.Standard,
			CBU:            cbu,
			Tier:           tier,
			EnvType:        envType,
			Owner:          owner,
			FirstSeen:      created.Format(time.RFC3339),
			LastSeen:       now.Format(time.RFC3339),
			DeltaStatus:    "NEW",
			DaysOpen:       daysAgo,
		})
	}
	fmt.Printf("%d done\n", len(gcpRaw))

	// ------- Write output files -------
	rawDir := filepath.Join(*outDir, "raw")
	normDir := filepath.Join(*outDir, "normalized")
	_ = os.MkdirAll(rawDir, 0o755)
	_ = os.MkdirAll(normDir, 0o755)

	writeJSON(filepath.Join(rawDir, "aws_securityhub_findings.json"), awsRaw)
	writeJSON(filepath.Join(rawDir, "azure_defender_assessments.json"), azureRaw)
	writeJSON(filepath.Join(rawDir, "gcp_scc_findings.json"), gcpRaw)

	allNorm := make([]normalizedFinding, 0, len(awsNorm)+len(azureNorm)+len(gcpNorm))
	allNorm = append(allNorm, awsNorm...)
	allNorm = append(allNorm, azureNorm...)
	allNorm = append(allNorm, gcpNorm...)

	writeJSON(filepath.Join(normDir, "all_findings.json"), allNorm)
	writeJSON(filepath.Join(normDir, "aws_findings.json"), awsNorm)
	writeJSON(filepath.Join(normDir, "azure_findings.json"), azureNorm)
	writeJSON(filepath.Join(normDir, "gcp_findings.json"), gcpNorm)

	// ------- Summary -------
	fmt.Println()
	fmt.Println("[+] Generation complete:")
	fmt.Printf("    AWS:    %d findings  -> %s/aws_securityhub_findings.json\n", len(awsRaw), rawDir)
	fmt.Printf("    Azure:  %d findings  -> %s/azure_defender_assessments.json\n", len(azureRaw), rawDir)
	fmt.Printf("    GCP:    %d findings  -> %s/gcp_scc_findings.json\n", len(gcpRaw), rawDir)
	fmt.Printf("    Normal: %d findings  -> %s/all_findings.json\n", len(allNorm), normDir)
	fmt.Println()

	// Distribution stats
	sevCounts := map[string]int{}
	envCounts := map[string]int{}
	cspCounts := map[string]int{}
	for _, f := range allNorm {
		sevCounts[f.Severity]++
		envCounts[f.EnvType]++
		cspCounts[f.CSP]++
	}
	fmt.Println("[*] Severity distribution:")
	for _, s := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"} {
		fmt.Printf("    %-12s %5d  (%.1f%%)\n", s, sevCounts[s], float64(sevCounts[s])/float64(len(allNorm))*100)
	}
	fmt.Println()
	fmt.Println("[*] Environment distribution:")
	for _, e := range []string{"prod", "staging", "dev", "sandbox"} {
		fmt.Printf("    %-12s %5d  (%.1f%%)\n", e, envCounts[e], float64(envCounts[e])/float64(len(allNorm))*100)
	}
}

func writeJSON(path string, v interface{}) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Error marshaling %s: %v\n", path, err)
		os.Exit(1)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "[!] Error writing %s: %v\n", path, err)
		os.Exit(1)
	}
	fmt.Printf("    Wrote %s (%.1f MB)\n", path, float64(len(data))/1024/1024)
}

func resourceTypeToService(rt string) string {
	switch rt {
	case "AwsS3Bucket":
		return "s3"
	case "AwsEc2Instance":
		return "ec2"
	case "AwsEc2SecurityGroup":
		return "ec2"
	case "AwsIamPolicy", "AwsIamUser":
		return "iam"
	case "AwsRdsDbInstance", "AwsRdsDbSnapshot":
		return "rds"
	case "AwsLambdaFunction":
		return "lambda"
	case "AwsElbv2LoadBalancer":
		return "elasticloadbalancing"
	case "AwsKmsKey":
		return "kms"
	case "AwsCloudTrailTrail":
		return "cloudtrail"
	case "AwsEcrRepository":
		return "ecr"
	case "AwsEcsTaskDefinition":
		return "ecs"
	case "AwsSnsTopic":
		return "sns"
	case "AwsSqsQueue":
		return "sqs"
	default:
		return "unknown"
	}
}
