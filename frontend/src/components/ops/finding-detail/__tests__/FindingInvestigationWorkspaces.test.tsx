import { describe, expect, it, vi } from "vitest";
import { screen } from "@testing-library/react";
import { renderWithProviders } from "@/test/utils";
import { FindingAttackPathWorkspace } from "@/components/ops/finding-detail/FindingAttackPathWorkspace";
import { FindingSecurityGraphWorkspace } from "@/components/ops/finding-detail/FindingSecurityGraphWorkspace";
import type { AttackPath } from "@/types/attack-path";
import type { Finding } from "@/types/compliance";

const SAMPLE_FINDING: Finding = {
  id: "f-001",
  source: "wiz",
  source_finding_id: "wiz-123",
  type: "cloud",
  title: "Public workload can reach production database",
  description:
    "An exposed workload has a reachable path into a sensitive database tier.",
  resource_type: "compute",
  resource_id: "res-1",
  resource_name: "public-api",
  platform: "aws",
  cloud_provider: "aws",
  region: "us-east-1",
  account_id: "123456789012",
  account_name: "prod",
  environment_type: "production",
  impacted_resources: [
    {
      resource_id: "res-2",
      resource_name: "orders-db",
      resource_type: "database",
      relationship: "reachable",
      impact_level: "high",
    },
  ],
  static_severity: "HIGH",
  severity: "HIGH",
  ai_risk_score: 8.7,
  ai_risk_level: "high",
  ai_risk_rationale:
    "Exposure plus privilege chaining makes this materially exploitable.",
  ai_contextual_factors: ["internet_exposed", "production", "sensitive_data"],
  exploit_available: true,
  remediation: "Restrict ingress and tighten identity permissions.",
  auto_remediatable: false,
  category: "NETWORK",
  status: "open",
  workflow_status: "in_progress",
  assignee: {
    user_id: "u-1",
    user_email: "analyst@example.com",
    user_name: "Alex Analyst",
    team: "Detection",
    assigned_at: "2026-03-29T16:00:00Z",
    assigned_by: "lead@example.com",
    escalated: false,
  },
  service_name: "orders-api",
  line_of_business: "Commerce",
  first_found_at: "2026-03-28T10:00:00Z",
  last_seen_at: "2026-03-30T10:00:00Z",
  due_date: "2026-04-02T10:00:00Z",
  deduplication_key: "dedup-1",
  canonical_rule_id: "CF-001",
  compliance_mappings: [
    {
      framework_id: "cis-aws",
      framework_name: "CIS AWS",
      control_id: "1.2",
      control_title: "Ensure public access is restricted",
      section: "Identity and Access Management",
      severity: "HIGH",
      url: "https://example.com/control",
    },
  ],
  mitre_tactics: ["TA0001"],
  mitre_techniques: ["T1190"],
  suppressed: false,
};

const SAMPLE_PATH: AttackPath = {
  id: "path-1",
  title: "Public compute to production database",
  description:
    "Internet exposure pivots through over-permissive access to a database.",
  severity: "HIGH",
  score: 88,
  hop_count: 3,
  entry_point: {
    id: "node-1",
    finding_id: "f-001",
    resource_id: "res-1",
    resource_name: "public-api",
    resource_type: "ecs_task",
    provider: "aws",
    account_id: "123456789012",
    region: "us-east-1",
    severity: "HIGH",
    category: "NETWORK",
    label: "Public API",
  },
  target: {
    id: "node-3",
    finding_id: "f-003",
    resource_id: "res-3",
    resource_name: "orders-db",
    resource_type: "rds_instance",
    provider: "aws",
    account_id: "123456789012",
    region: "us-east-1",
    severity: "HIGH",
    category: "DATABASE",
    label: "Orders DB",
  },
  nodes: [],
  edges: [],
  mitre_tactics: ["TA0001"],
  finding_ids: ["f-001", "f-003"],
  ai_enriched: true,
  ai_description: "Validated lateral path from ingress to crown jewel.",
};

describe("Finding investigation workspaces", () => {
  it("renders the attack-path load state inline under the finding", () => {
    renderWithProviders(
      <FindingAttackPathWorkspace
        finding={SAMPLE_FINDING}
        relatedPaths={[]}
        attackPathsEnabled={false}
        onLoadAttackPaths={vi.fn()}
        onOpenSecurityGraph={vi.fn()}
      />,
    );

    expect(
      screen.getByText("Load attack-path analysis for this finding"),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: /load attack path analysis/i }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: /open security graph context/i }),
    ).toBeInTheDocument();
  });

  it("renders security-graph timeline and control context inline", () => {
    renderWithProviders(
      <FindingSecurityGraphWorkspace
        finding={SAMPLE_FINDING}
        relatedPaths={[SAMPLE_PATH]}
        ticketLinked
        enrichment={{
          root_cause:
            "Exposure and excessive identity trust create a direct path to data.",
          impact:
            "An attacker can move from the public workload into the database plane.",
          remediation: "Restrict exposure and tighten privileges.",
          related_controls: ["internet_exposed && data_access"],
          enriched_at: "2026-03-30T11:00:00Z",
        }}
        onOpenTimeline={vi.fn()}
        onOpenAttackPath={vi.fn()}
      />,
    );

    expect(screen.getByText("Security Graph Context")).toBeInTheDocument();
    expect(screen.getByText("Timeline Context")).toBeInTheDocument();
    expect(screen.getByText("Attack path linked")).toBeInTheDocument();
    expect(screen.getByText("Analyst Briefing")).toBeInTheDocument();
    expect(
      screen.getByText("Containment order for this finding"),
    ).toBeInTheDocument();
    expect(screen.getByText("Exploit available")).toBeInTheDocument();
    expect(screen.getByText("Internet exposed")).toBeInTheDocument();
    expect(screen.getByText("Graph Reasoning")).toBeInTheDocument();
    expect(screen.getByText("Operator Cue")).toBeInTheDocument();
    expect(
      screen.getByText("internet_exposed && data_access"),
    ).toBeInTheDocument();
  });
});
