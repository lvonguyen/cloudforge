#!/usr/bin/env node
/**
 * enrich-findings-bedrock.mjs
 *
 * Offline script that enriches findings with AI-generated impacted_resources
 * and toxic_combo_details using AWS Bedrock (Sonnet 4.6).
 *
 * Usage:
 *   node scripts/enrich-findings-bedrock.mjs [options]
 *
 * Options:
 *   --input <path>     Input findings JSON (default: frontend/public/mock/findings.json)
 *   --output <path>    Output enriched JSON (default: stdout)
 *   --dry-run          Show what would be enriched without calling Bedrock
 *   --force            Bypass monthly budget check
 *   --max-accounts <n> Limit to N accounts (default: all)
 *
 * Environment:
 *   AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY — or use `op run --` prefix
 *   BEDROCK_REGION (default: us-east-1)
 *   BEDROCK_MODEL (default: us.anthropic.claude-sonnet-4-6)
 *   BEDROCK_MONTHLY_BUDGET_CENTS (default: 1500 = $15)
 */

import { readFileSync, writeFileSync } from 'fs'

// --- CLI args ---
const args = process.argv.slice(2)
const getArg = (name) => { const i = args.indexOf(name); return i !== -1 ? args[i + 1] : undefined }
const hasFlag = (name) => args.includes(name)

const INPUT_PATH = getArg('--input') ?? 'frontend/public/mock/findings.json'
const OUTPUT_PATH = getArg('--output')
const DRY_RUN = hasFlag('--dry-run')
const FORCE = hasFlag('--force')
const MAX_ACCOUNTS = parseInt(getArg('--max-accounts') ?? '0', 10) || Infinity

const REGION = process.env.BEDROCK_REGION ?? 'us-east-1'
const MODEL_ID = process.env.BEDROCK_MODEL ?? 'us.anthropic.claude-sonnet-4-6'
const BUDGET_CENTS = parseInt(process.env.BEDROCK_MONTHLY_BUDGET_CENTS ?? '1500', 10)

// Cost rates: Sonnet 4.6 input ~$3/MTok, output ~$15/MTok
const INPUT_COST_PER_MTOK = 3.0
const OUTPUT_COST_PER_MTOK = 15.0

// --- Load findings ---
console.error(`[+] Loading findings from ${INPUT_PATH}`)
const findings = JSON.parse(readFileSync(INPUT_PATH, 'utf-8'))
console.error(`[+] ${findings.length} findings loaded`)

// --- Group by account ---
const byAccount = new Map()
for (const f of findings) {
  if (!byAccount.has(f.account_id)) byAccount.set(f.account_id, [])
  byAccount.get(f.account_id).push(f)
}

const accountIds = [...byAccount.keys()].filter(id => byAccount.get(id).length > 5)
const accountsToProcess = accountIds.slice(0, MAX_ACCOUNTS)

console.error(`[+] ${byAccount.size} accounts, ${accountsToProcess.length} eligible (>5 findings)`)

if (DRY_RUN) {
  console.error('[!] DRY RUN — showing enrichment plan:')
  let totalTokensEst = 0
  for (const accId of accountsToProcess) {
    const acctFindings = byAccount.get(accId)
    const critHigh = acctFindings.filter(f => f.severity === 'CRITICAL' || f.severity === 'HIGH')
    const tokenEst = Math.ceil(JSON.stringify(acctFindings.map(f => ({
      id: f.id, resource_id: f.resource_id, resource_name: f.resource_name,
      resource_type: f.resource_type, severity: f.severity, category: f.category,
    }))).length / 4)
    totalTokensEst += tokenEst
    console.error(`  Account ${accId}: ${acctFindings.length} findings (${critHigh.length} CRIT/HIGH), ~${tokenEst} input tokens`)
  }
  const estInputCost = (totalTokensEst / 1_000_000) * INPUT_COST_PER_MTOK
  const estOutputCost = (totalTokensEst * 2 / 1_000_000) * OUTPUT_COST_PER_MTOK // assume 2x output
  const estTotalCost = estInputCost + estOutputCost
  console.error(`\n  Estimated cost: $${estTotalCost.toFixed(3)} (${accountsToProcess.length} API calls)`)
  console.error(`  Budget: $${(BUDGET_CENTS / 100).toFixed(2)}/month`)
  console.error(`  Budget usage: ${((estTotalCost * 100 / BUDGET_CENTS) * 100).toFixed(1)}%`)
  process.exit(0)
}

// --- Bedrock SDK ---
let BedrockRuntimeClient, InvokeModelCommand
try {
  const mod = await import('@aws-sdk/client-bedrock-runtime')
  BedrockRuntimeClient = mod.BedrockRuntimeClient
  InvokeModelCommand = mod.InvokeModelCommand
} catch {
  console.error('[!] @aws-sdk/client-bedrock-runtime not installed. Run: npm install @aws-sdk/client-bedrock-runtime')
  process.exit(1)
}

const client = new BedrockRuntimeClient({ region: REGION })

// --- Budget tracking ---
let totalCostCents = 0

async function callBedrock(systemPrompt, userPrompt) {
  const body = JSON.stringify({
    anthropic_version: 'bedrock-2023-05-31',
    max_tokens: 4096,
    system: systemPrompt,
    messages: [{ role: 'user', content: userPrompt }],
  })

  const command = new InvokeModelCommand({
    modelId: MODEL_ID,
    contentType: 'application/json',
    accept: 'application/json',
    body: new TextEncoder().encode(body),
  })

  const response = await client.send(command)
  const result = JSON.parse(new TextDecoder().decode(response.body))

  // Track cost
  const inputTokens = result.usage?.input_tokens ?? Math.ceil(userPrompt.length / 4)
  const outputTokens = result.usage?.output_tokens ?? Math.ceil((result.content?.[0]?.text?.length ?? 0) / 4)
  const costMicros = (inputTokens * INPUT_COST_PER_MTOK + outputTokens * OUTPUT_COST_PER_MTOK) / 1_000_000 * 100
  totalCostCents += costMicros

  return result.content?.[0]?.text ?? ''
}

const SYSTEM_PROMPT = `You are a cloud security analyst. Given a set of findings for a single cloud account, identify which resources impact each other and any toxic combinations. Respond ONLY with valid JSON matching this schema:
{
  "impacted_resources": [
    { "finding_id": "src_finding_id", "targets": [{ "resource_id": "...", "resource_name": "...", "resource_type": "...", "severity": "HIGH" }] }
  ],
  "toxic_combos": [
    { "finding_ids": ["id1", "id2"], "combo_type": "privilege_escalation|data_exfiltration|lateral_movement|network_exposure|credential_theft", "description": "..." }
  ]
}
Only include real relationships where one resource's compromise would credibly affect another.`

// --- Process accounts ---
console.error(`[+] Processing ${accountsToProcess.length} accounts with Bedrock ${MODEL_ID}`)

for (let i = 0; i < accountsToProcess.length; i++) {
  const accId = accountsToProcess[i]
  const acctFindings = byAccount.get(accId)

  // Budget guard: abort if >50% of monthly budget used in this run
  if (!FORCE && totalCostCents > BUDGET_CENTS * 0.5) {
    console.error(`[!] Budget guard: $${(totalCostCents / 100).toFixed(2)} spent (>${BUDGET_CENTS * 0.5 / 100} limit). Use --force to override.`)
    break
  }

  const summaries = acctFindings.map(f => ({
    id: f.id, resource_id: f.resource_id, resource_name: f.resource_name,
    resource_type: f.resource_type, severity: f.severity, category: f.category,
    region: f.region,
  }))

  const userPrompt = `Account: ${accId}\nFindings:\n${JSON.stringify(summaries, null, 0)}`

  try {
    console.error(`  [${i + 1}/${accountsToProcess.length}] Account ${accId} (${acctFindings.length} findings)`)
    const response = await callBedrock(SYSTEM_PROMPT, userPrompt)

    // Parse JSON from response
    const jsonStart = response.indexOf('{')
    const jsonEnd = response.lastIndexOf('}')
    if (jsonStart === -1 || jsonEnd === -1) {
      console.error(`    [!] No JSON in response, skipping`)
      continue
    }

    const result = JSON.parse(response.slice(jsonStart, jsonEnd + 1))

    // Apply impacted_resources
    if (result.impacted_resources) {
      for (const ir of result.impacted_resources) {
        const finding = findings.find(f => f.id === ir.finding_id)
        if (finding && ir.targets?.length > 0) {
          finding.impacted_resources = ir.targets
        }
      }
    }

    // Apply toxic_combos
    if (result.toxic_combos) {
      for (const tc of result.toxic_combos) {
        if (!tc.finding_ids?.length) continue
        const primaryFinding = findings.find(f => f.id === tc.finding_ids[0])
        if (primaryFinding) {
          primaryFinding.toxic_combo_details = {
            combo_type: tc.combo_type ?? 'lateral_movement',
            description: tc.description ?? '',
            related_findings: tc.finding_ids.slice(1),
            attack_vector: 'network',
            attack_path: ['Internet', primaryFinding.resource_name],
            exploit_potential: primaryFinding.severity === 'CRITICAL' ? 'active' : 'possible',
            blast_radius: 'account',
            mitre_techniques: [],
          }
        }
      }
    }

    console.error(`    [+] Applied ${result.impacted_resources?.length ?? 0} impact links, ${result.toxic_combos?.length ?? 0} toxic combos`)
  } catch (err) {
    console.error(`    [!] Error: ${err.message}`)
  }

  // Small delay between accounts
  if (i < accountsToProcess.length - 1) {
    await new Promise(r => setTimeout(r, 200))
  }
}

// --- Output ---
const output = JSON.stringify(findings)

if (OUTPUT_PATH) {
  writeFileSync(OUTPUT_PATH, output)
  console.error(`[+] Written to ${OUTPUT_PATH}`)
} else {
  process.stdout.write(output)
}

const irCount = findings.filter(f => f.impacted_resources?.length > 0).length
const tcCount = findings.filter(f => f.toxic_combo_details).length
console.error(`\n[+] Done. ${irCount} findings with impacted_resources, ${tcCount} with toxic_combo_details`)
console.error(`[+] Estimated cost: $${(totalCostCents / 100).toFixed(3)}`)
