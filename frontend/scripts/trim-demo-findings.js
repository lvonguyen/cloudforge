#!/usr/bin/env node
/**
 * trim-demo-findings.js
 *
 * Reduces dist/mock/findings.json from ~42MB (20k findings) to a
 * representative ~500-finding subset for Cloudflare Pages deployment
 * (25MB per-file limit). Uses stratified sampling to preserve the
 * proportional distribution across severity, cloud_provider, category,
 * and status dimensions.
 *
 * Called automatically by the build script after `vite build`.
 */

import { readFileSync, writeFileSync, existsSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const FINDINGS_PATH = join(__dirname, '..', 'dist', 'mock', 'findings.json')
const TARGET_COUNT = 500

if (!existsSync(FINDINGS_PATH)) {
  console.log('[trim-demo] dist/mock/findings.json not found — skipping (LFS pointer?)')
  process.exit(0)
}

const raw = readFileSync(FINDINGS_PATH, 'utf8')

// LFS pointer files start with "version https://git-lfs"
if (raw.startsWith('version https://git-lfs')) {
  console.log('[trim-demo] findings.json is an LFS pointer — skipping')
  process.exit(0)
}

const findings = JSON.parse(raw)

if (findings.length <= TARGET_COUNT) {
  console.log(`[trim-demo] ${findings.length} findings already <= ${TARGET_COUNT} — no trim needed`)
  process.exit(0)
}

// Stratified sampling: bucket by composite key, then proportionally draw
const buckets = new Map()
for (const f of findings) {
  const key = `${f.severity}|${f.cloud_provider}|${f.category}|${f.status}`
  if (!buckets.has(key)) buckets.set(key, [])
  buckets.get(key).push(f)
}

// Deterministic shuffle (seeded Fisher-Yates with simple LCG)
function seededShuffle(arr, seed = 42) {
  let s = seed
  const lcg = () => { s = (s * 1664525 + 1013904223) & 0x7fffffff; return s / 0x7fffffff }
  for (let i = arr.length - 1; i > 0; i--) {
    const j = Math.floor(lcg() * (i + 1))
    ;[arr[i], arr[j]] = [arr[j], arr[i]]
  }
  return arr
}

const sampled = []
// Proportional allocation: each bucket gets ceil(bucket.length / total * TARGET)
for (const [, items] of buckets) {
  const count = Math.max(1, Math.ceil((items.length / findings.length) * TARGET_COUNT))
  seededShuffle(items)
  sampled.push(...items.slice(0, count))
}

// If oversampled due to ceil rounding, trim back; if under, we keep what we have
seededShuffle(sampled)
const result = sampled.slice(0, TARGET_COUNT)

writeFileSync(FINDINGS_PATH, JSON.stringify(result))

const sizeMB = (Buffer.byteLength(JSON.stringify(result)) / 1024 / 1024).toFixed(2)
console.log(`[trim-demo] ${findings.length} -> ${result.length} findings (${sizeMB} MB)`)
