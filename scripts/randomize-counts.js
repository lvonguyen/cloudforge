#!/usr/bin/env node

/**
 * Randomly removes 150-1000 findings from findings.json using seeded PRNG.
 * Produces reproducible output (seed=42). Removal is uniform across severities.
 *
 * Usage: node scripts/randomize-counts.js
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const SEED = 42;
const MIN_REMOVE = 150;
const MAX_REMOVE = 1000;
const FINDINGS_PATH = path.resolve(__dirname, '../frontend/public/mock/findings.json');

/** Seeded PRNG using SHA-256 counter mode. */
class SeededRandom {
  constructor(seed) {
    this.seed = String(seed);
    this.counter = 0;
  }

  /** Returns a float in [0, 1). */
  next() {
    const hash = crypto
      .createHash('sha256')
      .update(`${this.seed}:${this.counter++}`)
      .digest();
    // Use first 4 bytes as uint32, divide by 2^32.
    const value = hash.readUInt32BE(0) / 0x100000000;
    return value;
  }

  /** Returns an integer in [min, max] inclusive. */
  nextInt(min, max) {
    return min + Math.floor(this.next() * (max - min + 1));
  }
}

/** Fisher-Yates shuffle (in-place) using seeded PRNG. */
function shuffle(arr, rng) {
  for (let i = arr.length - 1; i > 0; i--) {
    const j = rng.nextInt(0, i);
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  return arr;
}

/** Count findings per severity level. */
function severityBreakdown(findings) {
  const counts = {};
  for (const f of findings) {
    const sev = f.severity || f.Severity || 'UNKNOWN';
    counts[sev] = (counts[sev] || 0) + 1;
  }
  return counts;
}

function main() {
  if (!fs.existsSync(FINDINGS_PATH)) {
    console.error(`[!] File not found: ${FINDINGS_PATH}`);
    console.error('    Make sure Git LFS has pulled the mock data.');
    process.exit(1);
  }

  console.log(`[*] Reading ${FINDINGS_PATH}...`);
  const raw = fs.readFileSync(FINDINGS_PATH, 'utf-8');
  const findings = JSON.parse(raw);
  const beforeCount = findings.length;

  if (beforeCount <= MIN_REMOVE) {
    console.error(`[!] Only ${beforeCount} findings — too few to trim (min removal: ${MIN_REMOVE}).`);
    process.exit(1);
  }

  const rng = new SeededRandom(SEED);
  const removeCount = rng.nextInt(MIN_REMOVE, Math.min(MAX_REMOVE, beforeCount - 1));

  // Build index array, shuffle, and pick first N to remove.
  const indices = Array.from({ length: beforeCount }, (_, i) => i);
  shuffle(indices, rng);
  const removeSet = new Set(indices.slice(0, removeCount));

  const kept = findings.filter((_, i) => !removeSet.has(i));

  const beforeBreakdown = severityBreakdown(findings);
  const afterBreakdown = severityBreakdown(kept);

  // Write back.
  fs.writeFileSync(FINDINGS_PATH, JSON.stringify(kept, null, 2) + '\n', 'utf-8');

  // Summary.
  console.log(`[+] Trimmed ${beforeCount} -> ${kept.length} findings (removed ${removeCount})`);
  console.log();
  console.log('    Severity breakdown:');
  const allSeverities = [...new Set([...Object.keys(beforeBreakdown), ...Object.keys(afterBreakdown)])].sort();
  for (const sev of allSeverities) {
    const before = beforeBreakdown[sev] || 0;
    const after = afterBreakdown[sev] || 0;
    console.log(`      ${sev.padEnd(12)} ${before} -> ${after}  (-${before - after})`);
  }
  console.log();
  console.log(`[*] Seed: ${SEED} (deterministic — same input always produces same output)`);
}

main();
