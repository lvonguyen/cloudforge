/**
 * RQL (Resource Query Language) client-side parser.
 * Parses structured queries like `severity=CRITICAL AND provider=aws`
 * into NLQFilters for direct use without an AI backend call.
 *
 * Grammar:
 *   query     = condition (('AND'|'OR') condition)*
 *   condition = field '=' value | field '!=' value
 *   field     = identifier
 *   value     = quoted_string | bare_word
 */

import type { NLQFilterField, NLQFilters } from '@/types/nlq'

export interface RQLToken {
  type: 'field' | 'op' | 'value' | 'logic'
  value: string
}

export interface RQLCondition {
  field: string
  op: '=' | '!='
  value: string
}

export interface RQLQuery {
  conditions: RQLCondition[]
  operators: ('AND' | 'OR')[]
}

const FIELD_ALIASES: Record<string, string> = {
  sev: 'severity',
  cloud: 'provider',
  cloud_provider: 'provider',
  env: 'environment',
  environment_type: 'environment',
  cat: 'category',
  stat: 'status',
}

const NLQ_FILTER_FIELDS = new Set<NLQFilterField>(['severity', 'provider', 'category', 'status', 'environment'])

function normalizeField(field: string): string {
  const lower = field.toLowerCase()
  return FIELD_ALIASES[lower] ?? lower
}

function isNLQFilterField(field: string): field is NLQFilterField {
  return NLQ_FILTER_FIELDS.has(field as NLQFilterField)
}

function tokenize(input: string): RQLToken[] {
  const tokens: RQLToken[] = []
  let i = 0
  const src = input.trim()

  while (i < src.length) {
    // Skip whitespace
    while (i < src.length && /\s/.test(src[i])) i++
    if (i >= src.length) break

    // Logic operators (AND / OR)
    if (src.slice(i, i + 3).toUpperCase() === 'AND' && (i + 3 >= src.length || /\s/.test(src[i + 3]))) {
      tokens.push({ type: 'logic', value: 'AND' })
      i += 3
      continue
    }
    if (src.slice(i, i + 2).toUpperCase() === 'OR' && (i + 2 >= src.length || /\s/.test(src[i + 2]))) {
      tokens.push({ type: 'logic', value: 'OR' })
      i += 2
      continue
    }

    // Operators (!=, =)
    if (src[i] === '!' && src[i + 1] === '=') {
      tokens.push({ type: 'op', value: '!=' })
      i += 2
      continue
    }
    if (src[i] === '=') {
      tokens.push({ type: 'op', value: '=' })
      i += 1
      continue
    }

    // Quoted string
    if (src[i] === '"' || src[i] === "'") {
      const quote = src[i]
      i++
      let val = ''
      while (i < src.length && src[i] !== quote) {
        val += src[i]
        i++
      }
      if (i < src.length) i++ // skip closing quote
      tokens.push({ type: 'value', value: val })
      continue
    }

    // Bare word (field name or value)
    let word = ''
    while (i < src.length && !/[\s=!]/.test(src[i])) {
      word += src[i]
      i++
    }
    if (word) {
      // Determine if this is a field or value based on context
      const prev = tokens[tokens.length - 1]
      if (prev?.type === 'op') {
        tokens.push({ type: 'value', value: word })
      } else {
        tokens.push({ type: 'field', value: word })
      }
    }
  }

  return tokens
}

export function parseRQL(input: string): RQLQuery {
  const tokens = tokenize(input)
  const conditions: RQLCondition[] = []
  const operators: ('AND' | 'OR')[] = []

  let i = 0
  while (i < tokens.length) {
    if (tokens[i].type === 'field' && tokens[i + 1]?.type === 'op' && tokens[i + 2]?.type === 'value') {
      conditions.push({
        field: normalizeField(tokens[i].value),
        op: tokens[i + 1].value as '=' | '!=',
        value: tokens[i + 2].value,
      })
      i += 3
    } else if (tokens[i].type === 'logic') {
      operators.push(tokens[i].value.toUpperCase() as 'AND' | 'OR')
      i++
    } else {
      i++ // skip unexpected tokens
    }
  }

  return { conditions, operators }
}

/** Convert parsed RQL into NLQFilters for consumption by filter dispatch. */
export function rqlToFilters(query: RQLQuery): NLQFilters {
  const filters: NLQFilters = {}

  for (const cond of query.conditions) {
    if (!isNLQFilterField(cond.field)) continue

    if (cond.op === '!=') {
      const exclude = filters.exclude ?? {}
      exclude[cond.field] = [...(exclude[cond.field] ?? []), cond.value]
      filters.exclude = exclude
      continue
    }

    filters[cond.field] = [...(filters[cond.field] ?? []), cond.value]
  }

  return filters
}

/** Validate that an RQL string is parseable and contains at least one condition. */
export function isValidRQL(input: string): boolean {
  if (!input.trim()) return false
  const query = parseRQL(input)
  return query.conditions.length > 0
}

/** RQL syntax hint shown in the query bar overlay. */
export const RQL_SYNTAX_HINT =
  'severity=CRITICAL AND provider=aws · status!=resolved · category=misconfiguration OR category=vulnerability'
