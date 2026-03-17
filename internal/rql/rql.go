// Package rql implements a Resource Query Language parser and evaluator.
// Grammar:
//
//	query      = condition { ("AND" | "OR") condition }
//	condition  = field operator value
//	field      = identifier { "." identifier }
//	operator   = "=" | "!=" | ">" | ">=" | "<" | "<="
//	value      = quoted_string | unquoted_word
package rql

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"
)

// TokenType identifies lexer tokens.
type TokenType int

const (
	TokenField TokenType = iota
	TokenOp
	TokenValue
	TokenAnd
	TokenOr
	TokenEOF
)

// Token is a lexed unit.
type Token struct {
	Type  TokenType
	Value string
}

// Operator is a comparison operator.
type Operator int

const (
	OpEq  Operator = iota // =
	OpNeq                 // !=
	OpGt                  // >
	OpGte                 // >=
	OpLt                  // <
	OpLte                 // <=
)

// Condition is a single field-operator-value predicate.
type Condition struct {
	Field string
	Op    Operator
	Value string
}

// Junction connects conditions.
type Junction int

const (
	JuncNone Junction = iota
	JuncAnd
	JuncOr
)

// Query is the parsed AST: a flat list of conditions connected by junctions.
type Query struct {
	Conditions []Condition
	Junctions  []Junction // len = len(Conditions)-1
}

// FieldAccessor returns the string value of a named field on the target object.
type FieldAccessor func(field string) (value string, ok bool)

// OrderedField provides numeric ordering for a field's values.
// Lower number = higher priority (e.g. CRITICAL=1, HIGH=2).
type OrderedField func(value string) (priority int, ok bool)

// Evaluator applies parsed queries against objects.
type Evaluator struct {
	accessor FieldAccessor
	ordered  map[string]OrderedField
}

// NewEvaluator creates a query evaluator.
func NewEvaluator(accessor FieldAccessor, ordered map[string]OrderedField) *Evaluator {
	return &Evaluator{accessor: accessor, ordered: ordered}
}

// Parse lexes and parses an RQL query string.
func Parse(input string) (*Query, error) {
	tokens, err := lex(input)
	if err != nil {
		return nil, err
	}
	return parse(tokens)
}

// Match evaluates a parsed query against an object via the configured accessor.
func (e *Evaluator) Match(q *Query) bool {
	if len(q.Conditions) == 0 {
		return true
	}

	results := make([]bool, len(q.Conditions))
	for i, cond := range q.Conditions {
		results[i] = e.evalCondition(cond)
	}

	// Evaluate left to right: AND binds tighter than OR.
	// Group by OR segments, each segment is ANDed together.
	result := results[0]
	for i, junc := range q.Junctions {
		next := results[i+1]
		switch junc {
		case JuncAnd:
			result = result && next
		case JuncOr:
			result = result || next
		}
	}
	return result
}

func (e *Evaluator) evalCondition(c Condition) bool {
	fieldVal, ok := e.accessor(c.Field)
	if !ok {
		return false
	}

	// Check if this field has ordered semantics (e.g. severity).
	if orderedFn, hasOrder := e.ordered[c.Field]; hasOrder {
		return e.evalOrdered(fieldVal, c.Op, c.Value, orderedFn)
	}

	// Default: string comparison (case-insensitive for = and !=).
	switch c.Op {
	case OpEq:
		return strings.EqualFold(fieldVal, c.Value)
	case OpNeq:
		return !strings.EqualFold(fieldVal, c.Value)
	case OpGt, OpGte, OpLt, OpLte:
		// Try numeric comparison.
		if fv, err := strconv.ParseFloat(fieldVal, 64); err == nil {
			if cv, err2 := strconv.ParseFloat(c.Value, 64); err2 == nil {
				return compareFloat(fv, c.Op, cv)
			}
		}
		return false
	}
	return false
}

func (e *Evaluator) evalOrdered(fieldVal string, op Operator, queryVal string, orderedFn OrderedField) bool {
	fp, fok := orderedFn(strings.ToUpper(fieldVal))
	qp, qok := orderedFn(strings.ToUpper(queryVal))
	if !fok || !qok {
		// Fall back to string equality.
		if op == OpEq {
			return strings.EqualFold(fieldVal, queryVal)
		}
		return false
	}
	// Lower priority number = higher severity, so comparisons are inverted.
	switch op {
	case OpEq:
		return fp == qp
	case OpNeq:
		return fp != qp
	case OpGte:
		return fp <= qp // field priority <= query priority means field >= query in severity
	case OpGt:
		return fp < qp
	case OpLte:
		return fp >= qp
	case OpLt:
		return fp > qp
	}
	return false
}

func compareFloat(a float64, op Operator, b float64) bool {
	switch op {
	case OpEq:
		return a == b
	case OpNeq:
		return a != b
	case OpGt:
		return a > b
	case OpGte:
		return a >= b
	case OpLt:
		return a < b
	case OpLte:
		return a <= b
	}
	return false
}

// --- Lexer ---

func lex(input string) ([]Token, error) {
	var tokens []Token
	runes := []rune(input)
	i := 0

	for i < len(runes) {
		// Skip whitespace.
		if unicode.IsSpace(runes[i]) {
			i++
			continue
		}

		// Operators: !=, >=, <=, =, >, <
		if runes[i] == '!' && i+1 < len(runes) && runes[i+1] == '=' {
			tokens = append(tokens, Token{Type: TokenOp, Value: "!="})
			i += 2
			continue
		}
		if runes[i] == '>' && i+1 < len(runes) && runes[i+1] == '=' {
			tokens = append(tokens, Token{Type: TokenOp, Value: ">="})
			i += 2
			continue
		}
		if runes[i] == '<' && i+1 < len(runes) && runes[i+1] == '=' {
			tokens = append(tokens, Token{Type: TokenOp, Value: "<="})
			i += 2
			continue
		}
		if runes[i] == '=' || runes[i] == '>' || runes[i] == '<' {
			tokens = append(tokens, Token{Type: TokenOp, Value: string(runes[i])})
			i++
			continue
		}

		// Quoted string value.
		if runes[i] == '"' {
			j := i + 1
			for j < len(runes) && runes[j] != '"' {
				j++
			}
			if j >= len(runes) {
				return nil, fmt.Errorf("unterminated string at position %d", i)
			}
			tokens = append(tokens, Token{Type: TokenValue, Value: string(runes[i+1 : j])})
			i = j + 1
			continue
		}

		// Word (field name, keyword, or unquoted value).
		j := i
		for j < len(runes) && !unicode.IsSpace(runes[j]) && runes[j] != '=' && runes[j] != '!' && runes[j] != '>' && runes[j] != '<' && runes[j] != '"' {
			j++
		}
		word := string(runes[i:j])
		upper := strings.ToUpper(word)
		switch upper {
		case "AND":
			tokens = append(tokens, Token{Type: TokenAnd, Value: word})
		case "OR":
			tokens = append(tokens, Token{Type: TokenOr, Value: word})
		default:
			tokens = append(tokens, Token{Type: TokenField, Value: word})
		}
		i = j
	}

	tokens = append(tokens, Token{Type: TokenEOF})
	return tokens, nil
}

// --- Parser ---

func parse(tokens []Token) (*Query, error) {
	q := &Query{}
	pos := 0

	for {
		if pos >= len(tokens) || tokens[pos].Type == TokenEOF {
			break
		}

		// Expect field.
		if tokens[pos].Type != TokenField {
			return nil, fmt.Errorf("expected field name at position %d, got %q", pos, tokens[pos].Value)
		}
		field := tokens[pos].Value
		pos++

		// Expect operator.
		if pos >= len(tokens) || tokens[pos].Type != TokenOp {
			return nil, fmt.Errorf("expected operator after %q", field)
		}
		op, err := parseOp(tokens[pos].Value)
		if err != nil {
			return nil, err
		}
		pos++

		// Expect value.
		if pos >= len(tokens) {
			return nil, fmt.Errorf("expected value after operator")
		}
		if tokens[pos].Type != TokenValue && tokens[pos].Type != TokenField {
			return nil, fmt.Errorf("expected value at position %d, got %q", pos, tokens[pos].Value)
		}
		value := tokens[pos].Value
		pos++

		q.Conditions = append(q.Conditions, Condition{Field: field, Op: op, Value: value})

		// Check for junction.
		if pos < len(tokens) && (tokens[pos].Type == TokenAnd || tokens[pos].Type == TokenOr) {
			if tokens[pos].Type == TokenAnd {
				q.Junctions = append(q.Junctions, JuncAnd)
			} else {
				q.Junctions = append(q.Junctions, JuncOr)
			}
			pos++
		}
	}

	if len(q.Conditions) == 0 {
		return nil, fmt.Errorf("empty query")
	}

	return q, nil
}

func parseOp(s string) (Operator, error) {
	switch s {
	case "=":
		return OpEq, nil
	case "!=":
		return OpNeq, nil
	case ">":
		return OpGt, nil
	case ">=":
		return OpGte, nil
	case "<":
		return OpLt, nil
	case "<=":
		return OpLte, nil
	default:
		return 0, fmt.Errorf("unknown operator %q", s)
	}
}
