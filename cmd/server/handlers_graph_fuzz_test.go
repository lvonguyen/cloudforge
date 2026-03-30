package main

import (
	"testing"
	"unicode"
	"unicode/utf8"
)

func FuzzValidateAndNormalizeGraphQuery(f *testing.F) {
	f.Add("gremlin", `g.V().count()`)
	f.Add("gremlin", "g.V().\u00a0inject(1,2,3)")
	f.Add("gremlin", `g.V().has('name', '${Runtime.exec("cmd")}')`)
	f.Add("cypher", `MATCH (n) RETURN n LIMIT 10`)
	f.Add("cypher", `CR/**/EATE (n:Test)`)
	f.Add("sparql", `SELECT * WHERE {?s ?p ?o}`)
	f.Add("", "")

	f.Fuzz(func(t *testing.T, language, query string) {
		normalized, err := validateAndNormalizeGraphQuery(language, query)
		if err != nil {
			if validationErr, ok := err.(*graphQueryValidationError); ok {
				if validationErr.status != 400 && validationErr.status != 403 {
					t.Fatalf("unexpected validation status %d", validationErr.status)
				}
				return
			}
			t.Fatalf("unexpected error type: %T", err)
		}

		if !utf8.ValidString(normalized) {
			t.Fatalf("normalized query is not valid UTF-8: %q", normalized)
		}
		if normalized == "" {
			t.Fatal("normalized query unexpectedly empty")
		}
		if normalized2, err := validateAndNormalizeGraphQuery(language, normalized); err != nil || normalized2 != normalized {
			t.Fatalf("graph query normalization is not idempotent: first=%q second=%q err=%v", normalized, normalized2, err)
		}
		for _, r := range normalized {
			if unicode.Is(unicode.Cf, r) {
				t.Fatalf("normalized query still contains format rune %U", r)
			}
			if r != ' ' && unicode.Is(unicode.Zs, r) {
				t.Fatalf("normalized query still contains Zs whitespace rune %U", r)
			}
		}
	})
}
