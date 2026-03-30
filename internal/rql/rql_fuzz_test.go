package rql

import "testing"

func FuzzParseAndMatch(f *testing.F) {
	for _, seed := range []string{
		`severity = HIGH`,
		`resource.type = "s3"`,
		`cloud_provider = "aws" OR cloud_provider = "gcp"`,
		`ai_risk_score > 7.5`,
		`severity = HIGH AND`,
		`severity = "unterminated`,
		``,
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {
		q, err := Parse(input)
		if err != nil {
			return
		}

		if len(q.Conditions) == 0 {
			t.Fatal("Parse returned a query with no conditions")
		}
		if got, want := len(q.Junctions), len(q.Conditions)-1; got != want {
			t.Fatalf("junction/condition mismatch: got %d junctions for %d conditions", got, len(q.Conditions))
		}

		accessor := func(field string) (string, bool) {
			switch field {
			case "severity":
				return "HIGH", true
			case "ai_risk_score":
				return "8.2", true
			default:
				return "value", true
			}
		}
		ev := NewEvaluator(accessor, map[string]OrderedField{"severity": severityOrder})
		_ = ev.Match(q)
	})
}
