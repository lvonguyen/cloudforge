package rql

import (
	"strings"
	"testing"
)

var severityOrder = func(v string) (int, bool) {
	m := map[string]int{"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4}
	p, ok := m[strings.ToUpper(v)]
	return p, ok
}

func TestParseAndMatch(t *testing.T) {
	tests := []struct {
		name   string
		query  string
		fields map[string]string
		want   bool
	}{
		{
			name:   "simple equality",
			query:  `resource.type = "s3"`,
			fields: map[string]string{"resource.type": "s3"},
			want:   true,
		},
		{
			name:   "case insensitive equality",
			query:  `cloud_provider = "AWS"`,
			fields: map[string]string{"cloud_provider": "aws"},
			want:   true,
		},
		{
			name:   "not equal",
			query:  `status != "resolved"`,
			fields: map[string]string{"status": "open"},
			want:   true,
		},
		{
			name:   "severity gte HIGH matches CRITICAL",
			query:  `severity >= HIGH`,
			fields: map[string]string{"severity": "CRITICAL"},
			want:   true,
		},
		{
			name:   "severity gte HIGH matches HIGH",
			query:  `severity >= HIGH`,
			fields: map[string]string{"severity": "HIGH"},
			want:   true,
		},
		{
			name:   "severity gte HIGH rejects MEDIUM",
			query:  `severity >= HIGH`,
			fields: map[string]string{"severity": "MEDIUM"},
			want:   false,
		},
		{
			name:   "AND both true",
			query:  `severity = HIGH AND cloud_provider = "aws"`,
			fields: map[string]string{"severity": "HIGH", "cloud_provider": "aws"},
			want:   true,
		},
		{
			name:   "AND one false",
			query:  `severity = HIGH AND cloud_provider = "gcp"`,
			fields: map[string]string{"severity": "HIGH", "cloud_provider": "aws"},
			want:   false,
		},
		{
			name:   "OR one true",
			query:  `cloud_provider = "aws" OR cloud_provider = "gcp"`,
			fields: map[string]string{"cloud_provider": "aws"},
			want:   true,
		},
		{
			name:  "AND binds tighter than OR",
			query: `cloud_provider = "aws" OR severity = HIGH AND status = "open"`,
			fields: map[string]string{
				"cloud_provider": "aws",
				"severity":       "LOW",
				"status":         "resolved",
			},
			want: true,
		},
		{
			name:  "multiple OR segments preserve AND grouping",
			query: `severity = HIGH AND cloud_provider = "aws" OR status = "open" AND resource.type = "ec2"`,
			fields: map[string]string{
				"severity":       "LOW",
				"cloud_provider": "aws",
				"status":         "open",
				"resource.type":  "ec2",
			},
			want: true,
		},
		{
			name:   "numeric gt",
			query:  `ai_risk_score > 7.5`,
			fields: map[string]string{"ai_risk_score": "8.2"},
			want:   true,
		},
		{
			name:   "numeric lte",
			query:  `ai_risk_score <= 5.0`,
			fields: map[string]string{"ai_risk_score": "5.0"},
			want:   true,
		},
		{
			name:   "missing field returns false",
			query:  `nonexistent = "foo"`,
			fields: map[string]string{},
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q, err := Parse(tt.query)
			if err != nil {
				t.Fatalf("Parse(%q) error: %v", tt.query, err)
			}

			accessor := func(field string) (string, bool) {
				v, ok := tt.fields[field]
				return v, ok
			}
			ordered := map[string]OrderedField{"severity": severityOrder}
			ev := NewEvaluator(accessor, ordered)

			got := ev.Match(q)
			if got != tt.want {
				t.Errorf("Match() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseErrors(t *testing.T) {
	bad := []string{
		"",
		"severity",
		`severity = `,
		`= "foo"`,
		`severity @@ "foo"`,
		`severity = "unterminated`,
		`severity = HIGH AND`,
	}
	for _, input := range bad {
		_, err := Parse(input)
		if err == nil {
			t.Errorf("Parse(%q) should have failed", input)
		}
	}
}
