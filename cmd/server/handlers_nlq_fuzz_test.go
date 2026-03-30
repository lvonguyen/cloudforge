package main

import (
	"reflect"
	"testing"
	"unicode/utf8"
)

func FuzzSanitizeNLQQuery(f *testing.F) {
	for _, seed := range []string{
		"normal query",
		"<script>alert(1)</script>critical AWS",
		"hello\x00world",
		"query <b>bold</b> end",
		"show <script findings",
		"",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {
		got := sanitizeNLQQuery(input)
		if !utf8.ValidString(got) {
			t.Fatalf("sanitizeNLQQuery returned invalid UTF-8: %q", got)
		}
		if got != sanitizeNLQQuery(got) {
			t.Fatalf("sanitizeNLQQuery is not idempotent for %q", input)
		}
		if htmlTagPattern.MatchString(got) {
			t.Fatalf("sanitizeNLQQuery left HTML-looking content behind: %q", got)
		}
		for _, r := range got {
			if r < 32 || r == 127 {
				t.Fatalf("sanitizeNLQQuery left control rune %U in %q", r, got)
			}
		}
	})
}

func FuzzValidateNLQResponse(f *testing.F) {
	f.Add("CRITICAL", "HIGH", "aws", "NETWORK", "open", "production", "<b>bold</b> text")
	f.Add("INVALID", "SUPER", "evil", "OTHER", "closed", "qa", "<script>alert(1)</script>")
	f.Add("", "", "", "", "", "", "")

	f.Fuzz(func(t *testing.T, severityA, severityB, provider, category, status, environment, text string) {
		resp := &NLQResponse{
			Severity:    []string{severityA, severityB},
			Provider:    []string{provider},
			Category:    []string{category},
			Status:      []string{status},
			Environment: []string{environment},
			Text:        text,
		}

		validateNLQResponse(resp)

		for _, v := range resp.Severity {
			if !allowedNLQValues["severity"][v] {
				t.Fatalf("unexpected severity value after validation: %q", v)
			}
		}
		for _, v := range resp.Provider {
			if !allowedNLQValues["provider"][v] {
				t.Fatalf("unexpected provider value after validation: %q", v)
			}
		}
		for _, v := range resp.Category {
			if !allowedNLQValues["category"][v] {
				t.Fatalf("unexpected category value after validation: %q", v)
			}
		}
		for _, v := range resp.Status {
			if !allowedNLQValues["status"][v] {
				t.Fatalf("unexpected status value after validation: %q", v)
			}
		}
		for _, v := range resp.Environment {
			if !allowedNLQValues["environment"][v] {
				t.Fatalf("unexpected environment value after validation: %q", v)
			}
		}
		if resp.Text != sanitizeNLQQuery(resp.Text) {
			t.Fatalf("validateNLQResponse left non-sanitized text behind: %q", resp.Text)
		}

		clone := &NLQResponse{
			Severity:    append([]string(nil), resp.Severity...),
			Provider:    append([]string(nil), resp.Provider...),
			Category:    append([]string(nil), resp.Category...),
			Status:      append([]string(nil), resp.Status...),
			Environment: append([]string(nil), resp.Environment...),
			Text:        resp.Text,
		}
		validateNLQResponse(clone)
		if !reflect.DeepEqual(resp, clone) {
			t.Fatalf("validateNLQResponse is not idempotent: before=%+v after=%+v", resp, clone)
		}
	})
}
