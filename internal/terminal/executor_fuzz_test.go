package terminal

import (
	"strings"
	"testing"

	"go.uber.org/zap"
)

func FuzzExecutorValidate(f *testing.F) {
	for _, seed := range []string{
		"",
		"   ",
		"aws s3 ls",
		"aws ec2 describe-instances --region us-east-1",
		`aws ec2 describe-instances --filters "Name=tag:Name,Values=aegis"`,
		"kubectl get pods -n aegis",
		"terraform version",
		"whoami",
		"aws s3 ls | grep bucket",
		"terraform destroy",
		"aws s3 ls --endpoint-url https://evil.example",
		"aws s3 ls\nrm -rf /",
	} {
		f.Add(seed)
	}

	executor := NewExecutor(zap.NewNop())

	f.Fuzz(func(t *testing.T, input string) {
		binary, args, err := executor.Validate(input)
		if err != nil {
			return
		}

		trimmed := strings.TrimSpace(input)
		if trimmed == "" {
			t.Fatal("Validate accepted an empty command")
		}

		for _, r := range trimmed {
			if strings.ContainsRune(shellMetachars, r) {
				t.Fatalf("Validate accepted shell metachar %q in %q", string(r), trimmed)
			}
		}

		tokens := tokenize(trimmed)
		if len(tokens) == 0 {
			t.Fatal("tokenize returned no tokens for accepted input")
		}
		if tokens[0] != binary {
			t.Fatalf("binary = %q, want %q", binary, tokens[0])
		}
		if strings.Join(args, " ") != strings.Join(tokens[1:], " ") {
			t.Fatalf("args = %q, want %q", strings.Join(args, " "), strings.Join(tokens[1:], " "))
		}
		if err := rejectDangerousFlags(args); err != nil {
			t.Fatalf("accepted args failed dangerous flag check: %v", err)
		}

		subcommand := strings.Join(args, " ")
		allowed := false
		for _, cmd := range executor.whitelist {
			if cmd.Binary != binary {
				continue
			}
			for _, prefix := range cmd.Prefixes {
				if prefix == "" || subcommand == prefix || strings.HasPrefix(subcommand, prefix+" ") {
					allowed = true
					break
				}
			}
			if allowed {
				break
			}
		}
		if !allowed {
			t.Fatalf("accepted command %q %q is not in whitelist", binary, subcommand)
		}
	})
}
