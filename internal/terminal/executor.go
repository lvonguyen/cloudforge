package terminal

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
	"unicode"

	"go.uber.org/zap"
)

// AllowedCommand defines a binary and its permitted subcommand prefixes.
type AllowedCommand struct {
	Binary   string
	Prefixes []string
}

// ExecResult holds the output and metadata from a command execution.
type ExecResult struct {
	Stdout    string
	Stderr    string
	ExitCode  int
	ElapsedMs int64
	IsMock    bool
}

// Executor validates commands against a whitelist and executes them.
type Executor struct {
	whitelist []AllowedCommand
	timeout   time.Duration
	maxOutput int
	logger    *zap.Logger
}

// NewExecutor creates an Executor with the default whitelist.
func NewExecutor(logger *zap.Logger) *Executor {
	return &Executor{
		whitelist: DefaultWhitelist,
		timeout:   30 * time.Second,
		maxOutput: 512 * 1024, // 512KB
		logger:    logger,
	}
}

// DefaultWhitelist contains read-only cloud CLI commands safe for demo use.
var DefaultWhitelist = []AllowedCommand{
	{Binary: "aws", Prefixes: []string{
		"s3 ls", "s3api list-buckets", "sts get-caller-identity",
		"ec2 describe-instances", "ec2 describe-vpcs", "ec2 describe-security-groups",
		"iam list-roles", "iam list-users", "iam get-account-summary",
		"securityhub get-findings", "securityhub describe-hub",
		"guardduty list-detectors", "config describe-compliance-by-resource",
		"organizations list-accounts",
	}},
	{Binary: "gcloud", Prefixes: []string{
		"projects list", "compute instances list", "compute networks list",
		"iam roles list", "iam service-accounts list",
		"scc findings list", "asset search-all-resources",
	}},
	{Binary: "az", Prefixes: []string{
		"account list", "account show",
		"vm list", "network vnet list",
		"security alert list", "security assessment list",
		"resource list", "ad user list",
	}},
	{Binary: "kubectl", Prefixes: []string{
		"get pods", "get nodes", "get namespaces", "get deployments",
		"get services", "get ingress", "get configmaps",
		"describe pod", "describe node", "describe deployment",
		"top pods", "top nodes",
		"cluster-info",
	}},
	{Binary: "terraform", Prefixes: []string{
		"state list", "state show",
		"output", "workspace list", "version",
	}},
	{Binary: "trivy", Prefixes: []string{
		"image", "fs", "config", "repo",
	}},
	{Binary: "aegis", Prefixes: []string{
		"status", "findings", "compliance", "version", "config",
	}},
	{Binary: "whoami", Prefixes: []string{""}},
	{Binary: "date", Prefixes: []string{""}},
	{Binary: "uptime", Prefixes: []string{""}},
	{Binary: "hostname", Prefixes: []string{""}},
}

// shellMetachars are characters that indicate shell injection attempts.
const shellMetachars = "|;&$`><(){}!#\n\r"

// Validate checks whether a command string is allowed.
func (e *Executor) Validate(input string) (binary string, args []string, err error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return "", nil, fmt.Errorf("empty command")
	}

	// Reject shell metacharacters before parsing.
	for _, c := range input {
		if strings.ContainsRune(shellMetachars, c) {
			return "", nil, fmt.Errorf("shell operators not allowed: %q", string(c))
		}
	}

	tokens := tokenize(input)
	if len(tokens) == 0 {
		return "", nil, fmt.Errorf("empty command after parsing")
	}

	binary = tokens[0]
	args = tokens[1:]
	subcommand := strings.Join(args, " ")

	for _, allowed := range e.whitelist {
		if allowed.Binary != binary {
			continue
		}
		for _, prefix := range allowed.Prefixes {
			if prefix == "" || strings.HasPrefix(subcommand, prefix) {
				return binary, args, nil
			}
		}
		return "", nil, fmt.Errorf("subcommand not allowed: %s %s", binary, subcommand)
	}

	return "", nil, fmt.Errorf("command not allowed: %s", binary)
}

// Execute runs a validated command and returns the result.
func (e *Executor) Execute(ctx context.Context, binary string, args []string) (*ExecResult, error) {
	start := time.Now()

	// Check if binary exists on PATH.
	_, lookErr := exec.LookPath(binary)
	if lookErr != nil {
		return e.mockExecute(binary, args, start)
	}

	ctx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, binary, args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &limitWriter{buf: &stdout, limit: e.maxOutput}
	cmd.Stderr = &limitWriter{buf: &stderr, limit: e.maxOutput}

	err := cmd.Run()

	result := &ExecResult{
		Stdout:    stdout.String(),
		Stderr:    stderr.String(),
		ExitCode:  0,
		ElapsedMs: time.Since(start).Milliseconds(),
	}

	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			result.ExitCode = -1
			result.Stderr += fmt.Sprintf("\n[timeout] command killed after %s", e.timeout)
		} else if exitErr, ok := err.(*exec.ExitError); ok {
			result.ExitCode = exitErr.ExitCode()
		} else {
			result.ExitCode = -1
			result.Stderr += fmt.Sprintf("\n[error] %v", err)
		}
	}

	if stdout.Len() >= e.maxOutput {
		result.Stdout += "\n[truncated — output exceeded 512KB]"
	}

	e.logger.Info("terminal.execute",
		zap.String("binary", binary),
		zap.Strings("args", args),
		zap.Int("exit_code", result.ExitCode),
		zap.Int64("elapsed_ms", result.ElapsedMs),
	)

	return result, nil
}

func (e *Executor) mockExecute(binary string, args []string, start time.Time) (*ExecResult, error) {
	key := mockKey(binary, args)
	output, ok := MockOutputs[key]
	if !ok {
		output = fmt.Sprintf("[demo] %s: command not installed — no mock output available", binary)
	}

	banner := fmt.Sprintf("[demo] %s not found on $PATH — showing sample output\n\n", binary)

	return &ExecResult{
		Stdout:    banner + output,
		ExitCode:  0,
		ElapsedMs: time.Since(start).Milliseconds(),
		IsMock:    true,
	}, nil
}

// tokenize performs simple shell-like tokenization (handles double quotes).
func tokenize(input string) []string {
	var tokens []string
	var current strings.Builder
	inQuote := false

	for _, r := range input {
		switch {
		case r == '"':
			inQuote = !inQuote
		case unicode.IsSpace(r) && !inQuote:
			if current.Len() > 0 {
				tokens = append(tokens, current.String())
				current.Reset()
			}
		default:
			current.WriteRune(r)
		}
	}

	if current.Len() > 0 {
		tokens = append(tokens, current.String())
	}

	return tokens
}

// limitWriter wraps a bytes.Buffer and stops writing after limit bytes.
type limitWriter struct {
	buf   *bytes.Buffer
	limit int
}

func (w *limitWriter) Write(p []byte) (int, error) {
	remaining := w.limit - w.buf.Len()
	if remaining <= 0 {
		return len(p), nil // Silently discard — already at limit.
	}
	if len(p) > remaining {
		p = p[:remaining]
	}
	return w.buf.Write(p)
}

// mockKey generates a lookup key for mock outputs.
func mockKey(binary string, args []string) string {
	if len(args) == 0 {
		return binary
	}
	// Use binary + first 2 non-flag args as key.
	// Skip flags (--foo) and their values (the arg after --foo).
	key := binary
	count := 0
	skipNext := false
	for _, a := range args {
		if skipNext {
			skipNext = false
			continue
		}
		if strings.HasPrefix(a, "-") {
			// If it's a --key=value style, just skip this token.
			// If it's --key style, skip this AND the next token (the value).
			if !strings.Contains(a, "=") {
				skipNext = true
			}
			continue
		}
		key += " " + a
		count++
		if count >= 2 {
			break
		}
	}
	return key
}
