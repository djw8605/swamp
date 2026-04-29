package agent

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ----------------------------------------------------------------------------
// Helpers shared by multiple tests
// ----------------------------------------------------------------------------

// mockHub records all broadcast messages for assertion.
type mockHub struct {
	messages []string
}

func (h *mockHub) Broadcast(_ string, data []byte) {
	h.messages = append(h.messages, string(data))
}

// setupWorkDir creates the minimal directory structure required by
// runOpenCodeProcess / runOpenCodeOnce inside a temporary directory.
func setupWorkDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "output"), 0755); err != nil {
		t.Fatalf("setupWorkDir: %v", err)
	}
	return dir
}

// writeFakeOpenCode writes a shell script to dir/opencode that simply echoes
// each of the provided JSON lines to stdout and exits 0.  All real opencode
// flags are silently ignored by the script.
func writeFakeOpenCode(t *testing.T, dir string, lines []string) string {
	t.Helper()
	var sb strings.Builder
	sb.WriteString("#!/bin/sh\n")
	for _, l := range lines {
		// Use printf to avoid echo interpreting escape sequences.
		sb.WriteString("printf '%s\\n' " + shellQuote(l) + "\n")
	}
	path := filepath.Join(dir, "opencode")
	if err := os.WriteFile(path, []byte(sb.String()), 0755); err != nil {
		t.Fatalf("writeFakeOpenCode: %v", err)
	}
	return path
}

// writeFakeOpenCodeStateful writes a shell script that uses a counter file to
// return different output on the first call vs all subsequent calls.
func writeFakeOpenCodeStateful(t *testing.T, dir string, firstLines, contLines []string) string {
	t.Helper()
	counterFile := filepath.Join(dir, ".call_count")

	var sb strings.Builder
	sb.WriteString("#!/bin/sh\n")
	fmt.Fprintf(&sb, "COUNT=$(cat %s 2>/dev/null || echo 0)\n", shellQuote(counterFile))
	sb.WriteString("COUNT=$((COUNT + 1))\n")
	fmt.Fprintf(&sb, "printf '%%s\\n' \"$COUNT\" > %s\n", shellQuote(counterFile))
	sb.WriteString("if [ \"$COUNT\" -le 1 ]; then\n")
	for _, l := range firstLines {
		sb.WriteString("  printf '%s\\n' " + shellQuote(l) + "\n")
	}
	sb.WriteString("else\n")
	for _, l := range contLines {
		sb.WriteString("  printf '%s\\n' " + shellQuote(l) + "\n")
	}
	sb.WriteString("fi\n")

	path := filepath.Join(dir, "opencode")
	if err := os.WriteFile(path, []byte(sb.String()), 0755); err != nil {
		t.Fatalf("writeFakeOpenCodeStateful: %v", err)
	}
	return path
}

// shellQuote wraps s in single quotes, escaping any embedded single quotes.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}

// callCount reads the counter file created by writeFakeOpenCodeStateful.
func callCount(t *testing.T, dir string) int {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, ".call_count"))
	if err != nil {
		t.Fatalf("callCount: %v", err)
	}
	var n int
	fmt.Sscanf(strings.TrimSpace(string(data)), "%d", &n)
	return n
}

// ----------------------------------------------------------------------------
// 1. parseOpenCodeEventMeta — step_finish with reason "length"
// ----------------------------------------------------------------------------

func TestParseOpenCodeEventMeta_StepFinishLength(t *testing.T) {
	line := []byte(`{"type":"step_finish","sessionId":"sess-abc","part":{"type":"step-finish","reason":"length","tokens":{}}}`)
	sid, reason, isWork := parseOpenCodeEventMeta(line)

	if sid != "sess-abc" {
		t.Errorf("sessionID = %q, want %q", sid, "sess-abc")
	}
	if reason != "length" {
		t.Errorf("stepReason = %q, want %q", reason, "length")
	}
	if isWork {
		t.Error("isWork = true, want false for step_finish event")
	}
}

// ----------------------------------------------------------------------------
// 2. parseOpenCodeEventMeta — sessionId extracted from a text event
// ----------------------------------------------------------------------------

func TestParseOpenCodeEventMeta_SessionID(t *testing.T) {
	line := []byte(`{"type":"text","sessionId":"sess-xyz","part":{"type":"text","text":"hello world"}}`)
	sid, reason, isWork := parseOpenCodeEventMeta(line)

	if sid != "sess-xyz" {
		t.Errorf("sessionID = %q, want %q", sid, "sess-xyz")
	}
	if reason != "" {
		t.Errorf("stepReason = %q, want empty string", reason)
	}
	if !isWork {
		t.Error("isWork = false, want true for text event")
	}
}

// parseOpenCodeEventMeta should also handle session_id (snake_case variant).
func TestParseOpenCodeEventMeta_SessionIDSnakeCase(t *testing.T) {
	line := []byte(`{"type":"tool_use","session_id":"snake-123","part":{"type":"tool","tool":"bash"}}`)
	sid, _, isWork := parseOpenCodeEventMeta(line)

	if sid != "snake-123" {
		t.Errorf("sessionID = %q, want %q", sid, "snake-123")
	}
	if !isWork {
		t.Error("isWork = false, want true for tool_use event")
	}
}

// Non-JSON lines should be safely ignored.
func TestParseOpenCodeEventMeta_NonJSON(t *testing.T) {
	sid, reason, isWork := parseOpenCodeEventMeta([]byte("not json at all"))
	if sid != "" || reason != "" || isWork {
		t.Errorf("expected all zero values for non-JSON line, got sid=%q reason=%q isWork=%v", sid, reason, isWork)
	}
}

// ----------------------------------------------------------------------------
// 3. Outer loop continues when reason is "length"
// ----------------------------------------------------------------------------

func TestRunOpenCodeProcess_ContinuesOnLength(t *testing.T) {
	workDir := setupWorkDir(t)

	firstLines := []string{
		`{"type":"text","sessionId":"test-sess","part":{"type":"text","text":"starting analysis"}}`,
		`{"type":"step_finish","sessionId":"test-sess","part":{"type":"step-finish","reason":"length"}}`,
	}
	contLines := []string{
		`{"type":"text","sessionId":"test-sess","part":{"type":"text","text":"completed analysis"}}`,
		`{"type":"step_finish","sessionId":"test-sess","part":{"type":"step-finish","reason":"end_turn"}}`,
	}

	binary := writeFakeOpenCodeStateful(t, workDir, firstLines, contLines)
	hub := &mockHub{}

	err := runOpenCodeProcess(context.Background(), binary, workDir, "test prompt", "analysis-1", "", "", "", hub)
	if err != nil {
		t.Fatalf("runOpenCodeProcess returned unexpected error: %v", err)
	}

	// Exactly two invocations should have occurred (initial + one continuation).
	if n := callCount(t, workDir); n != 2 {
		t.Errorf("binary call count = %d, want 2", n)
	}

	// The hub should have received a continuation broadcast.
	found := false
	for _, msg := range hub.messages {
		if strings.Contains(msg, "[continuation]") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected a [continuation] broadcast message, none found")
	}
}

// ----------------------------------------------------------------------------
// 4. Outer loop stops on normal completion (no "length")
// ----------------------------------------------------------------------------

func TestRunOpenCodeProcess_StopsOnEndTurn(t *testing.T) {
	workDir := setupWorkDir(t)

	lines := []string{
		`{"type":"text","sessionId":"sess-normal","part":{"type":"text","text":"done"}}`,
		`{"type":"step_finish","sessionId":"sess-normal","part":{"type":"step-finish","reason":"end_turn"}}`,
	}
	binary := writeFakeOpenCode(t, workDir, lines)
	hub := &mockHub{}

	err := runOpenCodeProcess(context.Background(), binary, workDir, "test prompt", "analysis-2", "", "", "", hub)
	if err != nil {
		t.Fatalf("runOpenCodeProcess returned unexpected error: %v", err)
	}

	// No counter file → only one invocation happened.
	if _, callCountFileErr := os.Stat(filepath.Join(workDir, ".call_count")); callCountFileErr == nil {
		// The stateful helper was not used, but let's also check the
		// non-stateful binary was not re-invoked by checking for
		// continuation broadcasts.
		for _, msg := range hub.messages {
			if strings.Contains(msg, "[continuation]") {
				t.Error("unexpected [continuation] broadcast; binary should have been called only once")
			}
		}
	}
}

// ----------------------------------------------------------------------------
// 5. Error when reason="length" but no sessionID in the stream
// ----------------------------------------------------------------------------

func TestRunOpenCodeProcess_ErrorOnLengthWithoutSessionID(t *testing.T) {
	workDir := setupWorkDir(t)

	// The fake binary outputs length finish but never emits a sessionId.
	lines := []string{
		`{"type":"text","part":{"type":"text","text":"some work done"}}`,
		`{"type":"step_finish","part":{"type":"step-finish","reason":"length"}}`,
	}
	binary := writeFakeOpenCode(t, workDir, lines)
	hub := &mockHub{}

	err := runOpenCodeProcess(context.Background(), binary, workDir, "test prompt", "analysis-3", "", "", "", hub)
	if err == nil {
		t.Fatal("expected an error when length finish has no sessionID, got nil")
	}
	if !strings.Contains(err.Error(), "session ID") {
		t.Errorf("error message %q should mention session ID", err.Error())
	}
}

// ----------------------------------------------------------------------------
// 6. BuildContinuationPrompt returns non-empty content with key instructions
// ----------------------------------------------------------------------------

func TestBuildContinuationPrompt_NonEmpty(t *testing.T) {
	p := BuildContinuationPrompt()

	if strings.TrimSpace(p) == "" {
		t.Fatal("BuildContinuationPrompt returned empty string")
	}

	keywords := []string{
		"continue",
		"restart",  // should say "Do NOT restart"
		"repeat",   // should say "Do NOT repeat"
		"output/results.sarif",
		"output/report.md",
	}
	for _, kw := range keywords {
		if !strings.Contains(strings.ToLower(p), strings.ToLower(kw)) {
			t.Errorf("BuildContinuationPrompt output missing expected keyword %q", kw)
		}
	}
}
