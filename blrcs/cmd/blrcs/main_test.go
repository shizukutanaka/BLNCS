package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRunVersion(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{"version"}, &out, &errOut)
	if code != 0 {
		t.Errorf("version exit code: %d", code)
	}
	if !strings.Contains(out.String(), "blrcs 1.0.0") {
		t.Errorf("version output: %s", out.String())
	}
}

func TestRunNoArgs(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run(nil, &out, &errOut)
	if code != 1 {
		t.Errorf("no args should exit 1, got %d", code)
	}
	if !strings.Contains(errOut.String(), "Usage") {
		t.Errorf("should print usage: %s", errOut.String())
	}
}

func TestRunUnknownCommand(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{"frobnicate"}, &out, &errOut)
	if code != 1 {
		t.Errorf("unknown command should exit 1, got %d", code)
	}
	if !strings.Contains(errOut.String(), "unknown") {
		t.Errorf("should report unknown: %s", errOut.String())
	}
}

func TestRunCompletionBash(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{"completion", "bash"}, &out, &errOut)
	if code != 0 {
		t.Errorf("bash completion exit: %d", code)
	}
	if !strings.Contains(out.String(), "complete -W") {
		t.Errorf("bash completion output: %s", out.String())
	}
}

func TestRunCompletionZsh(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{"completion", "zsh"}, &out, &errOut)
	if code != 0 || !strings.Contains(out.String(), "compdef") {
		t.Errorf("zsh completion: code=%d out=%s", code, out.String())
	}
}

func TestRunCompletionFish(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{"completion", "fish"}, &out, &errOut)
	if code != 0 || !strings.Contains(out.String(), "complete -c blrcs") {
		t.Errorf("fish completion: code=%d", code)
	}
}

func TestRunCompletionUnknownShell(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{"completion", "powershell"}, &out, &errOut)
	if code != 1 {
		t.Errorf("unknown shell should exit 1, got %d", code)
	}
	if !strings.Contains(errOut.String(), "unknown shell") {
		t.Errorf("should report unknown shell: %s", errOut.String())
	}
}

func TestRunCompletionNoShell(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{"completion"}, &out, &errOut)
	if code != 1 {
		t.Errorf("missing shell arg should exit 1, got %d", code)
	}
}

func TestRunDoctorDefault(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{"doctor"}, &out, &errOut)
	// Doctor exit code depends on environment; just ensure it runs and writes output
	if out.Len() == 0 {
		t.Error("doctor should produce output")
	}
	_ = code
}

func TestRunDoctorJSON(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{"doctor", "--json"}, &out, &errOut)
	if !strings.Contains(out.String(), "passed") {
		t.Errorf("JSON output should contain 'passed': %s", out.String())
	}
	_ = code
}

func TestRunDoctorBadFlag(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{"doctor", "--nonexistent-flag"}, &out, &errOut)
	if code != 2 {
		t.Errorf("bad flag should exit 2, got %d", code)
	}
}

func TestRunDoctorCustomTimeout(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{"doctor", "--timeout", "60"}, &out, &errOut)
	_ = code
	if out.Len() == 0 {
		t.Error("doctor with timeout should produce output")
	}
}
