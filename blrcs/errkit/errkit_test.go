package errkit

import (
	"errors"
	"strings"
	"testing"
)

func TestErrorString(t *testing.T) {
	e := E(OpDPPIssue, CodeInvalidInput, "productId required", nil)
	s := e.Error()
	if !strings.Contains(s, "compliance.IssueDPP") {
		t.Errorf("missing op: %s", s)
	}
	if !strings.Contains(s, "productId required") {
		t.Errorf("missing message: %s", s)
	}
}

func TestErrorWithCause(t *testing.T) {
	cause := errors.New("io: disk full")
	e := E(OpStorageWrite, CodeIO, "persist failed", cause)
	if !strings.Contains(e.Error(), "disk full") {
		t.Errorf("cause not in string: %s", e.Error())
	}
	// Unwrap
	if errors.Unwrap(e) != cause {
		t.Errorf("unwrap mismatch")
	}
}

func TestErrorIs(t *testing.T) {
	notFound := NotFound()
	specific := E(OpScittReceipt, CodeNotFound, "leaf not found", nil)
	if !errors.Is(specific, notFound) {
		t.Error("CodeNotFound match should work")
	}
	other := E(OpDPPIssue, CodeInvalidInput, "...", nil)
	if errors.Is(other, notFound) {
		t.Error("different code should not match")
	}
}

func TestErrorAs(t *testing.T) {
	var dst *Error
	src := E(OpVPCreateRequest, CodeUnauthorized, "no token", nil)
	if !errors.As(src, &dst) {
		t.Fatal("As failed")
	}
	if dst.Code != CodeUnauthorized {
		t.Errorf("As code: %s", dst.Code)
	}
}

func TestWrapPreservesCode(t *testing.T) {
	original := E(OpStorageRead, CodeIO, "read fail", nil)
	wrapped := Wrap(OpScittRegister, original)
	var dst *Error
	if !errors.As(wrapped, &dst) {
		t.Fatal("As failed")
	}
	if dst.Code != CodeIO {
		t.Errorf("wrapped should preserve code, got %s", dst.Code)
	}
	// op のチェイン
	if dst.Op != OpScittRegister {
		t.Errorf("outer op: %s", dst.Op)
	}
}

func TestWrapNonStructuredError(t *testing.T) {
	plain := errors.New("plain error")
	wrapped := Wrap(OpDCAPIBuild, plain)
	if !strings.Contains(wrapped.Error(), "plain error") {
		t.Errorf("plain cause not retained: %s", wrapped.Error())
	}
	if CodeOf(wrapped) != CodeUnknown {
		t.Errorf("plain wrap should be Unknown, got %s", CodeOf(wrapped))
	}
}

func TestWrapNil(t *testing.T) {
	if Wrap(OpDPPIssue, nil) != nil {
		t.Fatal("Wrap(nil) should return nil")
	}
}

func TestRetryable(t *testing.T) {
	e := Retryable(OpStorageWrite, CodeIO, "transient", nil)
	if !IsRetryable(e) {
		t.Error("should be retryable")
	}
	hard := E(OpDPPVerify, CodeIntegrity, "tampered", nil)
	if IsRetryable(hard) {
		t.Error("integrity error must not be retryable")
	}
}

func TestHTTPStatusMapping(t *testing.T) {
	cases := []struct {
		code Code
		want int
	}{
		{CodeInvalidInput, 400},
		{CodeUnauthorized, 401},
		{CodeForbidden, 403},
		{CodeNotFound, 404},
		{CodeConflict, 409},
		{CodeTimeout, 408},
		{CodeRateLimited, 429},
		{CodeUnsupported, 501},
		{CodeIO, 500},
		{CodeNetwork, 500},
		{CodeIntegrity, 400},
		{CodeSecurity, 400},
		{CodeInternal, 500},
	}
	for _, c := range cases {
		e := E("test", c.code, "x", nil)
		if got := e.HTTPStatus(); got != c.want {
			t.Errorf("Code %s: got %d want %d", c.code, got, c.want)
		}
	}
}

func TestPublicMessageHidesDetail(t *testing.T) {
	e := EWithDetail(OpDPPIssue, CodeSecurity, "verification failed",
		"key fingerprint mismatch: expected SHA256:abc123 got SHA256:def456", nil)
	pub := e.PublicError()
	if pub != "verification failed" {
		t.Errorf("public should hide detail, got: %s", pub)
	}
	// Internal log line should contain detail
	log := e.LogLine()
	if !strings.Contains(log, "fingerprint mismatch") {
		t.Errorf("log should include detail: %s", log)
	}
}

func TestSentinelComparisons(t *testing.T) {
	// Common pattern: code inside service, check at handler
	e := E(OpVPCreateRequest, CodeNotFound, "session expired", nil)
	if !errors.Is(e, NotFound()) {
		t.Error("Is NotFound failed")
	}
	if errors.Is(e, Unauthorized()) {
		t.Error("Is Unauthorized should be false")
	}
}

func TestCodeOfPlainError(t *testing.T) {
	if CodeOf(errors.New("plain")) != CodeUnknown {
		t.Error("plain error should be Unknown code")
	}
	if CodeOf(nil) != CodeUnknown {
		t.Error("nil error should be Unknown code")
	}
}

func TestCodeOfWrappedTwice(t *testing.T) {
	inner := E(OpStorageRead, CodeIO, "io fail", nil)
	mid := Wrap(OpScittReceipt, inner)
	outer := Wrap(OpVPProcess, mid)
	if CodeOf(outer) != CodeIO {
		t.Errorf("deeply wrapped Code: %s", CodeOf(outer))
	}
}

func TestErrorConstructors(t *testing.T) {
	// Verify each code-specific constructor creates an error with the right code.
	pairs := []struct {
		err  error
		code Code
	}{
		{Forbidden(), CodeForbidden},
		{InvalidInput(), CodeInvalidInput},
		{Conflict(), CodeConflict},
		{RateLimited(), CodeRateLimited},
		{Integrity(), CodeIntegrity},
		{Security(), CodeSecurity},
		{Timeout(), CodeTimeout},
		{Internal(), CodeInternal},
		{NotFound(), CodeNotFound},
		{Unauthorized(), CodeUnauthorized},
	}
	for _, p := range pairs {
		if CodeOf(p.err) != p.code {
			t.Errorf("%v: want %s, got %s", p.err, p.code, CodeOf(p.err))
		}
	}
}

func TestPublicErrorNilWrapped(t *testing.T) {
	e := E(OpDPPIssue, CodeInternal, "internal error", nil)
	pub := e.PublicError()
	if pub == "" {
		t.Error("PublicError should not be empty")
	}
}
