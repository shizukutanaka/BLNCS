// Package integration contains end-to-end integration tests that verify
// cross-package behaviour and Apple Engineering Principles (structured errors,
// context propagation, deterministic outputs).
package integration

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"blrcs/errkit"
	"blrcs/telemetry"
	"blrcs/types"
)

// captureRec — テストで Telemetry 出力を確認
type captureRec struct {
	events []telemetry.Event
}

func (c *captureRec) Record(ev telemetry.Event) {
	c.events = append(c.events, ev)
}

// TestApplePrinciplesIntegrated — 3つの改善が連携して動くこと
//
// 検証:
//  1. types: 不正値をコンストラクタで弾く (Make invalid states unrepresentable)
//  2. errkit: エラーが構造化される (Op + Code + Public + Detail 分離)
//  3. telemetry: span でレイテンシ自動計測 + counter/histogram 自動更新
func TestApplePrinciplesIntegrated(t *testing.T) {
	rec := &captureRec{}
	tel := telemetry.New(rec)

	// === 1. 強型プリミティブ — invalid 値はそもそも作れない ===
	_, err := types.NewDID("not-a-did")
	if err == nil {
		t.Fatal("invalid DID should be rejected at construction")
	}
	_, err = types.NewGTIN("invalidchecksum")
	if err == nil {
		t.Fatal("invalid GTIN should be rejected at construction")
	}
	_, err = types.NewCarbonFootprint(-5)
	if err == nil {
		t.Fatal("negative carbon should be rejected")
	}

	// 正常値
	did := types.MustDID("did:web:factory.example")
	gtin := types.MustGTIN("04012345678901")
	country := types.MustCountryCode("JP")
	carbon := types.MustCarbonFootprint(2.47)
	recycled := types.MustPercent(85)

	if did.IsZero() || gtin.IsZero() || country.IsZero() {
		t.Fatal("valid types should not be zero")
	}

	// === 2. 構造化エラー — Op/Code 分岐可能 ===
	hardError := errkit.E(errkit.OpDPPVerify, errkit.CodeIntegrity, "signature mismatch", nil)
	transientError := errkit.Retryable(errkit.OpStorageWrite, errkit.CodeIO, "transient write failure", nil)

	if errkit.IsRetryable(hardError) {
		t.Error("integrity error must NOT be retryable")
	}
	if !errkit.IsRetryable(transientError) {
		t.Error("transient error should be retryable")
	}
	if !errors.Is(hardError, errkit.Integrity()) {
		t.Error("Is(Integrity()) failed")
	}
	if hardError.HTTPStatus() != 400 {
		t.Errorf("HTTP status: %d", hardError.HTTPStatus())
	}
	// Public message hides internal detail
	internalDetailErr := errkit.EWithDetail(
		errkit.OpDPPIssue, errkit.CodeSecurity,
		"verification failed",
		"key fingerprint SHA256:abc123 mismatch",
		nil,
	)
	pub := internalDetailErr.PublicError()
	if strings.Contains(pub, "abc123") {
		t.Error("CRITICAL: internal detail leaked to public message")
	}

	// === 3. Telemetry — span 自動計測 + メトリクス ===
	span := tel.StartSpan(context.Background(), "DPP.Issue",
		slog.String("issuer", did.String()),
		slog.String("country", country.String()),
		slog.Float64("carbonKg", carbon.KgCO2e()),
		slog.Float64("recycledPct", recycled.Value()),
	)
	// Simulate work
	tel.Counter("dpp.issued").Inc()
	span.End()

	// Verify events recorded
	hasStart := false
	hasEnd := false
	for _, e := range rec.events {
		if e.Name == "DPP.Issue.start" {
			hasStart = true
		}
		if e.Name == "DPP.Issue.end" {
			hasEnd = true
			// elapsed attr present
			hasElapsed := false
			for _, a := range e.Attrs {
				if a.Key == "elapsed" {
					hasElapsed = true
				}
			}
			if !hasElapsed {
				t.Error("elapsed missing in end event")
			}
		}
	}
	if !hasStart || !hasEnd {
		t.Error("span start/end not recorded")
	}

	// Counters reflect activity
	if tel.Counter("dpp.issued").Value() != 1 {
		t.Errorf("dpp.issued counter: %d", tel.Counter("dpp.issued").Value())
	}
	if tel.Counter("DPP.Issue.success").Value() != 1 {
		t.Errorf("auto success counter: %d", tel.Counter("DPP.Issue.success").Value())
	}

	// Snapshot with all metrics
	snap := tel.Snapshot()
	if len(snap.Counters) < 2 {
		t.Errorf("expected ≥2 counters, got %d", len(snap.Counters))
	}
	if hist, ok := snap.Histograms["DPP.Issue.duration_ms"]; !ok || hist.Count != 1 {
		t.Errorf("duration histogram: %+v", hist)
	}
}

// TestErrorPropagationThroughLayers — errkit.Wrap で操作チェイン形成
func TestErrorPropagationThroughLayers(t *testing.T) {
	// Simulate storage layer error
	storageErr := errkit.E(errkit.OpStorageWrite, errkit.CodeIO, "fsync failed", errors.New("ENOSPC"))

	// SCITT layer wraps it
	scittErr := errkit.Wrap(errkit.OpScittRegister, storageErr)

	// VP layer wraps it again
	vpErr := errkit.Wrap(errkit.OpVPProcess, scittErr)

	// Final code is preserved through chain
	if errkit.CodeOf(vpErr) != errkit.CodeIO {
		t.Errorf("code lost through wraps: got %s", errkit.CodeOf(vpErr))
	}

	// Original cause traceable
	var inner *errkit.Error
	if !errors.As(vpErr, &inner) {
		t.Fatal("As failed")
	}

	// Error string contains all 3 op layers somewhere (chain)
	s := vpErr.Error()
	for _, want := range []string{"openid4vp.Process", "scitt.Register", "storage.Write"} {
		if !strings.Contains(s, want) {
			t.Errorf("error chain missing %q in: %s", want, s)
		}
	}
}
