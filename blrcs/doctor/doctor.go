// Package doctor — BLRCS 自己診断
//
// Apple `xcrun simctl runtime` / macOS `system_diagnose` 相当。
// プロセス起動時 / デプロイ前の sanity check として全機能を実走行。
//
// 利用シナリオ:
//
//	$ blrcs doctor
//	✓ crypto.ed25519 keygen          1.2ms
//	✓ compliance.IssueDPP            45.1ms
//	✓ compliance.VerifyDPP           62.3ms
//	✓ compliance.SDJWTRoundTrip      78.4ms
//	✓ compliance.RangeProof          21.0ms
//	✓ scitt.RegisterAndVerify        103.2ms
//	✓ storage.MemoryRoundTrip        0.5ms
//	✓ openid4vp.E2E                  150.7ms
//	✓ openid4vci.E2E                 89.3ms
//	✓ telemetry.Snapshot             0.1ms
//	────────────────────────────────────
//	10 checks passed in 551.8ms
//
// CI / Kubernetes Init Container でも使える。
// 失敗時は exit code 1 + 詳細をstderr。
package doctor

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"strings"
	"time"

	"blrcs/compliance"
	"blrcs/mdoc"
	"blrcs/revocation"
	"blrcs/scitt"
	"blrcs/storage"
	"blrcs/telemetry"
)

// ============================================================================
// Result types
// ============================================================================

// Status — チェック結果
type Status int

const (
	StatusPass Status = iota
	StatusFail
	StatusSkip
)

func (s Status) String() string {
	switch s {
	case StatusPass:
		return "pass"
	case StatusFail:
		return "fail"
	case StatusSkip:
		return "skip"
	}
	return "unknown"
}

// Result — 1チェック結果
type Result struct {
	Name     string
	Status   Status
	Duration time.Duration
	Error    error
	Detail   string
}

// Report — 全チェック結果
type Report struct {
	Results  []Result
	Total    int
	Passed   int
	Failed   int
	Skipped  int
	Duration time.Duration
}

// HasFailures — 1つでも失敗があるか
func (r *Report) HasFailures() bool { return r.Failed > 0 }

// ============================================================================
// Check definition
// ============================================================================

// Check — 1つの診断チェック
type Check struct {
	Name string
	Fn   func(ctx context.Context) error
}

// DefaultChecks — BLRCS 標準診断スイート
func DefaultChecks() []Check {
	return []Check{
		{Name: "crypto.ed25519.keygen", Fn: checkEd25519Keygen},
		{Name: "compliance.IssueDPP", Fn: checkIssueDPP},
		{Name: "compliance.VerifyDPP", Fn: checkVerifyDPP},
		{Name: "compliance.TamperDetection", Fn: checkTamperDetection},
		{Name: "compliance.SDJWTRoundTrip", Fn: checkSDJWTRoundTrip},
		{Name: "compliance.SDJWTSelectiveDisclosure", Fn: checkSDJWTSelective},
		{Name: "compliance.RangeProof", Fn: checkRangeProof},
		{Name: "compliance.GS1DigitalLink", Fn: checkGS1DLLink},
		{Name: "compliance.BatteryPassport", Fn: checkBatteryPassport},
		{Name: "scitt.RegisterAndVerify", Fn: checkSCITTRoundTrip},
		{Name: "scitt.InclusionProofGrowth", Fn: checkSCITTGrowth},
		{Name: "revocation.SignedListRoundTrip", Fn: checkRevocationSignedList},
		{Name: "revocation.BitstringStatusList", Fn: checkRevocationBitstring},
		{Name: "mdoc.DeviceAuthRoundTrip", Fn: checkMdocDeviceAuth},
		{Name: "storage.MemoryRoundTrip", Fn: checkStorageRoundTrip},
		{Name: "telemetry.SnapshotEmpty", Fn: checkTelemetrySnapshot},
	}
}

// ============================================================================
// Run
// ============================================================================

// Run — 全チェック実行、Report を返す
func Run(ctx context.Context, checks []Check) *Report {
	report := &Report{Total: len(checks)}
	startAll := time.Now()
	for _, c := range checks {
		if ctx.Err() != nil {
			report.Results = append(report.Results, Result{
				Name: c.Name, Status: StatusSkip, Error: ctx.Err(),
			})
			report.Skipped++
			continue
		}
		startCheck := time.Now()
		err := c.Fn(ctx)
		dur := time.Since(startCheck)
		r := Result{Name: c.Name, Duration: dur}
		if err != nil {
			r.Status = StatusFail
			r.Error = err
			report.Failed++
		} else {
			r.Status = StatusPass
			report.Passed++
		}
		report.Results = append(report.Results, r)
	}
	report.Duration = time.Since(startAll)
	return report
}

// ============================================================================
// Pretty-print
// ============================================================================

// PrintTo — 人間可読の表形式で w に書き出す
func (r *Report) PrintTo(w io.Writer) {
	maxName := 4 // "name" min
	for _, res := range r.Results {
		if len(res.Name) > maxName {
			maxName = len(res.Name)
		}
	}
	for _, res := range r.Results {
		mark := "✓"
		switch res.Status {
		case StatusFail:
			mark = "✗"
		case StatusSkip:
			mark = "—"
		}
		ms := float64(res.Duration.Microseconds()) / 1000.0
		fmt.Fprintf(w, "%s %-*s  %7.2fms\n", mark, maxName, res.Name, ms)
		if res.Error != nil {
			fmt.Fprintf(w, "  %s\n", res.Error)
		}
	}
	fmt.Fprintln(w, strings.Repeat("─", 50))
	totalMs := float64(r.Duration.Microseconds()) / 1000.0
	fmt.Fprintf(w, "%d/%d passed in %.1fms",
		r.Passed, r.Total, totalMs)
	if r.Failed > 0 {
		fmt.Fprintf(w, " (%d failed)", r.Failed)
	}
	if r.Skipped > 0 {
		fmt.Fprintf(w, " (%d skipped)", r.Skipped)
	}
	fmt.Fprintln(w)
}

// ============================================================================
// Individual checks
// ============================================================================

func checkEd25519Keygen(ctx context.Context) error {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	if len(pub) != ed25519.PublicKeySize || len(priv) != ed25519.PrivateKeySize {
		return fmt.Errorf("unexpected key sizes pub=%d priv=%d", len(pub), len(priv))
	}
	// signing+verify smoke test
	msg := []byte("doctor-test")
	sig := ed25519.Sign(priv, msg)
	if !ed25519.Verify(pub, msg, sig) {
		return fmt.Errorf("self-signed message failed verification")
	}
	return nil
}

func checkIssueDPP(ctx context.Context) error {
	iss, err := compliance.NewIssuer("did:web:doctor.test")
	if err != nil {
		return err
	}
	cred, err := iss.Issue(compliance.PassportClaim{
		ProductID:    "DOCTOR-001",
		Category:     "diagnostic",
		CarbonKgCO2e: 0.1,
	}, time.Hour)
	if err != nil {
		return err
	}
	if cred.Proof == nil {
		return fmt.Errorf("issued credential has no proof")
	}
	return nil
}

func checkVerifyDPP(ctx context.Context) error {
	iss, _ := compliance.NewIssuer("did:web:doctor.test")
	cred, err := iss.Issue(compliance.PassportClaim{ProductID: "X"}, time.Hour)
	if err != nil {
		return err
	}
	return compliance.Verify(cred, iss.PublicKey())
}

func checkTamperDetection(ctx context.Context) error {
	iss, _ := compliance.NewIssuer("did:web:doctor.test")
	cred, _ := iss.Issue(compliance.PassportClaim{ProductID: "X", CarbonKgCO2e: 1.0}, time.Hour)
	cred.Subject.CarbonKgCO2e = 999.0 // tamper
	if err := compliance.Verify(cred, iss.PublicKey()); err == nil {
		return fmt.Errorf("CRITICAL: tampered credential verified")
	}
	return nil
}

func checkSDJWTRoundTrip(ctx context.Context) error {
	iss, _ := compliance.NewIssuer("did:web:doctor.test")
	sdjwt, _, err := iss.IssueSDJWT("doctor-subject",
		map[string]any{"x": 1, "y": "v"},
		map[string]any{"public": "data"},
		time.Hour,
	)
	if err != nil {
		return err
	}
	vc, err := compliance.VerifySDJWT(sdjwt, iss.PublicKey())
	if err != nil {
		return err
	}
	if vc.Subject != "doctor-subject" {
		return fmt.Errorf("subject mismatch: %s", vc.Subject)
	}
	if vc.Claims["x"] == nil || vc.Claims["y"] == nil || vc.Claims["public"] == nil {
		return fmt.Errorf("disclosed claims missing")
	}
	return nil
}

func checkSDJWTSelective(ctx context.Context) error {
	iss, _ := compliance.NewIssuer("did:web:doctor.test")
	sdjwt, _, err := iss.IssueSDJWT("s",
		map[string]any{"public_ok": "show", "secret": "hide"},
		map[string]any{"clear": "always"},
		time.Hour,
	)
	if err != nil {
		return err
	}
	// Only reveal "public_ok"
	pres, err := compliance.Present(sdjwt, []string{"public_ok"})
	if err != nil {
		return err
	}
	vc, err := compliance.VerifySDJWT(pres, iss.PublicKey())
	if err != nil {
		return err
	}
	if _, leaked := vc.Claims["secret"]; leaked {
		return fmt.Errorf("CRITICAL: secret claim leaked in selective presentation")
	}
	if _, ok := vc.Claims["public_ok"]; !ok {
		return fmt.Errorf("disclosed claim missing")
	}
	return nil
}

func checkRangeProof(ctx context.Context) error {
	att, err := compliance.NewSensorAttester("did:device:doctor")
	if err != nil {
		return err
	}
	salt := make([]byte, 32)
	_, _ = rand.Read(salt)
	stmt := compliance.RangeStatement{Min: 2, Max: 8, Unit: "c", Name: "doctor"}
	commit := compliance.Commit(5.0, salt, stmt)
	proof, err := att.Attest(commit, 5.0)
	if err != nil {
		return err
	}
	if err := compliance.VerifyRange(proof, att.PublicKey()); err != nil {
		return err
	}
	return nil
}

func checkGS1DLLink(ctx context.Context) error {
	gtin, err := compliance.ComputeGTINCheckDigit("0401234567890")
	if err != nil {
		return err
	}
	uri, err := compliance.BuildDLURI("dpp.example", compliance.GS1Key{GTIN: gtin, Serial: "X"})
	if err != nil {
		return err
	}
	host, key, err := compliance.ParseDLURI(uri)
	if err != nil {
		return err
	}
	if host != "dpp.example" {
		return fmt.Errorf("host roundtrip: %s", host)
	}
	if key.GTIN != gtin {
		return fmt.Errorf("gtin roundtrip: %s", key.GTIN)
	}
	return nil
}

func checkBatteryPassport(ctx context.Context) error {
	iss, _ := compliance.NewIssuer("did:web:doctor.battery")
	cred, err := iss.IssueBatteryPassport(compliance.BatteryPassportClaim{
		BatteryID:                   "DOC-BAT-1",
		Category:                    compliance.BatteryCategoryEV,
		Chemistry:                   compliance.ChemistryNMC,
		CapacityKWh:                 75.0,
		CarbonFootprintKgCO2ePerKWh: 50.0,
		DueDiligenceReportURL:       "https://doctor.example/dd.pdf",
	}, 365*24*time.Hour)
	if err != nil {
		return err
	}
	hasMarker := false
	for _, t := range cred.Type {
		if t == "BatteryPassport" {
			hasMarker = true
		}
	}
	if !hasMarker {
		return fmt.Errorf("BatteryPassport type marker missing")
	}
	return compliance.Verify(cred, iss.PublicKey())
}

func checkSCITTRoundTrip(ctx context.Context) error {
	ledger, err := scitt.NewLedger("did:web:doctor.ts")
	if err != nil {
		return err
	}
	defer func() { _ = ledger.Close() }()
	iss, _ := compliance.NewIssuer("did:web:doctor.iss")
	stmt, err := scitt.SignStatement(iss.PrivateKey(), iss.ID, "doctor-subj", "text/plain", []byte("payload"))
	if err != nil {
		return err
	}
	receipt, err := ledger.Register(stmt)
	if err != nil {
		return err
	}
	return scitt.VerifyReceipt(receipt, stmt, ledger.PublicKey())
}

func checkSCITTGrowth(ctx context.Context) error {
	ledger, _ := scitt.NewLedger("did:web:doctor.ts")
	defer func() { _ = ledger.Close() }()
	iss, _ := compliance.NewIssuer("did:web:doctor.iss")
	// Register 20 statements
	for i := 0; i < 20; i++ {
		stmt, _ := scitt.SignStatement(iss.PrivateKey(), iss.ID,
			fmt.Sprintf("subj-%d", i), "text/plain", []byte(fmt.Sprintf("p%d", i)))
		if _, err := ledger.Register(stmt); err != nil {
			return err
		}
	}
	// Verify leaf 0 still has valid inclusion in grown tree
	stmt, receipt, err := ledger.Get(0)
	if err != nil {
		return err
	}
	return scitt.VerifyReceipt(receipt, stmt, ledger.PublicKey())
}

func checkRevocationSignedList(ctx context.Context) error {
	iss, err := compliance.NewIssuer("did:web:doctor.revocation")
	if err != nil {
		return err
	}
	list := revocation.New(iss.ID)
	if _, err := list.Revoke("cred-doctor-1", revocation.ReasonRecall, "diagnostic recall"); err != nil {
		return err
	}
	if !list.IsRevoked("cred-doctor-1") {
		return fmt.Errorf("revoked credential not reported revoked")
	}
	if list.IsRevoked("cred-doctor-unknown") {
		return fmt.Errorf("never-revoked credential reported revoked")
	}
	signed, err := list.Sign(iss.PrivateKey())
	if err != nil {
		return err
	}
	if err := revocation.Verify(signed, iss.PublicKey()); err != nil {
		return fmt.Errorf("signed list verification failed: %w", err)
	}
	// Tamper detection: a different key must not verify.
	otherPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	if err := revocation.Verify(signed, otherPub); err == nil {
		return fmt.Errorf("CRITICAL: signed list verified under wrong key")
	}
	return nil
}

func checkRevocationBitstring(ctx context.Context) error {
	list := revocation.NewBitstringStatusList(revocation.PurposeRevocation, revocation.MinBitstringSize)
	if err := list.SetStatus(42, true); err != nil {
		return err
	}
	on, err := list.GetStatus(42)
	if err != nil {
		return err
	}
	if !on {
		return fmt.Errorf("bit 42 set but reads false")
	}
	encoded, err := list.EncodedList()
	if err != nil {
		return err
	}
	decoded, err := revocation.DecodeBitstringStatusList(revocation.PurposeRevocation, encoded)
	if err != nil {
		return fmt.Errorf("encode/decode round-trip failed: %w", err)
	}
	on2, err := decoded.GetStatus(42)
	if err != nil {
		return err
	}
	if !on2 {
		return fmt.Errorf("bit 42 lost across encode/decode round-trip")
	}
	return nil
}

func checkMdocDeviceAuth(ctx context.Context) error {
	issuerPub, issuerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	devicePub, devicePriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	cred, err := mdoc.Issue(mdoc.IssueParams{
		DocType: "org.iso.18013.5.1.mDL",
		NameSpaces: map[string][]mdoc.Element{
			"org.iso.18013.5.1": {
				{Identifier: "family_name", Value: "Doctor"},
				{Identifier: "age_over_18", Value: true},
			},
		},
		Validity:   mdoc.ValidityInfo{Signed: now, ValidFrom: now, ValidUntil: now.Add(24 * time.Hour)},
		DeviceKey:  devicePub,
		IssuerPriv: issuerPriv,
	})
	if err != nil {
		return err
	}
	transcript := []byte("doctor-session-transcript")
	doc, err := mdoc.PresentWithDeviceAuth(cred,
		map[string][]string{"org.iso.18013.5.1": {"family_name"}},
		"org.iso.18013.5.1.mDL", devicePriv, transcript)
	if err != nil {
		return err
	}
	vd, err := mdoc.VerifyDocument(doc, issuerPub, transcript, now)
	if err != nil {
		return fmt.Errorf("device-authenticated document failed verification: %w", err)
	}
	if vd.NameSpaces["org.iso.18013.5.1"]["family_name"] != "Doctor" {
		return fmt.Errorf("disclosed family_name missing/incorrect")
	}
	if _, leaked := vd.NameSpaces["org.iso.18013.5.1"]["age_over_18"]; leaked {
		return fmt.Errorf("CRITICAL: undisclosed claim age_over_18 leaked")
	}
	// Replay against a different transcript must be rejected.
	if _, err := mdoc.VerifyDocument(doc, issuerPub, []byte("attacker-transcript"), now); err == nil {
		return fmt.Errorf("CRITICAL: device auth accepted under wrong session transcript")
	}
	return nil
}

func checkStorageRoundTrip(ctx context.Context) error {
	s := storage.NewMemoryStorage()
	defer func() { _ = s.Close() }()
	idx, err := s.AppendStatement([]byte(`{"test":"data"}`))
	if err != nil {
		return err
	}
	if idx != 0 {
		return fmt.Errorf("first idx should be 0, got %d", idx)
	}
	sz, err := s.Size()
	if err != nil {
		return err
	}
	if sz != 1 {
		return fmt.Errorf("size after 1 append: %d", sz)
	}
	count := 0
	err = s.IterateStatements(func(idx uint64, blob storage.StatementBlob) error {
		count++
		return nil
	})
	if err != nil {
		return err
	}
	if count != 1 {
		return fmt.Errorf("iterate count: %d", count)
	}
	return nil
}

func checkTelemetrySnapshot(ctx context.Context) error {
	tel := telemetry.New(telemetry.NopRecorder{})
	tel.Counter("doctor.test").Inc()
	tel.Histogram("doctor.hist").Observe(1.5)
	snap := tel.Snapshot()
	if snap.Counters["doctor.test"] != 1 {
		return fmt.Errorf("counter snapshot wrong")
	}
	if snap.Histograms["doctor.hist"].Count != 1 {
		return fmt.Errorf("histogram snapshot wrong")
	}
	return nil
}
