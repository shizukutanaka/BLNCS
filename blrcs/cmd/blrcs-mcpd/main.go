// blrcs-mcpd — BLRCS MCP HTTP daemon (MCP 2.0 Streamable HTTP)
//
// 使用:
//
//	blrcs-mcpd                                                   # HTTP 8080
//	BLRCS_LISTEN=:9090 BLRCS_DATA_DIR=/data blrcs-mcpd           # 永続
//	BLRCS_TLS_CERT=cert.pem BLRCS_TLS_KEY=key.pem blrcs-mcpd     # HTTPS
//	BLRCS_AUTH_TOKENS=token1:agent-1,token2:agent-2 blrcs-mcpd   # Bearer auth
//	BLRCS_RATE_LIMIT_RPS=10 blrcs-mcpd                           # 10req/s per principal
//	BLRCS_ENCRYPTION_KEY=<64 hex chars> BLRCS_DATA_DIR=/data blrcs-mcpd  # AES-256-GCM at rest
//	BLRCS_VCI_URL=https://issue.example blrcs-mcpd               # enable OpenID4VCI issuer
//	BLRCS_VP_CLIENT_ID=https://verify.example blrcs-mcpd         # enable OpenID4VP verifier
//	BLRCS_TRUSTED_DIDS=did:web:a.example,did:web:b.example       # restrict verify_*_by_did trust
//	BLRCS_DIAG=1 blrcs-mcpd                                      # enable /diag/snapshot.{json,txt}
//
// エンドポイント:
//
//	POST /mcp          — JSON-RPC
//	GET  /mcp          — SSE stream
//	DELETE /mcp        — session close
//	GET /healthz       — liveness probe
//	GET /readyz        — readiness probe
//	GET /metrics       — Prometheus metrics
//	GET /.well-known/blrcs-capabilities.json — 有効な機能の宣言 (get_server_capabilities と同一データ)
//	GET /.well-known/privacy.json            — GDPR Art.30 相当のデータ処理宣言
//
// BLRCS_DIAG=1 設定時のみ (運用診断):
//
//	GET /diag/snapshot.json — ランタイム/テレメトリ/直近エラーのスナップショット
//	GET /diag/snapshot.txt  — 同上 (人間可読)
//
// BLRCS_VCI_URL 設定時のみ (OpenID4VCI, wallet向け):
//
//	GET  /.well-known/openid-credential-issuer
//	GET  /.well-known/jwks.json
//	POST /token
//	POST /nonce
//	POST /credential
//
// BLRCS_VP_CLIENT_ID 設定時のみ (OpenID4VP, wallet向け):
//
//	POST /openid4vp/authorize — request 生成
//	POST /openid4vp/callback  — wallet からの vp_token 受付
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"blrcs/atrest"
	"blrcs/compliance"
	"blrcs/config"
	"blrcs/diag"
	"blrcs/didresolver"
	"blrcs/healthprobe"
	"blrcs/httpmw"
	"blrcs/mcp"
	"blrcs/metrics"
	"blrcs/openid4vci"
	"blrcs/openid4vp"
	"blrcs/privacy"
	"blrcs/storage"
	"blrcs/telemetry"
)

func main() {
	listen := envOr("BLRCS_LISTEN", ":8080")
	tsID := envOr("BLRCS_TS_ID", "did:web:localhost/ts")
	serverDID := envOr("BLRCS_SERVER_DID", "did:web:localhost/mcp")
	dataDir := os.Getenv("BLRCS_DATA_DIR")
	tlsCert := os.Getenv("BLRCS_TLS_CERT")
	tlsKey := os.Getenv("BLRCS_TLS_KEY")
	authTokens := os.Getenv("BLRCS_AUTH_TOKENS")
	rateLimitStr := os.Getenv("BLRCS_RATE_LIMIT_RPS")

	// Server init
	var srv *mcp.Server
	var err error
	var store *storage.FileStorage
	if dataDir == "" {
		srv, err = mcp.NewServer(tsID, serverDID)
	} else {
		store, err = storage.NewFileStorage(dataDir)
		if err != nil {
			fatal("storage init:", err)
		}
		// Persisted storage must be closed on shutdown to release the file handle.
		defer func() { _ = store.Close() }()

		// Optional encryption at rest: BLRCS_ENCRYPTION_KEY wraps the statement
		// log (DPP/Battery-Passport payloads, which may carry PII/confidential
		// supply-chain data) in AES-256-GCM before it touches disk. Off by
		// default so existing plaintext deployments are unaffected; the TS
		// signing keypair itself is unaffected either way — see
		// storage.EncryptedStorage's doc comment for why that's out of scope
		// here (it belongs to an external KMS/HSM, per atrest's own design).
		var backing storage.Storage = store
		if keyHex := os.Getenv("BLRCS_ENCRYPTION_KEY"); keyHex != "" {
			key, herr := hex.DecodeString(keyHex)
			if herr != nil || len(key) != atrest.KeySize {
				fatal("invalid BLRCS_ENCRYPTION_KEY:", fmt.Errorf("must be %d hex-encoded bytes (got %d)", atrest.KeySize*2, len(keyHex)))
			}
			cipher, cerr := atrest.NewCipher(atrest.KeyIDFromUint32(1), key)
			if cerr != nil {
				fatal("encryption init:", cerr)
			}
			backing = storage.NewEncryptedStorage(store, cipher)
			fmt.Fprintln(os.Stderr, "storage: statement log encrypted at rest (AES-256-GCM)")
		}
		srv, err = mcp.NewServerWithStorage(tsID, serverDID, backing)
	}
	if err != nil {
		fatal("server init:", err)
	}

	// Demo issuers
	// DID はハードコードされた存在しないドメイン (.example) ではなく、
	// operator が実際に指定した (または localhost にフォールバックする)
	// serverDID から派生させる — 常に一貫した、operator の意図した
	// ドメインを指す。
	demoIssuer, _ := compliance.NewIssuer(serverDID + "-issuer")
	demoSensor, _ := compliance.NewSensorAttester("did:device:blrcs-demo-sensor")
	srv.RegisterIssuer(demoIssuer)
	srv.RegisterAttester(demoSensor)

	// Optional OpenID4VCI issuer: the openid4vci package is fully implemented
	// and tested (including the §7 Nonce Endpoint proof-replay mitigation),
	// but ships its own http.Handler that nothing was mounting — off by
	// default (no wallet-facing endpoints unless BLRCS_VCI_URL is set) since,
	// unlike the MCP tool surface, this exposes unauthenticated endpoints a
	// real wallet talks to directly per spec.
	vciURL := os.Getenv("BLRCS_VCI_URL")
	var vciIssuer *openid4vci.Issuer
	if vciURL != "" {
		vciIssuer = openid4vci.NewIssuer(vciURL, demoIssuer)
		vciIssuer.RegisterConfiguration(openid4vci.CredentialConfiguration{
			ID:                "eu-dpp-v1",
			CredentialType:    "DigitalProductPassport",
			Format:            "vc+sd-jwt",
			DisclosableClaims: []string{"carbonKgCO2e"},
			ClearClaims:       []string{"productId", "category"},
			ValidForDays:      365,
		})
		srv.RegisterVCIIssuer(vciIssuer)
	}

	// Optional OpenID4VP verifier: same shape of gap as openid4vci — the
	// package's request/response protocol (CreateRequest/ProcessResponse) and
	// its production HTTP handlers (AuthorizeHandler/CallbackHandler) were
	// fully implemented and tested, but previously reachable only from
	// cmd/blrcs-demo (a throwaway demo binary), never this daemon. Off by
	// default for the same reason as VCI: these are unauthenticated endpoints
	// a real wallet talks to directly per spec.
	vpClientID := os.Getenv("BLRCS_VP_CLIENT_ID")
	var vpVerifier *openid4vp.Verifier
	if vpClientID != "" {
		responseURI := vpClientID + "/openid4vp/callback"
		vpVerifier = openid4vp.NewVerifier(vpClientID, responseURI, nil)
		srv.RegisterVPVerifier(vpVerifier)
	}

	// Optional trust anchor restriction for verify_passport_by_did/
	// verify_sdjwt_by_did: by default the server accepts whatever key a DID
	// resolves to (the same posture as an agent manually chaining
	// resolve_did -> verify_passport, which has no allowlist either). Setting
	// BLRCS_TRUSTED_DIDS opts into a real PKI-style restriction — only
	// credentials from these specific issuer DIDs verify via the *_by_did
	// tools, regardless of what any DID resolves to.
	if trustedDIDs := os.Getenv("BLRCS_TRUSTED_DIDS"); trustedDIDs != "" {
		anchor := didresolver.NewTrustAnchor()
		for _, did := range strings.Split(trustedDIDs, ",") {
			if did = strings.TrimSpace(did); did != "" {
				anchor.AddDID(did)
			}
		}
		srv.RegisterTrustAnchor(anchor)
		fmt.Fprintf(os.Stderr, "trust anchor: restricted to %d DID(s)\n", len(strings.Split(trustedDIDs, ",")))
	}

	// Auth
	var auth mcp.AuthVerifier
	if authTokens != "" {
		// Use config.ParseTokens rather than a hand-rolled parser: it fails fast
		// on a malformed pair, an empty principal, or a duplicate token instead of
		// silently dropping or overwriting entries. An empty principal is a real
		// hijack risk here — sessions are bound to their principal, so two tokens
		// both authenticating to "" could hijack each other's sessions.
		tokens, terr := config.ParseTokens(authTokens)
		if terr != nil {
			fatal("invalid BLRCS_AUTH_TOKENS:", terr)
		}
		auth = &mcp.BearerTokenAuth{Tokens: tokens}
		fmt.Fprintf(os.Stderr, "auth: bearer (%d tokens)\n", len(tokens))
	}

	// Rate limiting
	var limiter mcp.RateLimiter
	if rateLimitStr != "" {
		rps, perr := strconv.ParseFloat(rateLimitStr, 64)
		if perr != nil || rps <= 0 {
			// Fail fast: a malformed value must not silently leave the daemon
			// with NO rate limiting (which is what dropping the error did).
			fatal("invalid BLRCS_RATE_LIMIT_RPS:", fmt.Errorf("%q must be a positive number", rateLimitStr))
		}
		limiter = mcp.NewTokenBucketLimiter(rps, rps*2)
		fmt.Fprintf(os.Stderr, "rate limit: %.0f rps per principal\n", rps)
	}

	// Telemetry + metrics
	jsonLog := os.Getenv("BLRCS_LOG_FORMAT") == "json"
	tel := telemetry.New(telemetry.NewSlogRecorder(os.Stderr, jsonLog))
	telemetry.SetDefault(tel)
	exp := metrics.NewExporter(tel, map[string]string{"service": "blrcs-mcpd"})

	// Structured health probes (Kubernetes liveness / readiness)
	probe := healthprobe.New()
	// Liveness: the process is running and not deadlocked.
	probe.AddLiveness("process", healthprobe.AlwaysOK())
	// Readiness: ledger is accessible and (when persistent) storage is open.
	probe.AddReadiness("ledger", healthprobe.Closure(func() error {
		_ = srv.Ledger().Size() // panics only if ledger is nil
		return nil
	}))
	if store != nil {
		probe.AddReadiness("storage", healthprobe.Closure(func() error {
			_, err := store.Size()
			return err
		}))
	}

	// Routes
	mux := http.NewServeMux()
	// httpmw.Default = Recovery -> RequestID -> SecurityHeaders -> AccessLog,
	// BLRCS's documented recommended chain — was only bare Recovery on every
	// route (no request-ID correlation, no security response headers, no
	// structured access log). Safe to apply to the SSE-serving /mcp route:
	// statusWriter/loggingResponseWriter now forward Flush/Unwrap so
	// http.NewResponseController (and mcp/http.go's direct http.Flusher
	// assertion) still reach the real ResponseWriter through the wrapper
	// stack — see httpmw's TestResponseControllerDrillsThroughRecoveryAndAccessLog.
	mcpHandler := mcp.NewHTTPHandler(srv, auth, limiter)
	// Stop the handler's background session-GC goroutine on shutdown.
	defer func() { _ = mcpHandler.Close() }()
	mux.Handle("/mcp", httpmw.Default(mcpHandler))
	// Health/metrics endpoints keep Recovery only (no RequestID/AccessLog): they
	// are typically polled every few seconds by Kubernetes/monitoring, and full
	// access logging of that traffic is noise, not signal. They previously had
	// NO middleware at all — zero panic protection — which Recovery now closes.
	mux.Handle("/metrics", httpmw.Recovery(exp))
	mux.Handle("/healthz", httpmw.Recovery(probe.Liveness()))
	mux.Handle("/readyz", httpmw.Recovery(probe.Readiness()))
	if vciIssuer != nil {
		// Mounted at "/" (catch-all): openid4vci.Issuer.Handler() owns its own
		// absolute paths (/.well-known/..., /token, /nonce, /credential) per
		// spec — none collide with /mcp, /metrics, /healthz, /readyz above,
		// which win on ServeMux's longest-match regardless of registration order.
		mux.Handle("/", httpmw.Default(vciIssuer.Handler()))
		fmt.Fprintf(os.Stderr, "openid4vci: issuer enabled at %s\n", vciURL)
	}
	if vpVerifier != nil {
		mux.Handle("/openid4vp/authorize", httpmw.Default(vpVerifier.AuthorizeHandler()))
		mux.Handle("/openid4vp/callback", httpmw.Default(vpVerifier.CallbackHandler(srv.RecordPresentationResult)))
		fmt.Fprintf(os.Stderr, "openid4vp: verifier enabled at %s\n", vpClientID)
	}
	// Always-on RFC 8615 .well-known discovery documents — unlike BLRCS_DIAG
	// (runtime internals: goroutine/memory stats, recent error messages) these
	// are meant for public discovery and carry no sensitive data. Both packages
	// were implemented and tested with a ready-made default builder
	// (capability.New()/Snapshot, privacy.BLRCSDefaultManifest) but nothing was
	// serving them. The capabilities document reuses srv.CapabilitiesSnapshot()
	// — the exact same data get_server_capabilities returns over MCP — so both
	// transports agree; the privacy manifest is a static GDPR Art.30-style
	// declaration of what data categories this service processes, not a live
	// technical claim, so (unlike an OpenAPI spec) it doesn't risk describing
	// endpoints that may or may not be enabled for this instance.
	mux.Handle("/.well-known/blrcs-capabilities.json", httpmw.Default(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(srv.CapabilitiesSnapshot())
	})))
	mux.Handle("/.well-known/privacy.json", httpmw.Default(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(privacy.BLRCSDefaultManifest(serverDID, "1.0.0"))
	})))
	// Optional sysdiagnose-style diagnostic snapshot: the diag package is fully
	// implemented and tested with a ready-to-mount Handler(), but nothing was
	// mounting it. Off by default (BLRCS_DIAG=1) since the snapshot exposes
	// runtime internals (goroutine/memory stats, telemetry counters, recent
	// error messages) an operator may not want on an unauthenticated port —
	// same opt-in posture as BLRCS_VCI_URL / BLRCS_VP_CLIENT_ID. Reuses the
	// same telemetry the /metrics exporter reads, so the two stay consistent.
	if os.Getenv("BLRCS_DIAG") == "1" {
		diagGen := diag.NewGenerator(tel, diag.ProductInfo{
			Name:    "BLRCS",
			Service: "blrcs-mcpd",
		})
		diagGen.AddResource("ledger.size", func(context.Context) string {
			return strconv.FormatInt(int64(srv.Ledger().Size()), 10)
		})
		diagGen.AddResource("persist", func(context.Context) string {
			return strconv.FormatBool(dataDir != "")
		})
		// Handler() owns /diag/snapshot.json and /diag/snapshot.txt (no collision
		// with the routes above); mount at "/" only if openid4vci didn't already
		// claim the catch-all, otherwise mount its two exact paths individually.
		diagHandler := httpmw.Default(diagGen.Handler())
		if vciIssuer == nil {
			mux.Handle("/diag/", diagHandler)
		} else {
			mux.Handle("/diag/snapshot.json", diagHandler)
			mux.Handle("/diag/snapshot.txt", diagHandler)
		}
		fmt.Fprintln(os.Stderr, "diag: snapshot enabled at /diag/snapshot.{json,txt}")
	}

	httpSrv := &http.Server{
		Addr:              listen,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      0, // SSE
		IdleTimeout:       5 * time.Minute,
	}

	fmt.Fprintf(os.Stderr, "blrcs-mcpd listening on %s\n", listen)
	fmt.Fprintf(os.Stderr, "  persist=%t tls=%t\n", dataDir != "", tlsCert != "")
	fmt.Fprintf(os.Stderr, "  ledger_size=%d\n", srv.Ledger().Size())

	// Graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(ctx)
	}()

	// Start server
	var serveErr error
	if tlsCert != "" && tlsKey != "" {
		serveErr = httpSrv.ListenAndServeTLS(tlsCert, tlsKey)
	} else {
		serveErr = httpSrv.ListenAndServe()
	}
	if serveErr != nil && serveErr != http.ErrServerClosed {
		fatal("serve:", serveErr)
	}
	fmt.Fprintln(os.Stderr, "shutdown complete")
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func fatal(args ...any) {
	fmt.Fprintln(os.Stderr, args...)
	os.Exit(1)
}
