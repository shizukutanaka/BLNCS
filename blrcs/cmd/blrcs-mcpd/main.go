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
//
// エンドポイント:
//
//	POST /mcp          — JSON-RPC
//	GET  /mcp          — SSE stream
//	DELETE /mcp        — session close
//	GET /healthz       — liveness probe
//	GET /readyz        — readiness probe
//
// BLRCS_VCI_URL 設定時のみ (OpenID4VCI, wallet向け):
//
//	GET  /.well-known/openid-credential-issuer
//	GET  /.well-known/jwks.json
//	POST /token
//	POST /nonce
//	POST /credential
package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"blrcs/atrest"
	"blrcs/compliance"
	"blrcs/config"
	"blrcs/healthprobe"
	"blrcs/httpmw"
	"blrcs/mcp"
	"blrcs/metrics"
	"blrcs/openid4vci"
	"blrcs/storage"
	"blrcs/telemetry"
)

func main() {
	listen := envOr("BLRCS_LISTEN", ":8080")
	tsID := envOr("BLRCS_TS_ID", "did:web:blrcs.example/ts")
	serverDID := envOr("BLRCS_SERVER_DID", "did:web:blrcs.example/mcp")
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
	demoIssuer, _ := compliance.NewIssuer("did:web:blrcs.example/demo-issuer")
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
	// Wrap MCP handler with panic recovery so a tool panic cannot crash the daemon.
	mcpHandler := mcp.NewHTTPHandler(srv, auth, limiter)
	// Stop the handler's background session-GC goroutine on shutdown.
	defer func() { _ = mcpHandler.Close() }()
	mux.Handle("/mcp", httpmw.Recovery(mcpHandler))
	mux.Handle("/metrics", exp)
	mux.Handle("/healthz", probe.Liveness())
	mux.Handle("/readyz", probe.Readiness())
	if vciIssuer != nil {
		// Mounted at "/" (catch-all): openid4vci.Issuer.Handler() owns its own
		// absolute paths (/.well-known/..., /token, /nonce, /credential) per
		// spec — none collide with /mcp, /metrics, /healthz, /readyz above,
		// which win on ServeMux's longest-match regardless of registration order.
		mux.Handle("/", httpmw.Recovery(vciIssuer.Handler()))
		fmt.Fprintf(os.Stderr, "openid4vci: issuer enabled at %s\n", vciURL)
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
