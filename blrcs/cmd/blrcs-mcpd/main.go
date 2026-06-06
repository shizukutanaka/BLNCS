// blrcs-mcpd — BLRCS MCP HTTP daemon (MCP 2.0 Streamable HTTP)
//
// 使用:
//
//	blrcs-mcpd                                                   # HTTP 8080
//	BLRCS_LISTEN=:9090 BLRCS_DATA_DIR=/data blrcs-mcpd           # 永続
//	BLRCS_TLS_CERT=cert.pem BLRCS_TLS_KEY=key.pem blrcs-mcpd     # HTTPS
//	BLRCS_AUTH_TOKENS=token1:agent-1,token2:agent-2 blrcs-mcpd   # Bearer auth
//	BLRCS_RATE_LIMIT_RPS=10 blrcs-mcpd                           # 10req/s per principal
//
// エンドポイント:
//
//	POST /mcp          — JSON-RPC
//	GET  /mcp          — SSE stream
//	DELETE /mcp        — session close
//	GET /healthz       — liveness probe
//	GET /readyz        — readiness probe
package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"blrcs/compliance"
	"blrcs/mcp"
	"blrcs/storage"
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
	if dataDir == "" {
		srv, err = mcp.NewServer(tsID, serverDID)
	} else {
		store, serr := storage.NewFileStorage(dataDir)
		if serr != nil {
			fatal("storage init:", serr)
		}
		srv, err = mcp.NewServerWithStorage(tsID, serverDID, store)
	}
	if err != nil {
		fatal("server init:", err)
	}

	// Demo issuers
	demoIssuer, _ := compliance.NewIssuer("did:web:blrcs.example/demo-issuer")
	demoSensor, _ := compliance.NewSensorAttester("did:device:blrcs-demo-sensor")
	srv.RegisterIssuer(demoIssuer)
	srv.RegisterAttester(demoSensor)

	// Auth
	var auth mcp.AuthVerifier
	if authTokens != "" {
		tokens := parseTokens(authTokens)
		auth = &mcp.BearerTokenAuth{Tokens: tokens}
		fmt.Fprintf(os.Stderr, "auth: bearer (%d tokens)\n", len(tokens))
	}

	// Rate limiting
	var limiter mcp.RateLimiter
	if rateLimitStr != "" {
		rps, err := strconv.ParseFloat(rateLimitStr, 64)
		if err == nil && rps > 0 {
			limiter = mcp.NewTokenBucketLimiter(rps, rps*2)
			fmt.Fprintf(os.Stderr, "rate limit: %.0f rps per principal\n", rps)
		}
	}

	// Routes
	mux := http.NewServeMux()
	mux.Handle("/mcp", mcp.NewHTTPHandler(srv, auth, limiter))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "ledger_size=%d", srv.Ledger().Size())
	})

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

// parseTokens — "token1:principal1,token2:principal2" → map
func parseTokens(s string) map[string]string {
	m := make(map[string]string)
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		idx := strings.Index(part, ":")
		if idx <= 0 || idx == len(part)-1 {
			continue
		}
		m[part[:idx]] = part[idx+1:]
	}
	return m
}

func fatal(args ...any) {
	fmt.Fprintln(os.Stderr, args...)
	os.Exit(1)
}
