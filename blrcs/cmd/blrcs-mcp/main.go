// blrcs-mcp — BLRCS Model Context Protocol server (stdio)
//
// 使用:
//
//	blrcs-mcp                                # 揮発モード (テスト/デモ)
//	BLRCS_DATA_DIR=/var/lib/blrcs blrcs-mcp  # 永続モード (プロダクション)
//
// Claude Desktop / Cursor / VS Code MCP拡張 等から:
//
//	{"mcpServers":{"blrcs":{"command":"blrcs-mcp","env":{"BLRCS_DATA_DIR":"/var/lib/blrcs"}}}}
//
// 環境変数:
//
//	BLRCS_TS_ID      — Transparency Service DID (default: did:web:blrcs.example/ts)
//	BLRCS_SERVER_DID — Server self DID        (default: did:web:blrcs.example/mcp)
//	BLRCS_DATA_DIR   — 永続化ディレクトリ。未設定なら揮発
package main

import (
	"fmt"
	"os"

	"blrcs/compliance"
	"blrcs/mcp"
	"blrcs/storage"
)

func main() {
	tsID := envOr("BLRCS_TS_ID", "did:web:blrcs.example/ts")
	serverDID := envOr("BLRCS_SERVER_DID", "did:web:blrcs.example/mcp")
	dataDir := os.Getenv("BLRCS_DATA_DIR")

	var srv *mcp.Server
	var err error
	if dataDir == "" {
		srv, err = mcp.NewServer(tsID, serverDID)
		fmt.Fprintln(os.Stderr, "blrcs-mcp: mode=memory (volatile)")
	} else {
		store, serr := storage.NewFileStorage(dataDir)
		if serr != nil {
			fmt.Fprintln(os.Stderr, "storage init:", serr)
			os.Exit(1)
		}
		defer func() { _ = store.Close() }()
		srv, err = mcp.NewServerWithStorage(tsID, serverDID, store)
		fmt.Fprintf(os.Stderr, "blrcs-mcp: mode=persistent dir=%s\n", dataDir)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "server init:", err)
		os.Exit(1)
	}

	// MVP: デモ用発行者/センサ自動登録。本番では外部設定/KMS連携
	demoIssuer, _ := compliance.NewIssuer("did:web:blrcs.example/demo-issuer")
	demoSensor, _ := compliance.NewSensorAttester("did:device:blrcs-demo-sensor")
	srv.RegisterIssuer(demoIssuer)
	srv.RegisterAttester(demoSensor)

	fmt.Fprintf(os.Stderr, "  ts_id=%s\n", tsID)
	fmt.Fprintf(os.Stderr, "  server_did=%s\n", serverDID)
	fmt.Fprintf(os.Stderr, "  demo_issuer_did=%s\n", demoIssuer.ID)
	fmt.Fprintf(os.Stderr, "  demo_sensor_did=%s\n", demoSensor.ID)
	fmt.Fprintf(os.Stderr, "  ledger_size=%d\n", srv.Ledger().Size())

	if err := srv.Serve(os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "serve:", err)
		os.Exit(1)
	}
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
