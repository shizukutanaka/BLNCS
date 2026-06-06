// blrcs-demo — Live DC-API demo server
//
// 使用:
//
//	blrcs-demo                                  # http://localhost:8090/demo
//	BLRCS_DEMO_LISTEN=:9000 blrcs-demo
//
// デモシナリオ: 繊維製品 DPP を検証サイトから要求、walletが開いて選択開示で応答
package main

import (
	"fmt"
	"net/http"
	"os"

	"blrcs/compliance"
	"blrcs/dcapi"
	"blrcs/openid4vp"
	"blrcs/tlsharden"
)

func main() {
	listen := envOr("BLRCS_DEMO_LISTEN", ":8090")

	iss, err := compliance.NewIssuer("did:web:factory.blrcs.example/demo")
	if err != nil {
		die("issuer init:", err)
	}
	ver := openid4vp.NewVerifier(
		"https://verify.blrcs.example",
		"",
		nil,
	)
	def := openid4vp.PresentationDefinition{
		ID:      "blrcs-demo-eu-dpp",
		Purpose: "EU ESPR compliance check",
		RequiredClaims: []string{
			"productId",
			"category",
			"originCountry",
			"carbonKgCO2e",
		},
		AcceptableIssuers: map[string][]byte{iss.ID: iss.PublicKey()},
	}
	mux := http.NewServeMux()
	mux.Handle("/", dcapi.DemoHandler(ver, def, ""))

	fmt.Fprintf(os.Stderr, "blrcs-demo listening on %s\n", listen)
	fmt.Fprintf(os.Stderr, "  Open http://localhost%s/demo in Safari 26 or Chrome 141\n", listen)
	fmt.Fprintf(os.Stderr, "  Demo issuer: %s\n", iss.ID)

	if err := tlsharden.HardenedServer(listen, mux).ListenAndServe(); err != nil {
		die("serve:", err)
	}
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func die(args ...any) {
	fmt.Fprintln(os.Stderr, args...)
	os.Exit(1)
}
