// DC-API live browser demo handler
//
// Apple/Google Wallet 対応ブラウザで以下のURLを開くと動作確認可能:
//
//	https://<verify.server>/dcapi/demo
//
// 1ページ完結: Verify ボタン → navigator.credentials.get() → 結果表示
package dcapi

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"blrcs/openid4vp"
)

// DemoHandler — DC-API クライアント側JSを含むシングルページ
//
// verifier: BLRCS openid4vp.Verifier — 実セッション管理担当
// def: このデモが要求する PresentationDefinition
//
// レイアウト:
//
//	GET  /dcapi/demo         — HTMLページ
//	POST /dcapi/demo/authorize — PresentationRequest生成 (DC-API payload返却)
//	POST /dcapi/demo/callback  — DC-API response受取 & 検証
func DemoHandler(verifier *openid4vp.Verifier, def openid4vp.PresentationDefinition, prefix string) http.Handler {
	prefix = strings.TrimRight(prefix, "/")
	mux := http.NewServeMux()

	mux.HandleFunc(prefix+"/demo", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		fmt.Fprint(w, renderDemoHTML(prefix, def))
	})

	mux.HandleFunc(prefix+"/demo/authorize", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		reqURL, state, err := verifier.CreateRequest(def)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// DC-API 用のブラウザ向け payload も生成
		call, err := BuildForVerifier(def, extractNonce(reqURL), verifier.ClientID, verifier.ResponseURI)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"requestURL": reqURL, // QR用(ネイティブWalletアプリ)
			"state":      state,
			"dcapi":      call, // ブラウザ用 navigator.credentials.get() 直接渡す
		})
	})

	mux.HandleFunc(prefix+"/demo/callback", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
		if err != nil {
			writeJSONErr(w, http.StatusBadRequest, err.Error())
			return
		}
		// body は {"protocol":"...", "data":{...}, "state":"..."}
		var dc DCAPIResponse
		wrapper := struct {
			DCAPIResponse
			State string `json:"state"`
		}{}
		if err := json.Unmarshal(body, &wrapper); err != nil {
			writeJSONErr(w, http.StatusBadRequest, "parse: "+err.Error())
			return
		}
		dc = wrapper.DCAPIResponse
		vpToken, responseState, err := dc.ExtractVPToken()
		if err != nil {
			writeJSONErr(w, http.StatusBadRequest, err.Error())
			return
		}
		// DC-API openid4vp パスでは state がinner payloadに入ることがある
		state := wrapper.State
		if state == "" {
			state = responseState
		}
		resp := &openid4vp.AuthorizationResponse{
			VPToken: vpToken,
			State:   state,
		}
		vp, err := verifier.ProcessResponse(resp)
		if err != nil {
			writeJSONErr(w, http.StatusBadRequest, err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":  "success",
			"subject": vp.Subject,
			"issuer":  vp.Issuer,
			"claims":  vp.Claims,
		})
	})

	return mux
}

func writeJSONErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status": "failure",
		"error":  msg,
	})
}

// extractNonce — request URL から nonce を取り出す (既存のCreateRequest結果から)
func extractNonce(reqURL string) string {
	// openid4vp://authorize?...&nonce=XXX&...
	idx := strings.Index(reqURL, "nonce=")
	if idx == -1 {
		return ""
	}
	s := reqURL[idx+len("nonce="):]
	end := strings.IndexByte(s, '&')
	if end == -1 {
		return s
	}
	return s[:end]
}

// renderDemoHTML — 完結HTML (外部CDN依存なし、Apple式ミニマル)
func renderDemoHTML(prefix string, def openid4vp.PresentationDefinition) string {
	claims := strings.Join(def.RequiredClaims, ", ")
	return `<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>BLRCS Digital Credentials — Live Verify</title>
<style>
  :root { color-scheme: light dark; }
  body {
    font: 15px/1.5 -apple-system, BlinkMacSystemFont, "SF Pro Text", sans-serif;
    max-width: 42rem; margin: 2rem auto; padding: 0 1.25rem;
    color: #1d1d1f;
    background: #fff;
  }
  @media (prefers-color-scheme: dark) {
    body { background: #000; color: #f5f5f7; }
    .panel { background: #1c1c1e; border-color: #333; }
  }
  h1 { font-size: 1.6rem; letter-spacing: -0.02em; margin: 0 0 0.5rem; }
  p.lead { color: #666; margin: 0 0 1.5rem; }
  .panel {
    border: 1px solid #e5e5e7;
    border-radius: 12px;
    padding: 1.25rem;
    margin: 1rem 0;
    background: #fafafa;
  }
  button {
    font: inherit; font-weight: 600;
    background: #0071e3; color: #fff;
    border: none; border-radius: 8px;
    padding: 0.6rem 1.1rem;
    cursor: pointer;
  }
  button:hover { background: #0077ed; }
  button:disabled { background: #999; cursor: wait; }
  pre {
    background: #0f0f11; color: #e5e5e7;
    padding: 0.75rem 1rem; border-radius: 8px;
    overflow: auto;
    font: 13px/1.4 "SF Mono", Menlo, monospace;
    white-space: pre-wrap;
    word-break: break-all;
  }
  .ok { color: #30d158; }
  .err { color: #ff453a; }
  small { color: #86868b; }
  kbd {
    background: #f1f1f3; padding: 0.1rem 0.35rem; border-radius: 4px;
    font-family: "SF Mono", monospace; font-size: 12px;
  }
</style>
</head>
<body>
<h1>BLRCS Digital Credentials</h1>
<p class="lead">Apple Wallet / Google Wallet / EUDI Wallet 互換検証デモ。</p>

<div class="panel">
  <strong>要求する開示項目</strong><br>
  <small>` + claims + `</small>
</div>

<button id="verify">Verify Identity</button>
<small id="hint"> — Wallet がインストールされた Safari 26 / Chrome 141 で動作</small>

<div class="panel" id="result" hidden>
  <div id="status"></div>
  <pre id="payload"></pre>
</div>

<script>
(async () => {
  const btn = document.getElementById('verify');
  const result = document.getElementById('result');
  const statusEl = document.getElementById('status');
  const payloadEl = document.getElementById('payload');

  if (typeof DigitalCredential === 'undefined' && !('credentials' in navigator)) {
    btn.disabled = true;
    btn.textContent = 'Not supported in this browser';
    return;
  }

  btn.addEventListener('click', async () => {
    btn.disabled = true;
    btn.textContent = 'Requesting…';
    result.hidden = false;
    statusEl.className = '';
    statusEl.textContent = '';
    payloadEl.textContent = '';

    try {
      // 1. Backend から DC-API request を取得
      const authResp = await fetch('` + prefix + `/demo/authorize', {method: 'POST'});
      if (!authResp.ok) throw new Error('authorize failed: ' + authResp.status);
      const {dcapi, state} = await authResp.json();

      // 2. ブラウザで Wallet 起動
      const credential = await navigator.credentials.get(dcapi);
      if (!credential) throw new Error('No credential returned');

      // 3. Backend に検証委託
      const cbResp = await fetch('` + prefix + `/demo/callback', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
          protocol: credential.protocol,
          data: JSON.parse(credential.data),
          state: state,
        })
      });
      const out = await cbResp.json();
      if (out.status === 'success') {
        statusEl.className = 'ok';
        statusEl.innerHTML = '✓ Verified — issuer: <code>' + out.issuer + '</code>';
        payloadEl.textContent = JSON.stringify(out.claims, null, 2);
      } else {
        statusEl.className = 'err';
        statusEl.textContent = '✗ ' + out.error;
      }
    } catch (err) {
      statusEl.className = 'err';
      statusEl.textContent = '✗ ' + err.message;
    } finally {
      btn.disabled = false;
      btn.textContent = 'Verify Identity';
    }
  });
})();
</script>
</body>
</html>`
}
