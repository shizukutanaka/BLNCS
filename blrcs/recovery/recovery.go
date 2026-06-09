// Package recovery — panic 回復ミドルウェア
//
// Apple NSExceptionHandler / Sentry / OS crash reporter 相当。
// HTTP ハンドラ・goroutine・MCP ツール呼出 — どこで panic しても:
//  1. プロセス全体は絶対に死なない
//  2. 構造化ログでスタックトレース記録
//  3. telemetry counter 自動増分
//  4. クライアントには 500 + 安全な短文を返却 (内部詳細漏洩なし)
//
// Apple 設計: defer recover() を中央集約、各ハンドラに散らばらせない
//
// 使用:
//
//	srv := &http.Server{
//	    Handler: recovery.Wrap(mux, telemetry.Default()),
//	}
//
//	recovery.Go(ctx, func() {
//	    // panic しても捕捉される独立 goroutine
//	    riskyWork()
//	})
package recovery

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"runtime/debug"

	"blrcs/telemetry"
)

// Wrap — net/http.Handler を panic 回復付きでラップ
//
// panic は recover、構造化ログに stack を出力、telemetry に1イベント。
// Apple iOS でアプリがクラッシュしても OS 側で symbolicated crash log を残すのと同じ。
func Wrap(h http.Handler, tel *telemetry.Telemetry) http.Handler {
	if tel == nil {
		tel = telemetry.Default()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sw := &statusWriter{ResponseWriter: w}
		defer func() {
			rec := recover()
			if rec == nil {
				return
			}
			handlePanic(tel, rec, "http.handler",
				slog.String("path", r.URL.Path),
				slog.String("method", r.Method),
				slog.String("remote", r.RemoteAddr),
			)
			// 既にレスポンスが書込み始められている場合、500 を上書きすると
			// "superfluous WriteHeader" と body 破損を招くため何もしない。
			if sw.wrote {
				return
			}
			defer func() { _ = recover() }() // double-panic 防止
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"error":"internal server error","status":500}`))
		}()
		h.ServeHTTP(sw, r)
	})
}

// statusWriter records whether the wrapped handler has begun writing the
// response, so the panic guard can avoid a superfluous WriteHeader on a partial
// response.
type statusWriter struct {
	http.ResponseWriter
	wrote bool
}

func (w *statusWriter) WriteHeader(code int) {
	w.wrote = true
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	w.wrote = true
	return w.ResponseWriter.Write(b)
}

// Flush forwards to the underlying writer when it supports http.Flusher.
func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Go — panic 回復付き goroutine
//
// 渡された関数が panic しても、プロセス全体は影響を受けない。
// MCP の auto-audit goroutine、ledger replay job 等で使う。
func Go(ctx context.Context, tel *telemetry.Telemetry, name string, fn func()) {
	if tel == nil {
		tel = telemetry.Default()
	}
	go func() {
		defer func() {
			if rec := recover(); rec != nil {
				handlePanic(tel, rec, "goroutine."+name)
			}
		}()
		fn()
	}()
}

// Safe — defer 1行で panic を回復する関数 (関数の先頭で `defer recovery.Safe(...)`)
//
//	func MyHandler() {
//	    defer recovery.Safe(tel, "MyHandler", &err)
//	    // ... 危険な処理 ...
//	}
//
// errOut が nil 以外なら panic を error に変換して呼出側に返す
func Safe(tel *telemetry.Telemetry, name string, errOut *error) {
	rec := recover()
	if rec == nil {
		return
	}
	if tel == nil {
		tel = telemetry.Default()
	}
	handlePanic(tel, rec, name)
	if errOut != nil {
		*errOut = fmt.Errorf("recovered panic in %s: %v", name, rec)
	}
}

// handlePanic — 統一ロジック (重複排除)
func handlePanic(tel *telemetry.Telemetry, rec any, source string, extraAttrs ...slog.Attr) {
	stack := debug.Stack()
	attrs := []slog.Attr{
		slog.String("source", source),
		slog.Any("panic", rec),
		slog.String("stack", string(stack)),
	}
	attrs = append(attrs, extraAttrs...)
	tel.Error("panic.recovered", attrs...)
	tel.Counter("panic.recovered.total").Inc()
	tel.Counter("panic.recovered." + source).Inc()
}
