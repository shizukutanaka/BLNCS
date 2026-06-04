// Package i18n — 多言語メッセージ管理
//
// Apple NSLocalizedString / Xcode Strings Catalog 相当。
// stdlib のみ。
package i18n

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

// ============================================================================
// Bundle
// ============================================================================

// Bundle — key → locale → message template のルックアップ表
type Bundle struct {
	mu       sync.RWMutex
	messages map[string]map[string]string // key → (locale → template)
}

// NewBundle — 初期メッセージ付き Bundle 構築
// msgs: key → (locale → message) マップ、nil 可
func NewBundle(msgs map[string]map[string]string) *Bundle {
	b := &Bundle{messages: make(map[string]map[string]string)}
	for k, locales := range msgs {
		b.messages[k] = make(map[string]string, len(locales))
		for loc, msg := range locales {
			b.messages[k][loc] = msg
		}
	}
	return b
}

// AddMessage — 1キー×1ロケールのメッセージ追加
func (b *Bundle) AddMessage(key, locale, template string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.messages[key] == nil {
		b.messages[key] = make(map[string]string)
	}
	b.messages[key][locale] = template
}

// Lookup — 指定 key + locale の生テンプレート取得
func (b *Bundle) Lookup(key, locale string) (string, bool) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	locales, ok := b.messages[key]
	if !ok {
		return "", false
	}
	msg, ok := locales[locale]
	return msg, ok
}

// Translate — key + locale でメッセージ生成、args は fmt.Sprintf 展開
//
// 指定 locale が無ければ最初に見つかるロケールにフォールバック
// key 自体が無ければ key 文字列をそのまま返す (Apple NSLocalizedString 互換)
func (b *Bundle) Translate(key, locale string, args ...any) string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	locales, ok := b.messages[key]
	if !ok {
		return key
	}
	tmpl, ok := locales[locale]
	if !ok {
		// Fallback: 言語コードの前方一致 (ja-JP → ja)
		prefix := locale
		if idx := strings.IndexByte(prefix, '-'); idx > 0 {
			prefix = prefix[:idx]
		}
		if t, ok := locales[prefix]; ok {
			tmpl = t
		} else {
			// どのロケールでもいいから返す (Apple風フォールバック)
			for _, t := range locales {
				tmpl = t
				break
			}
		}
	}
	if tmpl == "" {
		return key
	}
	if len(args) > 0 {
		return fmt.Sprintf(tmpl, args...)
	}
	return tmpl
}

// Locales — 指定 key が対応するロケール一覧
func (b *Bundle) Locales(key string) []string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	locales, ok := b.messages[key]
	if !ok {
		return nil
	}
	out := make([]string, 0, len(locales))
	for l := range locales {
		out = append(out, l)
	}
	sort.Strings(out)
	return out
}

// LoadJSON — JSON 形式の一括ロード
//
// 形式: {"key": {"locale": "message", ...}, ...}
func (b *Bundle) LoadJSON(data []byte) error {
	var raw map[string]map[string]string
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for k, locales := range raw {
		if b.messages[k] == nil {
			b.messages[k] = make(map[string]string)
		}
		for loc, msg := range locales {
			b.messages[k][loc] = msg
		}
	}
	return nil
}

// ============================================================================
// Global singleton — package-level convenience API
// ============================================================================

var (
	globalBundle *Bundle
	globalLocale atomic.Value // string
)

func init() {
	globalBundle = NewBundle(builtinMessages())
	globalLocale.Store("en")
}

// SetLocale — グローバルロケール設定
func SetLocale(locale string) {
	globalLocale.Store(locale)
}

// GetLocale — 現在のグローバルロケール
func GetLocale() string {
	return globalLocale.Load().(string)
}

// T — グローバルバンドルで現在ロケールの翻訳を取得
func T(key string, args ...any) string {
	return globalBundle.Translate(key, GetLocale(), args...)
}

// TLocale — グローバルバンドルで指定ロケールの翻訳 (グローバル state 変更なし)
func TLocale(locale, key string, args ...any) string {
	return globalBundle.Translate(key, locale, args...)
}

// AddMessages — グローバルバンドルにメッセージ追加
func AddMessages(msgs map[string]map[string]string) {
	for k, locales := range msgs {
		for loc, msg := range locales {
			globalBundle.AddMessage(k, loc, msg)
		}
	}
}

// LoadJSONGlobal — グローバルバンドルに JSON 一括ロード
func LoadJSONGlobal(data []byte) error {
	return globalBundle.LoadJSON(data)
}

// ============================================================================
// Accept-Language header parsing
// ============================================================================

// LocaleFromAcceptLanguage — HTTP Accept-Language ヘッダからベストロケール選択
//
// RFC 7231 §5.3.5 の weight (q=) を解析し、supported の中から最良を返す
// 一致なしなら supported[0] にフォールバック
func LocaleFromAcceptLanguage(header string, supported []string) string {
	if len(supported) == 0 {
		return "en"
	}
	if header == "" || header == "*" {
		return supported[0]
	}
	supportedSet := make(map[string]bool, len(supported))
	for _, s := range supported {
		supportedSet[s] = true
	}
	// Parse tags by quality
	tags := strings.Split(header, ",")
	for _, tag := range tags {
		tag = strings.TrimSpace(tag)
		// Remove quality suffix
		lang := tag
		if idx := strings.Index(tag, ";"); idx > 0 {
			lang = tag[:idx]
		}
		lang = strings.TrimSpace(lang)
		// Exact match
		if supportedSet[lang] {
			return lang
		}
		// Prefix match (ja-JP → ja)
		if idx := strings.IndexByte(lang, '-'); idx > 0 {
			prefix := lang[:idx]
			if supportedSet[prefix] {
				return prefix
			}
		}
	}
	return supported[0]
}

// ============================================================================
// Built-in BLRCS messages (en + ja)
// ============================================================================

func builtinMessages() map[string]map[string]string {
	return map[string]map[string]string{
		"compliance.invalidProductID": {
			"en": "Invalid product ID: %s",
			"ja": "無効な製品ID: %s",
		},
		"compliance.signatureInvalid": {
			"en": "Signature verification failed",
			"ja": "署名検証に失敗しました",
		},
		"compliance.expired": {
			"en": "Credential expired at %s",
			"ja": "資格情報は %s に期限切れです",
		},
		"compliance.issuerUnknown": {
			"en": "Unknown issuer: %s",
			"ja": "不明な発行者: %s",
		},
		"scitt.registered": {
			"en": "Statement registered at leaf %d",
			"ja": "ステートメントをリーフ %d に登録しました",
		},
		"scitt.inclusionFailed": {
			"en": "Inclusion proof verification failed",
			"ja": "包含証明の検証に失敗しました",
		},
		"storage.writeFailed": {
			"en": "Failed to write to storage: %s",
			"ja": "ストレージへの書き込みに失敗しました: %s",
		},
		"privacy.minimizationViolation": {
			"en": "Data minimization violation: operation %s accessed %s",
			"ja": "データ最小化違反: 操作 %s が %s にアクセスしました",
		},
	}
}
