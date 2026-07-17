package i18n

import (
	"strings"
	"sync"
	"testing"
)

// ============================================================================
// Bundle basics
// ============================================================================

func TestBundleNewAndLookup(t *testing.T) {
	b := NewBundle(map[string]map[string]string{
		"hello": {"en": "Hello", "ja": "こんにちは"},
	})
	if got, ok := b.Lookup("hello", "en"); !ok || got != "Hello" {
		t.Errorf("en lookup: %s ok=%v", got, ok)
	}
	if got, ok := b.Lookup("hello", "ja"); !ok || got != "こんにちは" {
		t.Errorf("ja lookup: %s ok=%v", got, ok)
	}
	if _, ok := b.Lookup("nonexistent", "en"); ok {
		t.Error("missing key should return false")
	}
}

func TestBundleAddMessage(t *testing.T) {
	b := NewBundle(nil)
	b.AddMessage("greet", "en", "Hello %s")
	b.AddMessage("greet", "fr", "Bonjour %s")
	if got, _ := b.Lookup("greet", "fr"); got != "Bonjour %s" {
		t.Errorf("fr template: %s", got)
	}
}

func TestBundleTranslateWithArgs(t *testing.T) {
	b := NewBundle(map[string]map[string]string{
		"greet": {"en": "Hello %s, you have %d items"},
	})
	got := b.Translate("greet", "en", "Alice", 3)
	if got != "Hello Alice, you have 3 items" {
		t.Errorf("translate: %s", got)
	}
}

func TestBundleTranslateFallbackToDefault(t *testing.T) {
	b := NewBundle(map[string]map[string]string{
		"key": {"en": "English text"},
	})
	// Request 'fr' but only 'en' exists — fallback
	got := b.Translate("key", "fr")
	if got != "English text" {
		t.Errorf("fallback: %s", got)
	}
}

func TestBundleTranslateUnknownKey(t *testing.T) {
	b := NewBundle(nil)
	got := b.Translate("missing.key", "en", "arg")
	// Apple convention: unknown key returns key itself
	if !strings.Contains(got, "missing.key") {
		t.Errorf("unknown key: %s", got)
	}
}

func TestBundleLocales(t *testing.T) {
	b := NewBundle(map[string]map[string]string{
		"key1": {"en": "A", "ja": "B", "de": "C"},
	})
	locales := b.Locales("key1")
	found := make(map[string]bool)
	for _, l := range locales {
		found[l] = true
	}
	for _, want := range []string{"en", "ja", "de"} {
		if !found[want] {
			t.Errorf("missing locale: %s", want)
		}
	}
}

// ============================================================================
// JSON loading
// ============================================================================

func TestBundleLoadJSON(t *testing.T) {
	b := NewBundle(nil)
	data := []byte(`{
		"login.success": {"en": "Login successful", "ja": "ログイン成功"},
		"login.failed": {"en": "Login failed", "ja": "ログイン失敗"}
	}`)
	if err := b.LoadJSON(data); err != nil {
		t.Fatal(err)
	}
	if got := b.Translate("login.success", "ja"); got != "ログイン成功" {
		t.Errorf("ja translation: %s", got)
	}
}

func TestBundleLoadInvalidJSON(t *testing.T) {
	b := NewBundle(nil)
	if err := b.LoadJSON([]byte("not json")); err == nil {
		t.Fatal("invalid JSON should error")
	}
}

// ============================================================================
// Global state — SetLocale / T
// ============================================================================

func TestGlobalSetLocaleAndTranslate(t *testing.T) {
	prev := GetLocale()
	defer SetLocale(prev) // restore

	SetLocale("ja")
	if GetLocale() != "ja" {
		t.Errorf("locale: %s", GetLocale())
	}
	got := T("compliance.signatureInvalid")
	if got != "署名検証に失敗しました" {
		t.Errorf("ja: %s", got)
	}

	SetLocale("en")
	got = T("compliance.signatureInvalid")
	if got != "Signature verification failed" {
		t.Errorf("en: %s", got)
	}
}

func TestTLocaleOverride(t *testing.T) {
	prev := GetLocale()
	defer SetLocale(prev)
	SetLocale("en")

	got := TLocale("ja", "compliance.signatureInvalid")
	if got != "署名検証に失敗しました" {
		t.Errorf("locale override: %s", got)
	}
	// Global locale unchanged
	if GetLocale() != "en" {
		t.Error("TLocale should not mutate global")
	}
}

func TestAddMessagesGlobal(t *testing.T) {
	AddMessages(map[string]map[string]string{
		"my.test.key": {"en": "Test EN", "ja": "テストJA"},
	})
	if got := TLocale("ja", "my.test.key"); got != "テストJA" {
		t.Errorf("added message: %s", got)
	}
	if got := TLocale("en", "my.test.key"); got != "Test EN" {
		t.Errorf("added message en: %s", got)
	}
}

func TestLoadJSONGlobal(t *testing.T) {
	data := []byte(`{"json.global.key": {"en": "from JSON"}}`)
	if err := LoadJSONGlobal(data); err != nil {
		t.Fatal(err)
	}
	if got := TLocale("en", "json.global.key"); got != "from JSON" {
		t.Errorf("loaded JSON: %s", got)
	}
}

// ============================================================================
// Accept-Language parsing
// ============================================================================

func TestLocaleFromAcceptLanguage(t *testing.T) {
	supported := []string{"en", "ja", "de"}
	cases := []struct {
		header, want string
	}{
		{"ja", "ja"},
		{"ja-JP,ja;q=0.9,en;q=0.8", "ja"},
		{"de-DE,de;q=0.9", "de"},
		{"fr-FR,fr;q=0.9", "en"}, // unsupported, fallback to first
		{"", "en"},
		{"*", "en"},
	}
	for _, c := range cases {
		got := LocaleFromAcceptLanguage(c.header, supported)
		if got != c.want {
			t.Errorf("Accept-Language %q: got %s want %s", c.header, got, c.want)
		}
	}
}

// ============================================================================
// Thread safety
// ============================================================================

func TestBundleConcurrentLookup(t *testing.T) {
	b := NewBundle(map[string]map[string]string{
		"k": {"en": "v"},
	})
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			b.Translate("k", "en")
		}()
	}
	wg.Wait()
}

func TestGlobalConcurrentSetLocale(t *testing.T) {
	prev := GetLocale()
	defer SetLocale(prev)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if i%2 == 0 {
				SetLocale("en")
			} else {
				SetLocale("ja")
			}
			_ = T("compliance.signatureInvalid")
		}(i)
	}
	wg.Wait()
}

// ============================================================================
// Built-in messages (smoke test for shipped strings)
// ============================================================================

func TestBuiltinMessagesPresent(t *testing.T) {
	// Compliance keys
	keys := []string{
		"compliance.invalidProductID",
		"compliance.signatureInvalid",
		"compliance.expired",
	}
	for _, k := range keys {
		for _, locale := range []string{"en", "ja"} {
			got := TLocale(locale, k, "test-arg")
			if strings.HasPrefix(got, "missing.") || got == k {
				t.Errorf("key %q locale %q not translated: %s", k, locale, got)
			}
		}
	}
}

// ============================================================================
// Coverage uplift: uncovered branches in Translate, Locales, LocaleFromAcceptLanguage
// ============================================================================

// TestTranslatePrefixFallback covers the "ja-JP → ja" region-stripping path in
// Translate when the exact locale isn't registered but the language prefix is.
func TestTranslatePrefixFallback(t *testing.T) {
	b := NewBundle(nil)
	b.AddMessage("msg.hello", "ja", "こんにちは")
	// "ja-JP" is not registered but "ja" is → prefix fallback
	got := b.Translate("msg.hello", "ja-JP")
	if got != "こんにちは" {
		t.Errorf("prefix fallback: got %q, want こんにちは", got)
	}
}

// TestTranslateAnyLocaleFallback covers the "for _, t := range locales" loop
// in Translate when neither exact nor prefix match is found.
func TestTranslateAnyLocaleFallback(t *testing.T) {
	b := NewBundle(nil)
	b.AddMessage("msg.any", "fr", "Bonjour")
	// "de" is not registered and there's no "de-*" prefix → any-locale fallback
	got := b.Translate("msg.any", "de")
	if got != "Bonjour" {
		t.Errorf("any-locale fallback: got %q, want Bonjour", got)
	}
}

// TestTranslateEmptyTemplate covers `return key` when the matched template is "".
func TestTranslateEmptyTemplate(t *testing.T) {
	b := NewBundle(nil)
	b.AddMessage("msg.empty", "en", "") // empty template
	got := b.Translate("msg.empty", "en")
	if got != "msg.empty" {
		t.Errorf("empty template should return key, got %q", got)
	}
}

// TestLocalesUnknownKey covers `return nil` in Locales when the key is missing.
func TestLocalesUnknownKey(t *testing.T) {
	b := NewBundle(nil)
	if b.Locales("no.such.key") != nil {
		t.Error("Locales for unknown key should return nil")
	}
}

// TestLocaleFromAcceptLanguageEmptySupported covers `return "en"` when the
// supported list is empty.
func TestLocaleFromAcceptLanguageEmptySupported(t *testing.T) {
	got := LocaleFromAcceptLanguage("fr,en;q=0.9", nil)
	if got != "en" {
		t.Errorf("empty supported should return en, got %q", got)
	}
}
