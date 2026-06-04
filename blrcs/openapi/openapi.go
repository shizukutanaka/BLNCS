// Package openapi — OpenAPI 3.0 仕様の宣言的構築 + 自動公開
//
// 設計: 宣言的に endpoint を登録、最終的に OpenAPI 3.0 JSON を生成。
//   - Swagger UI / Postman / 自動 client SDK 生成すべて互換
//   - apispec パッケージの拡張 — 既存 endpoint を OpenAPI に投影
//   - /openapi.json で公開、CI で client コード自動生成可能
//
// 解決する短所:
//   - "OpenAPI 仕様書化未済 — apispec パッケージあるが OpenAPI 出力なし"
//
// 利用例:
//
//	spec := openapi.New("BLRCS API", "1.0.0", "BLRCS Compliance API")
//	spec.AddPath("/openid4vp/authorize", openapi.Endpoint{
//	    Method: "POST",
//	    Summary: "Create OpenID4VP authorization request",
//	    RequestBody: &openapi.JSONSchema{...},
//	    Responses: map[int]openapi.Response{
//	        200: {Description: "OK", Schema: ...},
//	    },
//	})
//	mux.Handle("/openapi.json", spec.JSONHandler())
package openapi

import (
	"encoding/json"
	"net/http"
	"sort"
	"sync"
)

// ============================================================================
// Top-level spec
// ============================================================================

// Spec — OpenAPI 3.0 ドキュメント
type Spec struct {
	OpenAPI    string                           `json:"openapi"` // "3.0.3"
	Info       Info                             `json:"info"`
	Servers    []Server                         `json:"servers,omitempty"`
	Paths      map[string]map[string]*Operation `json:"paths"`
	Components Components                       `json:"components"`

	mu sync.RWMutex
}

// Info — メタデータ
type Info struct {
	Title       string   `json:"title"`
	Version     string   `json:"version"`
	Description string   `json:"description,omitempty"`
	Contact     *Contact `json:"contact,omitempty"`
	License     *License `json:"license,omitempty"`
}

type Contact struct {
	Name  string `json:"name,omitempty"`
	URL   string `json:"url,omitempty"`
	Email string `json:"email,omitempty"`
}

type License struct {
	Name string `json:"name"`
	URL  string `json:"url,omitempty"`
}

// Server — base URL
type Server struct {
	URL         string `json:"url"`
	Description string `json:"description,omitempty"`
}

// Components — schemas / securitySchemes 共通
type Components struct {
	Schemas         map[string]*Schema         `json:"schemas,omitempty"`
	SecuritySchemes map[string]*SecurityScheme `json:"securitySchemes,omitempty"`
}

// SecurityScheme — auth definition
type SecurityScheme struct {
	Type         string `json:"type"`             // "http" | "apiKey" | "oauth2"
	Scheme       string `json:"scheme,omitempty"` // "bearer"
	BearerFormat string `json:"bearerFormat,omitempty"`
}

// ============================================================================
// Operation = method × path
// ============================================================================

// Operation — 1 endpoint
type Operation struct {
	Summary     string                `json:"summary,omitempty"`
	Description string                `json:"description,omitempty"`
	Tags        []string              `json:"tags,omitempty"`
	OperationID string                `json:"operationId,omitempty"`
	Parameters  []Parameter           `json:"parameters,omitempty"`
	RequestBody *RequestBody          `json:"requestBody,omitempty"`
	Responses   map[string]*Response  `json:"responses"`
	Security    []map[string][]string `json:"security,omitempty"`
	Deprecated  bool                  `json:"deprecated,omitempty"`
}

// Parameter — query/path/header/cookie
type Parameter struct {
	Name        string  `json:"name"`
	In          string  `json:"in"` // "query" | "path" | "header" | "cookie"
	Description string  `json:"description,omitempty"`
	Required    bool    `json:"required,omitempty"`
	Schema      *Schema `json:"schema,omitempty"`
}

// RequestBody
type RequestBody struct {
	Description string               `json:"description,omitempty"`
	Required    bool                 `json:"required,omitempty"`
	Content     map[string]MediaType `json:"content"`
}

// Response
type Response struct {
	Description string               `json:"description"`
	Content     map[string]MediaType `json:"content,omitempty"`
	Headers     map[string]Header    `json:"headers,omitempty"`
}

// MediaType
type MediaType struct {
	Schema  *Schema     `json:"schema,omitempty"`
	Example interface{} `json:"example,omitempty"`
}

// Header
type Header struct {
	Description string  `json:"description,omitempty"`
	Schema      *Schema `json:"schema,omitempty"`
}

// ============================================================================
// JSON Schema (subset)
// ============================================================================

// Schema — JSON Schema (OpenAPI 3.0 subset)
type Schema struct {
	Type        string             `json:"type,omitempty"` // "object" | "string" | "integer" | "boolean" | "array"
	Format      string             `json:"format,omitempty"`
	Description string             `json:"description,omitempty"`
	Properties  map[string]*Schema `json:"properties,omitempty"`
	Required    []string           `json:"required,omitempty"`
	Items       *Schema            `json:"items,omitempty"`
	Enum        []interface{}      `json:"enum,omitempty"`
	Example     interface{}        `json:"example,omitempty"`
	Ref         string             `json:"$ref,omitempty"`
	MinLength   int                `json:"minLength,omitempty"`
	MaxLength   int                `json:"maxLength,omitempty"`
	Minimum     *float64           `json:"minimum,omitempty"`
	Maximum     *float64           `json:"maximum,omitempty"`
}

// ============================================================================
// Builder API
// ============================================================================

// New — 空 OpenAPI 仕様
func New(title, version, description string) *Spec {
	return &Spec{
		OpenAPI: "3.0.3",
		Info: Info{
			Title:       title,
			Version:     version,
			Description: description,
		},
		Paths: make(map[string]map[string]*Operation),
		Components: Components{
			Schemas:         make(map[string]*Schema),
			SecuritySchemes: make(map[string]*SecurityScheme),
		},
	}
}

// SetServer — base URL の登録
func (s *Spec) SetServer(url, description string) *Spec {
	s.mu.Lock()
	s.Servers = append(s.Servers, Server{URL: url, Description: description})
	s.mu.Unlock()
	return s
}

// SetContact — 連絡先 (Apple App Store privacy contact 同水準)
func (s *Spec) SetContact(name, url, email string) *Spec {
	s.mu.Lock()
	s.Info.Contact = &Contact{Name: name, URL: url, Email: email}
	s.mu.Unlock()
	return s
}

// SetLicense — ライセンス
func (s *Spec) SetLicense(name, url string) *Spec {
	s.mu.Lock()
	s.Info.License = &License{Name: name, URL: url}
	s.mu.Unlock()
	return s
}

// AddBearerAuth — Bearer auth scheme 登録
func (s *Spec) AddBearerAuth(name string) *Spec {
	s.mu.Lock()
	s.Components.SecuritySchemes[name] = &SecurityScheme{
		Type:         "http",
		Scheme:       "bearer",
		BearerFormat: "JWT",
	}
	s.mu.Unlock()
	return s
}

// AddSchema — 再利用可能 schema 登録 (Components/schemas/<name>)
func (s *Spec) AddSchema(name string, schema *Schema) *Spec {
	s.mu.Lock()
	s.Components.Schemas[name] = schema
	s.mu.Unlock()
	return s
}

// AddPath — endpoint の登録
//
// Apple URLComponents の addQueryItem 思想 — 1 endpoint 1コール、宣言的
func (s *Spec) AddPath(path, method string, op *Operation) *Spec {
	s.mu.Lock()
	if s.Paths[path] == nil {
		s.Paths[path] = make(map[string]*Operation)
	}
	// methodは小文字 (OpenAPI 仕様)
	s.Paths[path][toLower(method)] = op
	s.mu.Unlock()
	return s
}

// ============================================================================
// JSON Output
// ============================================================================

// JSON — OpenAPI 3.0 ドキュメント全体を JSON 化
func (s *Spec) JSON() ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return json.MarshalIndent(s, "", "  ")
}

// JSONHandler — GET /openapi.json HTTP handler
func (s *Spec) JSONHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		body, err := s.JSON()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "max-age=300") // 5min cache
		_, _ = w.Write(body)
	})
}

// ============================================================================
// Pre-built BLRCS spec
// ============================================================================

// BLRCSDefault — BLRCS 標準 endpoint を全て収録した OpenAPI spec
func BLRCSDefault(version string) *Spec {
	s := New("BLRCS API", version, "Blockchain Logistics & Compliance Service - EU DPP and Battery Passport platform")
	s.SetContact("BLRCS", "https://github.com/shizukutanaka/blrcs", "")
	s.SetLicense("MIT", "https://opensource.org/licenses/MIT")
	s.AddBearerAuth("bearerAuth")

	// Common schemas
	s.AddSchema("Error", &Schema{
		Type: "object",
		Properties: map[string]*Schema{
			"error":  {Type: "string"},
			"status": {Type: "integer"},
		},
		Required: []string{"error"},
	})
	s.AddSchema("PassportClaim", &Schema{
		Type:        "object",
		Description: "EU ESPR Digital Product Passport claim",
		Properties: map[string]*Schema{
			"productId":     {Type: "string", Description: "GS1 GTIN-14"},
			"category":      {Type: "string"},
			"originCountry": {Type: "string", Description: "ISO 3166-1 alpha-2"},
			"carbonKgCO2e":  {Type: "number", Description: "kg CO2 equivalent"},
		},
		Required: []string{"productId"},
	})
	s.AddSchema("PresentationDefinition", &Schema{
		Type: "object",
		Properties: map[string]*Schema{
			"id":             {Type: "string"},
			"purpose":        {Type: "string"},
			"requiredClaims": {Type: "array", Items: &Schema{Type: "string"}},
			"acceptableDIDs": {Type: "array", Items: &Schema{Type: "string"}},
		},
		Required: []string{"id", "requiredClaims"},
	})

	// Endpoints
	s.AddPath("/openid4vp/authorize", "POST", &Operation{
		Tags:        []string{"OpenID4VP"},
		Summary:     "Create OpenID4VP authorization request",
		Description: "Generates a fresh nonce + state, returns wallet-bound URL",
		OperationID: "createOpenID4VPRequest",
		RequestBody: &RequestBody{
			Required: true,
			Content: map[string]MediaType{
				"application/json": {
					Schema: &Schema{Ref: "#/components/schemas/PresentationDefinition"},
				},
			},
		},
		Responses: map[string]*Response{
			"200": {
				Description: "Created",
				Content: map[string]MediaType{
					"application/json": {
						Schema: &Schema{
							Type: "object",
							Properties: map[string]*Schema{
								"requestURL": {Type: "string"},
								"state":      {Type: "string"},
							},
						},
					},
				},
			},
			"400": errorResponse(),
		},
	})

	s.AddPath("/openid4vp/callback", "POST", &Operation{
		Tags:        []string{"OpenID4VP"},
		Summary:     "Process Wallet vp_token response",
		OperationID: "processOpenID4VPResponse",
		RequestBody: &RequestBody{
			Required: true,
			Content: map[string]MediaType{
				"application/x-www-form-urlencoded": {
					Schema: &Schema{
						Type: "object",
						Properties: map[string]*Schema{
							"vp_token": {Type: "string"},
							"state":    {Type: "string"},
						},
						Required: []string{"vp_token", "state"},
					},
				},
			},
		},
		Responses: map[string]*Response{
			"200": {Description: "Verified"},
			"400": errorResponse(),
		},
	})

	s.AddPath("/.well-known/openid-credential-issuer", "GET", &Operation{
		Tags:        []string{"OpenID4VCI"},
		Summary:     "OpenID4VCI metadata",
		OperationID: "getIssuerMetadata",
		Responses: map[string]*Response{
			"200": {Description: "Metadata"},
		},
	})

	s.AddPath("/token", "POST", &Operation{
		Tags:        []string{"OpenID4VCI"},
		Summary:     "Token endpoint (pre-authorized code → access_token)",
		OperationID: "exchangeToken",
		Responses: map[string]*Response{
			"200": {Description: "Token granted"},
			"400": errorResponse(),
		},
	})

	s.AddPath("/credential", "POST", &Operation{
		Tags:        []string{"OpenID4VCI"},
		Summary:     "Credential endpoint",
		OperationID: "issueCredential",
		Security:    []map[string][]string{{"bearerAuth": {}}},
		Responses: map[string]*Response{
			"200": {Description: "SD-JWT credential"},
			"401": errorResponse(),
		},
	})

	s.AddPath("/healthz", "GET", &Operation{
		Tags:        []string{"Operations"},
		Summary:     "Liveness probe",
		OperationID: "liveness",
		Responses: map[string]*Response{
			"200": {Description: "Alive"},
			"503": {Description: "Not alive"},
		},
	})

	s.AddPath("/readyz", "GET", &Operation{
		Tags:        []string{"Operations"},
		Summary:     "Readiness probe",
		OperationID: "readiness",
		Responses: map[string]*Response{
			"200": {Description: "Ready"},
			"503": {Description: "Not ready"},
		},
	})

	s.AddPath("/metrics", "GET", &Operation{
		Tags:        []string{"Operations"},
		Summary:     "Prometheus metrics",
		OperationID: "prometheusMetrics",
		Responses: map[string]*Response{
			"200": {
				Description: "Prometheus exposition format",
				Content: map[string]MediaType{
					"text/plain": {Schema: &Schema{Type: "string"}},
				},
			},
		},
	})

	s.AddPath("/.well-known/blrcs-capabilities.json", "GET", &Operation{
		Tags:        []string{"Discovery"},
		Summary:     "Capability discovery",
		OperationID: "getCapabilities",
		Responses: map[string]*Response{
			"200": {Description: "Capability manifest"},
		},
	})

	s.AddPath("/.well-known/privacy.json", "GET", &Operation{
		Tags:        []string{"Discovery"},
		Summary:     "Privacy manifest (GDPR Art.30)",
		OperationID: "getPrivacyManifest",
		Responses: map[string]*Response{
			"200": {Description: "Privacy manifest"},
		},
	})

	return s
}

func errorResponse() *Response {
	return &Response{
		Description: "Error",
		Content: map[string]MediaType{
			"application/json": {Schema: &Schema{Ref: "#/components/schemas/Error"}},
		},
	}
}

// ============================================================================
// helpers
// ============================================================================

func toLower(s string) string {
	out := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		out[i] = c
	}
	return string(out)
}

// SortedPaths — テスト用 sorted path list
func (s *Spec) SortedPaths() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	paths := make([]string, 0, len(s.Paths))
	for p := range s.Paths {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	return paths
}
