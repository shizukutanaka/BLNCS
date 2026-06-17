package metrics

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"blrcs/telemetry"
)

func makeTelWithData(t *testing.T) *telemetry.Telemetry {
	t.Helper()
	tel := telemetry.New(telemetry.NopRecorder{})
	tel.Counter("dpp.issued").Add(42)
	tel.Counter("dpp.verify.errors").Add(3)
	tel.Histogram("compliance_IssuePassport_duration_ms").Observe(12.5)
	tel.Histogram("compliance_IssuePassport_duration_ms").Observe(35.0)
	tel.Histogram("compliance_IssuePassport_duration_ms").Observe(8.0)
	return tel
}

func TestExporterPrometheusFormat(t *testing.T) {
	tel := makeTelWithData(t)
	exp := NewExporter(tel, map[string]string{"instance": "test-1", "version": "1.0"})

	var buf strings.Builder
	exp.WriteMetrics(&buf)
	out := buf.String()

	// Counter lines
	if !strings.Contains(out, "dpp_issued_total") {
		t.Error("missing dpp_issued_total")
	}
	if !strings.Contains(out, "# TYPE dpp_issued_total counter") {
		t.Error("missing counter TYPE")
	}
	if !strings.Contains(out, " 42 ") {
		t.Error("missing counter value 42")
	}
	// Histogram summary lines
	if !strings.Contains(out, `quantile="0.5"`) {
		t.Error("missing p50 quantile")
	}
	if !strings.Contains(out, `quantile="0.99"`) {
		t.Error("missing p99 quantile")
	}
	if !strings.Contains(out, "_count") {
		t.Error("missing histogram _count")
	}
	if !strings.Contains(out, "_sum") {
		t.Error("missing histogram _sum")
	}
}

func TestExporterLabels(t *testing.T) {
	tel := telemetry.New(telemetry.NopRecorder{})
	tel.Counter("test.counter").Inc()
	exp := NewExporter(tel, map[string]string{"env": "prod", "region": "jp-east"})

	var buf strings.Builder
	exp.WriteMetrics(&buf)
	out := buf.String()
	// Labels should appear on counter line
	if !strings.Contains(out, `env="prod"`) {
		t.Errorf("missing env label: %s", out)
	}
	if !strings.Contains(out, `region="jp-east"`) {
		t.Errorf("missing region label: %s", out)
	}
}

func TestExporterNoLabels(t *testing.T) {
	tel := telemetry.New(telemetry.NopRecorder{})
	tel.Counter("c").Add(1)
	exp := NewExporter(tel, nil)
	var buf strings.Builder
	exp.WriteMetrics(&buf)
	out := buf.String()
	// Should still have valid output without labels
	if !strings.Contains(out, "c_total") {
		t.Errorf("missing counter: %s", out)
	}
	// Should not have empty {} label set
	if strings.Contains(out, "{}") {
		t.Errorf("should not have empty label braces: %s", out)
	}
}

func TestMetricNameSanitize(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"dpp.issued", "dpp_issued"},
		{"compliance.IssuePassport.duration_ms", "compliance_IssuePassport_duration_ms"},
		{"DPP:Issue", "DPP:Issue"}, // : is valid in Prometheus (recording rules)
		{"normal_name", "normal_name"},
		{"123start", "_23start"}, // leading digit
	}
	for _, c := range cases {
		if got := sanitize(c.in); got != c.want {
			t.Errorf("sanitize(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestLabelValueEscaping verifies that Prometheus label values escape the
// backslash, double-quote, and line-feed characters per the exposition format.
// Without escaping, a value with a '"' corrupts the line and a newline lets an
// attacker inject forged metric lines into the scrape.
func TestLabelValueEscaping(t *testing.T) {
	tel := telemetry.New(telemetry.NopRecorder{})
	tel.Counter("c").Inc()
	// A malicious/awkward label value with a quote, backslash, and newline that
	// would otherwise break the exposition format or inject a fake metric.
	exp := NewExporter(tel, map[string]string{
		"version": `1.0"} injected_total 999` + "\n" + `evil{x="`,
		"path":    `C:\temp`,
	})
	var buf strings.Builder
	exp.WriteMetrics(&buf)
	out := buf.String()

	// The raw quote/newline/backslash must not appear unescaped in the value.
	if strings.Contains(out, "injected_total 999\n") {
		t.Errorf("newline in label value was not escaped — metric injection possible:\n%s", out)
	}
	// The escaped forms must be present.
	if !strings.Contains(out, `\"`) {
		t.Errorf("double-quote not escaped as \\\":\n%s", out)
	}
	if !strings.Contains(out, `\n`) {
		t.Errorf("newline not escaped as \\n:\n%s", out)
	}
	if !strings.Contains(out, `C:\\temp`) {
		t.Errorf("backslash not escaped as \\\\:\n%s", out)
	}
}

// TestEscapeHelpAndLabelHelpers unit-tests the escapers directly, including the
// HELP rule (double-quote is NOT escaped in HELP, only backslash and newline).
func TestEscapeHelpAndLabelHelpers(t *testing.T) {
	if got := escapeLabelValue(`a"b\c` + "\n" + "d"); got != `a\"b\\c\nd` {
		t.Errorf("escapeLabelValue = %q", got)
	}
	if got := escapeLabelValue("plain"); got != "plain" {
		t.Errorf("escapeLabelValue should pass plain values through, got %q", got)
	}
	// HELP keeps '"' literal but escapes '\' and newline.
	if got := escapeHelp(`a"b\c` + "\n" + "d"); got != `a"b\\c\nd` {
		t.Errorf("escapeHelp = %q", got)
	}
}

func TestHTTPHandlerGET(t *testing.T) {
	tel := makeTelWithData(t)
	exp := NewExporter(tel, map[string]string{"v": "1"})

	ts := httptest.NewServer(exp)
	defer ts.Close()

	resp, err := http.Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status: %d", resp.StatusCode)
	}
	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "text/plain") {
		t.Errorf("content-type: %s", ct)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "dpp_issued_total") {
		t.Errorf("missing metric in HTTP response: %s", body)
	}
}

func TestHTTPHandlerMethodNotAllowed(t *testing.T) {
	tel := telemetry.New(telemetry.NopRecorder{})
	exp := NewExporter(tel, nil)
	ts := httptest.NewServer(exp)
	defer ts.Close()

	req, _ := http.NewRequest("POST", ts.URL, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 405 {
		t.Fatalf("want 405, got %d", resp.StatusCode)
	}
}

func TestDashboardHandler(t *testing.T) {
	tel := makeTelWithData(t)
	exp := NewExporter(tel, map[string]string{"instance": "test"})

	mux := http.NewServeMux()
	mux.Handle("/dashboard", exp.DashboardHandler())
	ts := httptest.NewServer(mux)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/dashboard")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status: %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	s := string(body)
	if !strings.Contains(s, "BLRCS Dashboard") {
		t.Error("missing dashboard header")
	}
	if !strings.Contains(s, "Counters") {
		t.Error("missing Counters section")
	}
	if !strings.Contains(s, "dpp.issued") {
		t.Errorf("missing counter name: %s", s)
	}
	if !strings.Contains(s, "42") {
		t.Errorf("missing counter value: %s", s)
	}
}

func TestEmptyTelemetryOutput(t *testing.T) {
	tel := telemetry.New(telemetry.NopRecorder{})
	exp := NewExporter(tel, nil)
	var buf strings.Builder
	exp.WriteMetrics(&buf)
	// No counters or histograms — empty output is valid
	out := buf.String()
	if strings.Contains(out, "NaN") {
		t.Errorf("NaN in empty output: %s", out)
	}
}
