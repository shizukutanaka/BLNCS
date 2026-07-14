package openid4vci

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// ============================================================================
// Axis 127: Notification Endpoint (OpenID4VCI 1.0 §10)
// ============================================================================

// issueOne is a small helper: creates an offer for the standard test config,
// exchanges it, and issues a credential without proof, returning the response.
func issueOne(t *testing.T) (*Issuer, *CredentialResponse) {
	t.Helper()
	iss, _ := setupIssuer(t)
	_, code, err := iss.CreateOffer(
		"eu-battery-passport-v1", "bat-notif",
		map[string]any{"carbonKgCO2ePerKWh": 40.0, "recycledCoPct": 12.0}, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	tr, err := iss.ExchangeCode(code)
	if err != nil {
		t.Fatal(err)
	}
	cr, err := iss.IssueCredentialWithProof(tr.AccessToken, CredentialRequest{})
	if err != nil {
		t.Fatal(err)
	}
	return iss, cr
}

func TestIssueCredentialReturnsNotificationID(t *testing.T) {
	_, cr := issueOne(t)
	if cr.NotificationID == "" {
		t.Fatal("CredentialResponse.NotificationID must not be empty")
	}
}

func TestHandleNotificationHappyPath(t *testing.T) {
	iss, _ := setupIssuer(t)
	_, code, err := iss.CreateOffer("eu-battery-passport-v1", "bat-notif-2",
		map[string]any{"carbonKgCO2ePerKWh": 1.0, "recycledCoPct": 1.0}, nil)
	if err != nil {
		t.Fatal(err)
	}
	tr, err := iss.ExchangeCode(code)
	if err != nil {
		t.Fatal(err)
	}
	cr, err := iss.IssueCredentialWithProof(tr.AccessToken, CredentialRequest{})
	if err != nil {
		t.Fatal(err)
	}

	var gotSubject, gotConfigID, gotEvent, gotDesc string
	iss.OnNotification = func(subject, configID, event, eventDescription string) {
		gotSubject, gotConfigID, gotEvent, gotDesc = subject, configID, event, eventDescription
	}

	err = iss.HandleNotification(tr.AccessToken, NotificationRequest{
		NotificationID:   cr.NotificationID,
		Event:            NotificationEventAccepted,
		EventDescription: "stored in wallet",
	})
	if err != nil {
		t.Fatalf("HandleNotification: %v", err)
	}
	if gotSubject != "bat-notif-2" {
		t.Errorf("subject: got %q", gotSubject)
	}
	if gotConfigID != "eu-battery-passport-v1" {
		t.Errorf("configID: got %q", gotConfigID)
	}
	if gotEvent != NotificationEventAccepted {
		t.Errorf("event: got %q", gotEvent)
	}
	if gotDesc != "stored in wallet" {
		t.Errorf("eventDescription: got %q", gotDesc)
	}
}

func TestHandleNotificationSingleUse(t *testing.T) {
	iss, _ := setupIssuer(t)
	_, code, _ := iss.CreateOffer("eu-battery-passport-v1", "bat-single",
		map[string]any{"carbonKgCO2ePerKWh": 1.0, "recycledCoPct": 1.0}, nil)
	tr, err := iss.ExchangeCode(code)
	if err != nil {
		t.Fatal(err)
	}
	cr, err := iss.IssueCredentialWithProof(tr.AccessToken, CredentialRequest{})
	if err != nil {
		t.Fatal(err)
	}

	if err := iss.HandleNotification(tr.AccessToken, NotificationRequest{
		NotificationID: cr.NotificationID, Event: NotificationEventAccepted,
	}); err != nil {
		t.Fatalf("first notification should succeed: %v", err)
	}
	err = iss.HandleNotification(tr.AccessToken, NotificationRequest{
		NotificationID: cr.NotificationID, Event: NotificationEventAccepted,
	})
	if err != ErrUnknownNotification {
		t.Fatalf("replayed notification_id: want ErrUnknownNotification, got %v", err)
	}
}

func TestHandleNotificationWrongAccessToken(t *testing.T) {
	iss, cr := issueOne(t)
	err := iss.HandleNotification("wrong-token", NotificationRequest{
		NotificationID: cr.NotificationID, Event: NotificationEventAccepted,
	})
	if err != ErrUnknownNotification {
		t.Fatalf("wrong access_token: want ErrUnknownNotification, got %v", err)
	}
}

func TestHandleNotificationUnknownID(t *testing.T) {
	iss, _ := setupIssuer(t)
	err := iss.HandleNotification("any-token", NotificationRequest{
		NotificationID: "does-not-exist", Event: NotificationEventAccepted,
	})
	if err != ErrUnknownNotification {
		t.Fatalf("unknown notification_id: want ErrUnknownNotification, got %v", err)
	}
}

func TestHandleNotificationInvalidEvent(t *testing.T) {
	iss, cr := issueOne(t)
	err := iss.HandleNotification("irrelevant", NotificationRequest{
		NotificationID: cr.NotificationID, Event: "not_a_real_event",
	})
	if err != ErrInvalidNotificationEvent {
		t.Fatalf("bad event: want ErrInvalidNotificationEvent, got %v", err)
	}
}

func TestHandleNotificationFailureAndDeletedEvents(t *testing.T) {
	iss, _ := setupIssuer(t)
	for _, event := range []string{NotificationEventFailure, NotificationEventDeleted} {
		_, code, _ := iss.CreateOffer("eu-battery-passport-v1", "bat-"+event,
			map[string]any{"carbonKgCO2ePerKWh": 1.0, "recycledCoPct": 1.0}, nil)
		tr, err := iss.ExchangeCode(code)
		if err != nil {
			t.Fatal(err)
		}
		cr, err := iss.IssueCredentialWithProof(tr.AccessToken, CredentialRequest{})
		if err != nil {
			t.Fatal(err)
		}
		if err := iss.HandleNotification(tr.AccessToken, NotificationRequest{
			NotificationID: cr.NotificationID, Event: event,
		}); err != nil {
			t.Errorf("event %s should be accepted: %v", event, err)
		}
	}
}

func TestMetadataIncludesNotificationEndpoint(t *testing.T) {
	iss, _ := setupIssuer(t)
	md := iss.Metadata()
	want := iss.URL + "/notification"
	if got := md["notification_endpoint"]; got != want {
		t.Errorf("notification_endpoint: got %v want %s", got, want)
	}
}

// ============================================================================
// HTTP layer
// ============================================================================

func TestNotificationEndpointHTTP(t *testing.T) {
	iss, _ := setupIssuer(t)
	ts := httptest.NewServer(iss.Handler())
	defer ts.Close()
	iss.URL = ts.URL

	_, code, err := iss.CreateOffer("eu-battery-passport-v1", "bat-http",
		map[string]any{"carbonKgCO2ePerKWh": 1.0, "recycledCoPct": 1.0}, nil)
	if err != nil {
		t.Fatal(err)
	}
	tr, err := iss.ExchangeCode(code)
	if err != nil {
		t.Fatal(err)
	}
	cr, err := iss.IssueCredentialWithProof(tr.AccessToken, CredentialRequest{})
	if err != nil {
		t.Fatal(err)
	}

	body, _ := json.Marshal(NotificationRequest{NotificationID: cr.NotificationID, Event: NotificationEventAccepted})
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/notification", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tr.AccessToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status: got %d want 204", resp.StatusCode)
	}

	// Replay: same notification_id again must be rejected.
	req2, _ := http.NewRequest(http.MethodPost, ts.URL+"/notification", bytes.NewReader(body))
	req2.Header.Set("Authorization", "Bearer "+tr.AccessToken)
	req2.Header.Set("Content-Type", "application/json")
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusBadRequest {
		t.Fatalf("replay status: got %d want 400", resp2.StatusCode)
	}
	var errBody map[string]string
	if err := json.NewDecoder(resp2.Body).Decode(&errBody); err != nil {
		t.Fatal(err)
	}
	if errBody["error"] != "invalid_notification_id" {
		t.Errorf("error: got %q", errBody["error"])
	}
}

func TestNotificationEndpointHTTPNoBearer(t *testing.T) {
	iss, _ := setupIssuer(t)
	ts := httptest.NewServer(iss.Handler())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/notification", "application/json", bytes.NewReader([]byte(`{}`)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status: got %d want 401", resp.StatusCode)
	}
}

func TestNotificationEndpointHTTPBadMethod(t *testing.T) {
	iss, _ := setupIssuer(t)
	ts := httptest.NewServer(iss.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/notification")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status: got %d want 405", resp.StatusCode)
	}
}

func TestNotificationEndpointHTTPMalformedBody(t *testing.T) {
	iss, _ := setupIssuer(t)
	ts := httptest.NewServer(iss.Handler())
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/notification", bytes.NewReader([]byte("not json")))
	req.Header.Set("Authorization", "Bearer sometoken")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status: got %d want 400", resp.StatusCode)
	}
	var errBody map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&errBody); err != nil {
		t.Fatal(err)
	}
	if errBody["error"] != "invalid_notification_request" {
		t.Errorf("error: got %q", errBody["error"])
	}
}

func TestNotificationEndpointHTTPInvalidEvent(t *testing.T) {
	iss, _ := setupIssuer(t)
	ts := httptest.NewServer(iss.Handler())
	defer ts.Close()

	body, _ := json.Marshal(NotificationRequest{NotificationID: "x", Event: "bogus"})
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/notification", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer sometoken")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status: got %d want 400", resp.StatusCode)
	}
	var errBody map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&errBody); err != nil {
		t.Fatal(err)
	}
	if errBody["error"] != "invalid_notification_request" {
		t.Errorf("error: got %q", errBody["error"])
	}
}
