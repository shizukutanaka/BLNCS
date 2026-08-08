package bundle

import (
	"context"
	"net"
	"net/http"
	"testing"
)

// failOnDial installs trip-wires that turn any outbound network attempt during
// a test into a test failure, and returns a restore func.
//
// This enforces the package's central claim: a bundle verifies with no network
// whatsoever. A comment asserting "no network calls" rots silently; this fails
// loudly the moment a future change introduces a fetch on the verify path.
//
// Two wires: http.DefaultTransport (anything using the stdlib HTTP client, e.g.
// a didresolver default fetcher) and net.DefaultResolver's Dial (raw DNS/dial).
func failOnDial(t *testing.T) func() {
	t.Helper()
	origTransport := http.DefaultTransport
	origResolver := net.DefaultResolver

	http.DefaultTransport = roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		t.Errorf("offline invariant violated: HTTP request to %s", r.URL)
		return nil, errNoNetwork
	})
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			t.Errorf("offline invariant violated: dial %s %s", network, address)
			return nil, errNoNetwork
		},
	}
	return func() {
		http.DefaultTransport = origTransport
		net.DefaultResolver = origResolver
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

var errNoNetwork = &noNetworkError{}

type noNetworkError struct{}

func (*noNetworkError) Error() string   { return "bundle test: network access is forbidden here" }
func (*noNetworkError) Timeout() bool   { return false }
func (*noNetworkError) Temporary() bool { return false }
