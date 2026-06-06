package tlsharden

import (
	"net/http"
	"testing"
	"time"
)

func TestHardenedServerSetsTimeouts(t *testing.T) {
	srv := HardenedServer(":0", http.NewServeMux())
	if srv.ReadHeaderTimeout == 0 {
		t.Error("ReadHeaderTimeout must be set (slowloris defense)")
	}
	if srv.ReadTimeout == 0 || srv.WriteTimeout == 0 || srv.IdleTimeout == 0 {
		t.Errorf("timeouts must be set: read=%v write=%v idle=%v",
			srv.ReadTimeout, srv.WriteTimeout, srv.IdleTimeout)
	}
	if srv.MaxHeaderBytes == 0 {
		t.Error("MaxHeaderBytes must be bounded")
	}
	if srv.Addr != ":0" || srv.Handler == nil {
		t.Error("addr/handler must be wired")
	}
}

func TestHardenedServerWithStreamingWriteZero(t *testing.T) {
	// SSE/streaming servers disable WriteTimeout; the helper must honor that.
	tmo := DefaultTimeouts()
	tmo.Write = 0
	srv := HardenedServerWith(":0", http.NewServeMux(), tmo)
	if srv.WriteTimeout != 0 {
		t.Errorf("WriteTimeout should be 0 for streaming, got %v", srv.WriteTimeout)
	}
	if srv.ReadHeaderTimeout != 5*time.Second {
		t.Errorf("ReadHeaderTimeout: %v", srv.ReadHeaderTimeout)
	}
}
