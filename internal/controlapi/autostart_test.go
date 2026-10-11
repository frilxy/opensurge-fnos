package controlapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"open-mihomo-gateway/internal/config"
	"open-mihomo-gateway/internal/gateway"
	"open-mihomo-gateway/internal/runtime"
)

func TestShouldRestoreGateway(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		hasDesired bool
		desired    bool
		want       bool
	}{
		{name: "missing desired restores", hasDesired: false, want: true},
		{name: "desired running restores", hasDesired: true, desired: true, want: true},
		{name: "desired stopped skips", hasDesired: true, desired: false, want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := shouldRestoreGateway(tc.hasDesired, tc.desired); got != tc.want {
				t.Fatalf("shouldRestoreGateway(%v, %v)=%v, want %v", tc.hasDesired, tc.desired, got, tc.want)
			}
		})
	}
}

func TestStoreGatewayDesiredRoundTrip(t *testing.T) {
	t.Parallel()
	store := NewStore(t.TempDir())
	if err := store.Ensure(); err != nil {
		t.Fatal(err)
	}
	running, exists, err := store.GatewayDesired()
	if err != nil || exists || running {
		t.Fatalf("empty store running=%v exists=%v err=%v", running, exists, err)
	}
	if err := store.SaveGatewayDesired(true); err != nil {
		t.Fatal(err)
	}
	running, exists, err = store.GatewayDesired()
	if err != nil || !exists || !running {
		t.Fatalf("saved running=%v exists=%v err=%v", running, exists, err)
	}
	if err := store.SaveGatewayDesired(false); err != nil {
		t.Fatal(err)
	}
	running, exists, err = store.GatewayDesired()
	if err != nil || !exists || running {
		t.Fatalf("saved stopped running=%v exists=%v err=%v", running, exists, err)
	}
}

func TestGatewayStartPersistsDesiredRunning(t *testing.T) {
	server := newTestServer(t)
	if err := server.store.SaveRecovery(RecoveryState{Stage: RecoveryRouterDHCPDisabledConfirmed, Required: true}); err != nil {
		t.Fatal(err)
	}
	request := httptestNewStart(server)
	response := httptestRecord(server, request)
	if response.Code != http.StatusAccepted {
		t.Fatalf("start status=%d body=%s", response.Code, response.Body.String())
	}
	waitForStoredOperation(t, server, request.Header.Get("Idempotency-Key"), "succeeded")
	running, exists, err := server.store.GatewayDesired()
	if err != nil || !exists || !running {
		t.Fatalf("desired running=%v exists=%v err=%v", running, exists, err)
	}
}

func TestGatewayStopPersistsDesiredStopped(t *testing.T) {
	server := newTestServer(t)
	request := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:61767/api/v1/gateway/stop", nil)
	request.Host = "127.0.0.1:61767"
	request.Header.Set("Authorization", "Bearer "+server.token)
	request.Header.Set("Idempotency-Key", "persist-stop")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusAccepted {
		t.Fatalf("stop status=%d body=%s", response.Code, response.Body.String())
	}
	waitForStoredOperation(t, server, "persist-stop", "succeeded")
	running, exists, err := server.store.GatewayDesired()
	if err != nil || !exists || running {
		t.Fatalf("desired running=%v exists=%v err=%v", running, exists, err)
	}
}

func TestRestoreGatewayIfDesiredStartsOnFirstRun(t *testing.T) {
	server := newSidecarTestServer(t)
	runner := &sequenceRunner{}
	server.runner = runner
	server.restoreGatewayIfDesired()
	if got := runner.snapshot(); !slices.Equal(got, []string{"start"}) {
		t.Fatalf("actions=%q, want [start]", got)
	}
	running, exists, err := server.store.GatewayDesired()
	if err != nil || !exists || !running {
		t.Fatalf("desired running=%v exists=%v err=%v", running, exists, err)
	}
}

func TestRestoreGatewayIfDesiredStopThenStartAfterInterrupt(t *testing.T) {
	server := newSidecarTestServer(t)
	cfg, err := config.LoadRuntime(server.configPath)
	if err != nil {
		t.Fatal(err)
	}
	paths := runtime.NewPaths(cfg)
	if err := runtime.Ensure(paths); err != nil {
		t.Fatal(err)
	}
	if err := runtime.SaveState(paths.StateFile, runtime.State{PIDMihomo: 1, BootSessionID: "previous-boot", StartedAt: time.Now().Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}
	server.gatewayStatus = func(context.Context, config.Config) (gateway.Status, error) {
		return gateway.Status{Gateway: "degraded", RuntimeState: "interrupted"}, nil
	}
	runner := &sequenceRunner{cleanup: func() {
		if err := os.Remove(paths.StateFile); err != nil && !os.IsNotExist(err) {
			t.Errorf("cleanup state: %v", err)
		}
	}}
	server.runner = runner
	if err := server.store.SaveGatewayDesired(true); err != nil {
		t.Fatal(err)
	}
	server.restoreGatewayIfDesired()
	if got := runner.snapshot(); !slices.Equal(got, []string{"stop", "start"}) {
		t.Fatalf("actions=%q, want [stop start]", got)
	}
}

func TestRestoreGatewayIfDesiredRecoversDegradedRuntime(t *testing.T) {
	server := newSidecarTestServer(t)
	cfg, err := config.LoadRuntime(server.configPath)
	if err != nil {
		t.Fatal(err)
	}
	paths := runtime.NewPaths(cfg)
	if err := runtime.Ensure(paths); err != nil {
		t.Fatal(err)
	}
	if err := runtime.SaveState(paths.StateFile, runtime.State{PIDMihomo: 1, BootSessionID: "current", StartedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	server.gatewayStatus = func(context.Context, config.Config) (gateway.Status, error) {
		return gateway.Status{Gateway: "degraded", RuntimeState: "active"}, nil
	}
	runner := &sequenceRunner{cleanup: func() {
		if err := os.Remove(paths.StateFile); err != nil && !os.IsNotExist(err) {
			t.Errorf("cleanup state: %v", err)
		}
	}}
	server.runner = runner
	server.restoreGatewayIfDesired()
	if got := runner.snapshot(); !slices.Equal(got, []string{"stop", "start"}) {
		t.Fatalf("actions=%q, want [stop start]", got)
	}
}

func TestRestoreGatewayIfDesiredSkipsWhenUserStopped(t *testing.T) {
	server := newSidecarTestServer(t)
	if err := server.store.SaveGatewayDesired(false); err != nil {
		t.Fatal(err)
	}
	runner := &sequenceRunner{}
	server.runner = runner
	server.restoreGatewayIfDesired()
	if got := runner.snapshot(); len(got) != 0 {
		t.Fatalf("actions=%q, want none", got)
	}
}

func TestRestoreGatewayIfDesiredNoopWhenDisabled(t *testing.T) {
	server := newSidecarTestServer(t)
	server.autostartGateway = false
	runner := &sequenceRunner{}
	server.runner = runner
	server.restoreGatewayIfDesired()
	if got := runner.snapshot(); len(got) != 0 {
		t.Fatalf("actions=%q, want none", got)
	}
}

func TestRestoreGatewayIfDesiredNoopWhenAlreadyRunning(t *testing.T) {
	server := newSidecarTestServer(t)
	server.gatewayStatus = func(context.Context, config.Config) (gateway.Status, error) {
		return gateway.Status{Gateway: "running", RuntimeState: "active"}, nil
	}
	runner := &sequenceRunner{}
	server.runner = runner
	server.restoreGatewayIfDesired()
	if got := runner.snapshot(); len(got) != 0 {
		t.Fatalf("actions=%q, want none", got)
	}
	running, exists, err := server.store.GatewayDesired()
	if err != nil || !exists || !running {
		t.Fatalf("desired running=%v exists=%v err=%v", running, exists, err)
	}
}

func TestRestoreGatewayIfDesiredSkipsUnconfirmedDHCPTakeover(t *testing.T) {
	server := newTestServer(t)
	server.autostartGateway = true
	runner := &sequenceRunner{}
	server.runner = runner
	server.restoreGatewayIfDesired()
	if got := runner.snapshot(); len(got) != 0 {
		t.Fatalf("actions=%q, want none", got)
	}
}

func TestRestoreGatewayIfDesiredCleansInterruptWithoutDHCPStart(t *testing.T) {
	server := newTestServer(t)
	server.autostartGateway = true
	cfg, err := config.LoadRuntime(server.configPath)
	if err != nil {
		t.Fatal(err)
	}
	paths := runtime.NewPaths(cfg)
	if err := runtime.Ensure(paths); err != nil {
		t.Fatal(err)
	}
	if err := runtime.SaveState(paths.StateFile, runtime.State{PIDMihomo: 1, BootSessionID: "previous-boot"}); err != nil {
		t.Fatal(err)
	}
	server.gatewayStatus = func(context.Context, config.Config) (gateway.Status, error) {
		return gateway.Status{Gateway: "degraded", RuntimeState: "interrupted"}, nil
	}
	runner := &sequenceRunner{cleanup: func() {
		_ = os.Remove(paths.StateFile)
	}}
	server.runner = runner
	server.restoreGatewayIfDesired()
	if got := runner.snapshot(); !slices.Equal(got, []string{"stop"}) {
		t.Fatalf("actions=%q, want [stop]", got)
	}
}

func newSidecarTestServer(t *testing.T) *Server {
	t.Helper()
	server := newTestServer(t)
	data, err := os.ReadFile(server.configPath)
	if err != nil {
		t.Fatal(err)
	}
	updated := strings.Replace(string(data), `mode: "same_wifi_dhcp"`, `mode: "same_lan"`, 1)
	updated = strings.Replace(updated, `enabled: true`, `enabled: false`, 1)
	if err := os.WriteFile(server.configPath, []byte(updated), 0o600); err != nil {
		t.Fatal(err)
	}
	server.autostartGateway = true
	return server
}

func httptestNewStart(server *Server) *http.Request {
	request := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:61767/api/v1/gateway/start", nil)
	request.Host = "127.0.0.1:61767"
	request.Header.Set("Authorization", "Bearer "+server.token)
	request.Header.Set("Idempotency-Key", "persist-start")
	return request
}

func httptestRecord(server *Server, request *http.Request) *httptest.ResponseRecorder {
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	return response
}

type sequenceRunner struct {
	mu      sync.Mutex
	actions []string
	cleanup func()
}

func (r *sequenceRunner) Run(_ context.Context, action, _ string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.actions = append(r.actions, action)
	if action == "stop" && r.cleanup != nil {
		r.cleanup()
	}
	return nil
}

func (r *sequenceRunner) StartPolicyWorkspace(_ context.Context, _ string, _ PolicyWorkspaceInput) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.actions = append(r.actions, "start")
	return nil
}

func (r *sequenceRunner) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.actions...)
}
