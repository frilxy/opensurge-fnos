package controlapi

import (
	"context"
	"encoding/binary"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"open-mihomo-gateway/internal/config"
	"open-mihomo-gateway/internal/gateway"
)

// dnsRecoveryController watches the LAN-facing DNS listener itself, not just
// the process that serves it. dnsmasq is single-threaded: it can stay alive
// (and keep its PID) while its sockets back up, in which case every downstream
// lookup times out but every process-level health check still reports "ok".
//
// Observed failure signature on fnOS: 192.168.10.229:53 Recv-Q grows without
// bound, the TCP listen backlog fills, a forwarding connection to the mihomo
// resolver stays in CLOSE-WAIT, and the dnsmasq CPU time stops advancing.
// Restarting mihomo does not help because mihomo is healthy; the gateway has to
// be reloaded so dnsmasq is replaced.
const (
	dnsRecoveryIdle       = "idle"
	dnsRecoveryObserving  = "observing"
	dnsRecoveryRecovering = "recovering"
	dnsRecoveryFailed     = "failed"

	dnsFailureProbeTimeout = "probe_timeout"

	autoDNSRecoveryInterval  = 10 * time.Second
	dnsProbeTimeout          = 3 * time.Second
	dnsProbeFailureThreshold = 3
	dnsHealthyConfirmations  = 2

	dnsProbeName = "example.com"
)

type dnsRecoveryController struct {
	mu              sync.Mutex
	state           string
	reason          string
	error           string
	failures        int
	healthyCount    int
	attempted       bool
	operationActive bool
}

func newDNSRecoveryController() *dnsRecoveryController {
	return &dnsRecoveryController{state: dnsRecoveryIdle}
}

func (c *dnsRecoveryController) observeHealthy() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.operationActive {
		return
	}
	if c.attempted {
		c.healthyCount++
		c.state = dnsRecoveryRecovering
		c.error = ""
		if c.healthyCount < dnsHealthyConfirmations {
			return
		}
	}
	c.state = dnsRecoveryIdle
	c.reason = ""
	c.error = ""
	c.failures = 0
	c.healthyCount = 0
	c.attempted = false
}

func (c *dnsRecoveryController) observeUnknown() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.operationActive {
		return
	}
	// A sample taken while no lifecycle operation is active still proves
	// nothing about DNS health; restart the consecutive counters.
	c.healthyCount = 0
	c.failures = 0
}

func (c *dnsRecoveryController) observeFailure(reason string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.operationActive {
		return false
	}
	c.healthyCount = 0
	if c.attempted && c.state == dnsRecoveryRecovering {
		c.state = dnsRecoveryFailed
		c.reason = reason
		c.error = "DNS resolution remained unhealthy after gateway reload"
		return false
	}
	if c.attempted || c.state == dnsRecoveryFailed {
		return false
	}
	if c.reason != reason {
		c.reason = reason
		c.failures = 0
	}
	c.state = dnsRecoveryObserving
	c.error = ""
	c.failures++
	return c.failures >= dnsProbeFailureThreshold
}

func (c *dnsRecoveryController) begin(reason string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.attempted || c.state == dnsRecoveryRecovering || c.state == dnsRecoveryFailed {
		return false
	}
	c.state = dnsRecoveryRecovering
	c.reason = reason
	c.error = ""
	c.attempted = true
	c.healthyCount = 0
	c.operationActive = true
	return true
}

func (c *dnsRecoveryController) finishAutomatic(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.operationActive = false
	if err != nil {
		c.state = dnsRecoveryFailed
		c.error = err.Error()
		return
	}
	// Reload returning success is not proof that resolution works again. Stay
	// in recovery until a fresh probe confirms healthy answers.
	c.state = dnsRecoveryRecovering
	c.error = ""
}

func (s *Server) monitorDNSRecovery(ctx context.Context) {
	s.evaluateDNSRecovery(ctx)
	ticker := time.NewTicker(autoDNSRecoveryInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.evaluateDNSRecovery(ctx)
		}
	}
}

func (s *Server) evaluateDNSRecovery(ctx context.Context) {
	cfg, err := config.LoadRuntime(s.configPath)
	if err != nil {
		s.dnsRecovery.observeUnknown()
		return
	}
	if !dnsHealthApplicable(cfg) {
		s.dnsRecovery.observeUnknown()
		return
	}
	if busy, err := gateway.LifecycleOperationInProgress(cfg); err != nil || busy {
		s.dnsRecovery.observeUnknown()
		return
	}
	status, err := s.gatewayStatus(ctx, cfg)
	if err != nil || status.RuntimeState != "active" {
		s.dnsRecovery.observeUnknown()
		return
	}
	// A missing mihomo is the mihomo recovery controller's incident; it has to
	// bring the process back before DNS can possibly answer again.
	if !strings.HasPrefix(status.Mihomo, "running") {
		s.dnsRecovery.observeUnknown()
		return
	}
	target := dnsProbeTarget(cfg)
	if target == "" {
		s.dnsRecovery.observeUnknown()
		return
	}
	probeCtx, cancel := context.WithTimeout(ctx, dnsProbeTimeout)
	healthy := probeDNS(probeCtx, target)
	cancel()
	if healthy {
		s.dnsRecovery.observeHealthy()
		return
	}
	if !s.dnsRecovery.observeFailure(dnsFailureProbeTimeout) {
		return
	}

	// Close the observation-to-action race with an external omg lifecycle
	// command. The Manager lock remains the final guard.
	if busy, err := gateway.LifecycleOperationInProgress(cfg); err != nil || busy {
		s.dnsRecovery.observeUnknown()
		return
	}
	recovery, err := s.store.Recovery()
	if err != nil || !mihomoRecoveryStageAllowed(cfg.Gateway.Mode, recovery.Stage) {
		s.dnsRecovery.observeUnknown()
		return
	}
	if !s.lifecycleMu.TryLock() {
		return
	}
	if !s.dnsRecovery.begin(dnsFailureProbeTimeout) {
		s.lifecycleMu.Unlock()
		return
	}

	op := newOperation("auto-reload-dns-"+randomToken(8), "reload")
	if err := s.store.CreateOperation(op); err != nil {
		s.lifecycleMu.Unlock()
		s.dnsRecovery.finishAutomatic(err)
		return
	}
	s.gatewayActivity.update(op)
	go s.runOperationLocked(op, cfg.Gateway.Mode, recovery, nil, s.dnsRecovery.finishAutomatic)
}

// dnsHealthApplicable reports whether this topology serves DNS from dnsmasq.
// DHCP takeover and same-LAN bypass both do; a control-plane-only setup does
// not, and probing it would produce a permanent false positive.
func dnsHealthApplicable(cfg config.Config) bool {
	return cfg.DHCP.Enabled || cfg.Gateway.SameLAN()
}

func dnsProbeTarget(cfg config.Config) string {
	host := strings.TrimSpace(cfg.DNS.Listen)
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = strings.TrimSpace(cfg.Gateway.LANIP)
	}
	if host == "" {
		return ""
	}
	port := cfg.DNS.Port
	if port == 0 {
		port = 53
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
}

// probeDNS sends one UDP query and accepts NOERROR or NXDOMAIN as proof that
// the listener is answering. SERVFAIL, a mismatched ID, a truncated reply and
// a timeout all count as failure.
func probeDNS(ctx context.Context, target string) bool {
	conn, err := (&net.Dialer{}).DialContext(ctx, "udp", target)
	if err != nil {
		return false
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	id := uint16(rand.Intn(1 << 16))
	if _, err := conn.Write(buildDNSQuery(id, dnsProbeName)); err != nil {
		return false
	}
	response := make([]byte, 512)
	n, err := conn.Read(response)
	if err != nil || n < 12 {
		return false
	}
	if binary.BigEndian.Uint16(response[0:2]) != id {
		return false
	}
	rcode := response[3] & 0x0f
	return rcode == 0 || rcode == 3
}

func buildDNSQuery(id uint16, name string) []byte {
	buf := make([]byte, 12, 12+len(name)+6)
	binary.BigEndian.PutUint16(buf[0:2], id)
	binary.BigEndian.PutUint16(buf[2:4], 0x0100) // RD
	binary.BigEndian.PutUint16(buf[4:6], 1)      // QDCOUNT
	for _, label := range strings.Split(name, ".") {
		buf = append(buf, byte(len(label)))
		buf = append(buf, label...)
	}
	buf = append(buf, 0)
	buf = binary.BigEndian.AppendUint16(buf, 1) // QTYPE A
	buf = binary.BigEndian.AppendUint16(buf, 1) // QCLASS IN
	return buf
}
