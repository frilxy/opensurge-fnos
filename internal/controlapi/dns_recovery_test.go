package controlapi

import (
	"context"
	"net"
	"testing"
	"time"

	"open-mihomo-gateway/internal/config"
)

func udpDNSResponder(t *testing.T, rcode byte) string {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	go func() {
		buf := make([]byte, 512)
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			return
		}
		response := make([]byte, n)
		copy(response, buf[:n])
		response[2] |= 0x80 // QR
		response[3] = 0x80 | rcode
		_, _ = conn.WriteTo(response, addr)
	}()
	return conn.LocalAddr().String()
}

func TestProbeDNSAcceptsNoError(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if !probeDNS(ctx, udpDNSResponder(t, 0)) {
		t.Fatal("probeDNS() = false for a NOERROR answer, want true")
	}
}

func TestProbeDNSAcceptsNXDomain(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if !probeDNS(ctx, udpDNSResponder(t, 3)) {
		t.Fatal("probeDNS() = false for NXDOMAIN, want true")
	}
}

func TestProbeDNSRejectsServfail(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if probeDNS(ctx, udpDNSResponder(t, 2)) {
		t.Fatal("probeDNS() = true for SERVFAIL, want false")
	}
}

func TestProbeDNSTreatsTimeoutAsUnhealthy(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	if probeDNS(ctx, conn.LocalAddr().String()) {
		t.Fatal("probeDNS() = true when the server never answers, want false")
	}
}

func TestDNSProbeTarget(t *testing.T) {
	cfg := config.Config{}
	cfg.DNS.Listen = "192.168.10.229"
	cfg.DNS.Port = 53
	if got := dnsProbeTarget(cfg); got != "192.168.10.229:53" {
		t.Fatalf("dnsProbeTarget() = %q, want 192.168.10.229:53", got)
	}

	cfg.DNS.Listen = "0.0.0.0"
	cfg.DNS.Port = 0
	cfg.Gateway.LANIP = "10.0.0.2"
	if got := dnsProbeTarget(cfg); got != "10.0.0.2:53" {
		t.Fatalf("dnsProbeTarget() = %q, want 10.0.0.2:53", got)
	}
}

func TestDNSRecoveryNeedsConsecutiveFailures(t *testing.T) {
	c := newDNSRecoveryController()
	if c.observeFailure(dnsFailureProbeTimeout) {
		t.Fatal("first failure triggered recovery, want threshold")
	}
	if c.observeFailure(dnsFailureProbeTimeout) {
		t.Fatal("second failure triggered recovery, want threshold")
	}
	if !c.observeFailure(dnsFailureProbeTimeout) {
		t.Fatal("third consecutive failure did not trigger recovery")
	}
	if !c.begin(dnsFailureProbeTimeout) {
		t.Fatal("begin() = false after threshold, want true")
	}
	if c.begin(dnsFailureProbeTimeout) {
		t.Fatal("begin() ran twice for one incident")
	}
	c.finishAutomatic(nil)
	// A successful reload is not proof of health: the incident stays in
	// recovery, and a further failure must not retry automatically.
	if c.observeFailure(dnsFailureProbeTimeout) {
		t.Fatal("recovery retried automatically after one attempt")
	}
	if c.state != dnsRecoveryFailed {
		t.Fatalf("state = %q after failed post-recovery probe, want %q", c.state, dnsRecoveryFailed)
	}
}

func TestDNSRecoveryHealthyClearsIncident(t *testing.T) {
	c := newDNSRecoveryController()
	for i := 0; i < dnsProbeFailureThreshold; i++ {
		c.observeFailure(dnsFailureProbeTimeout)
	}
	if !c.begin(dnsFailureProbeTimeout) {
		t.Fatal("begin() = false, want true")
	}
	c.finishAutomatic(nil)
	c.observeHealthy()
	if c.state != dnsRecoveryRecovering {
		t.Fatalf("state = %q after one healthy probe, want %q", c.state, dnsRecoveryRecovering)
	}
	c.observeHealthy()
	if c.state != dnsRecoveryIdle {
		t.Fatalf("state = %q after confirmed health, want %q", c.state, dnsRecoveryIdle)
	}
}

func TestDNSHealthApplicable(t *testing.T) {
	cfg := config.Config{}
	if dnsHealthApplicable(cfg) {
		t.Fatal("dnsHealthApplicable() = true for a control-plane-only config")
	}
	cfg.DHCP.Enabled = true
	if !dnsHealthApplicable(cfg) {
		t.Fatal("dnsHealthApplicable() = false with DHCP enabled")
	}
	cfg = config.Config{}
	cfg.Gateway.Mode = config.GatewayModeSameLAN
	if !dnsHealthApplicable(cfg) {
		t.Fatal("dnsHealthApplicable() = false for the same-LAN bypass topology")
	}
}
