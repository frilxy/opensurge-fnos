//go:build linux

package macosnetwork

import (
	"context"

	"open-mihomo-gateway/internal/runtime"
)

// SystemDNS is a no-op on Linux. fnOS owns resolver configuration; the
// control plane must not rewrite /etc/resolv.conf or systemd-resolved.
type SystemDNS struct{}

func (SystemDNS) Prepare(_ context.Context, _ string) (runtime.SystemDNSSnapshot, error) {
	return runtime.SystemDNSSnapshot{}, nil
}

func (SystemDNS) Enable(_ context.Context, _ runtime.SystemDNSSnapshot) error {
	return nil
}

func (SystemDNS) Restore(_ context.Context, _ runtime.SystemDNSSnapshot) (bool, error) {
	return true, nil
}

func (SystemDNS) Verify(_ context.Context, _ runtime.SystemDNSSnapshot) error {
	return nil
}
