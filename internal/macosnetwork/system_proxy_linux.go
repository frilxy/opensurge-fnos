//go:build linux

package macosnetwork

import (
	"context"

	"open-mihomo-gateway/internal/runtime"
)

// SystemProxy is unused on Linux. Sidecar routing works by pointing clients
// at the NAS gateway/DNS, not by flipping a host "system proxy" switch.
type SystemProxy struct{}

func (SystemProxy) Prepare(_ context.Context, _ string, _ int) (runtime.SystemProxySnapshot, error) {
	return runtime.SystemProxySnapshot{}, ErrManagedByFnOS
}

func (SystemProxy) Enable(_ context.Context, _ runtime.SystemProxySnapshot, _ int) error {
	return ErrManagedByFnOS
}

func (SystemProxy) Restore(_ context.Context, _ runtime.SystemProxySnapshot) error {
	return ErrManagedByFnOS
}
