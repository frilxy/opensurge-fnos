//go:build linux

package macosnetwork

import (
	"context"
	"time"
)

func ProbeDHCPServers(_ context.Context, _ string, _ time.Duration) ([]string, error) {
	return nil, ErrManagedByFnOS
}
