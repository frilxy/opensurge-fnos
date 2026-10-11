package controlapi

import (
	"context"
	"fmt"
	"log"

	"open-mihomo-gateway/internal/config"
	"open-mihomo-gateway/internal/runtime"
)

// shouldRestoreGateway reports whether a sidecar should bring the gateway back
// after the control plane starts. Missing desired state means "was never
// recorded": Docker/fnOS treats that as restore, matching a first install and
// upgrades from builds that did not persist intent.
func shouldRestoreGateway(hasDesired, desired bool) bool {
	if !hasDesired {
		return true
	}
	return desired
}

func (s *Server) restoreGatewayIfDesired() {
	if !s.autostartGateway {
		return
	}
	if !s.lifecycleMu.TryLock() {
		log.Printf("OpenSurge gateway autostart skipped: another lifecycle operation is running")
		return
	}
	defer s.lifecycleMu.Unlock()

	cfg, err := config.LoadRuntime(s.configPath)
	if err != nil {
		log.Printf("OpenSurge gateway autostart: load config: %v", err)
		return
	}
	status, err := s.gatewayStatus(context.Background(), cfg)
	if err != nil {
		log.Printf("OpenSurge gateway autostart: status: %v", err)
		return
	}
	desired, hasDesired, err := s.store.GatewayDesired()
	if err != nil {
		log.Printf("OpenSurge gateway autostart: desired state: %v", err)
		return
	}
	if status.Gateway == "running" && status.RuntimeState == "active" {
		if !hasDesired {
			if err := s.store.SaveGatewayDesired(true); err != nil {
				log.Printf("OpenSurge persist gateway desired running: %v", err)
			}
		}
		return
	}
	if !shouldRestoreGateway(hasDesired, desired) {
		log.Printf("OpenSurge gateway autostart skipped: last GUI action was stop")
		return
	}

	recovery, _ := s.store.Recovery()
	_, exists, err := runtime.LoadState(runtime.NewPaths(cfg).StateFile)
	if err != nil {
		log.Printf("OpenSurge gateway autostart: runtime state: %v", err)
		return
	}
	if status.RuntimeState == "interrupted" || exists {
		log.Printf("OpenSurge gateway autostart: clearing leftover runtime before start")
		if err := s.runAutostartAction("stop", cfg.Gateway.Mode, recovery, nil); err != nil {
			log.Printf("OpenSurge gateway autostart: stop leftover runtime: %v", err)
			return
		}
	}

	if cfg.Gateway.Mode == config.GatewayModeSameWiFiDHCP && recovery.Stage != RecoveryRouterDHCPDisabledConfirmed {
		log.Printf("OpenSurge gateway autostart skipped: same-LAN DHCP takeover is not confirmed")
		return
	}

	input, err := s.policyWorkspaceInput(PolicyWorkspaceRequest{Action: "read"})
	if err != nil {
		log.Printf("OpenSurge gateway autostart: policy snapshot: %v", err)
		return
	}
	if input.ExpectedGatewayState != policyWorkspaceGatewayStopped {
		log.Printf("OpenSurge gateway autostart: runtime is still present after stop")
		return
	}
	if err := s.store.SaveGatewayDesired(true); err != nil {
		log.Printf("OpenSurge persist gateway desired running: %v", err)
	}
	log.Printf("OpenSurge gateway autostart: starting bypass gateway")
	if err := s.runAutostartAction("start", cfg.Gateway.Mode, recovery, &input); err != nil {
		log.Printf("OpenSurge gateway autostart: start: %v", err)
		return
	}
	log.Printf("OpenSurge gateway autostart: gateway is running")
}

func (s *Server) runAutostartAction(kind, topology string, recovery RecoveryState, startWorkspace *PolicyWorkspaceInput) error {
	op := newOperation("autostart-"+kind+"-"+randomToken(8), kind)
	if err := s.store.CreateOperation(op); err != nil {
		return err
	}
	s.gatewayActivity.update(op)
	s.runOperation(op, topology, recovery, startWorkspace, nil)
	saved, err := s.store.Operation(op.ID)
	if err != nil {
		return err
	}
	if saved.State != "succeeded" {
		if saved.Error != "" {
			return fmt.Errorf("%s: %s", kind, saved.Error)
		}
		return fmt.Errorf("gateway %s did not succeed", kind)
	}
	return nil
}
