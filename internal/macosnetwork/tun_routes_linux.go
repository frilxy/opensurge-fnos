//go:build linux

package macosnetwork

import (
	"context"
	"fmt"

	"open-mihomo-gateway/internal/config"
)

func LookupRoute(ctx context.Context, destination string) (RouteSelection, error) {
	output, err := runCommand(ctx, "ip", "-j", "route", "get", destination)
	if err != nil {
		return RouteSelection{}, err
	}
	route := parseRouteGet(output)
	if route.Interface == "" {
		return RouteSelection{}, fmt.Errorf("route lookup for %s did not report an interface", destination)
	}
	return route, nil
}

func VerifyMacTUNRoutes(ctx context.Context, device string) error {
	if device == "" {
		return fmt.Errorf("TUN device is missing")
	}
	for _, destination := range []string{config.LocalSystemDNSServer, "198.18.0.2"} {
		route, err := LookupRoute(ctx, destination)
		if err != nil {
			return err
		}
		if route.Interface != device {
			return fmt.Errorf("TUN route for %s selects %s, expected %s", destination, route.Interface, device)
		}
	}
	return nil
}

func parseRouteGet(output string) RouteSelection {
	for _, entry := range parseIPRoutes(output) {
		if entry.Dev == "" {
			continue
		}
		return RouteSelection{Interface: entry.Dev, Gateway: entry.Gateway}
	}
	return RouteSelection{}
}
