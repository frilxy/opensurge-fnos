//go:build linux

package macosnetwork

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
)

// ErrManagedByFnOS means the operation would change the host NIC or system
// proxy/DNS. fnOS owns those settings; the sidecar control plane does not.
var ErrManagedByFnOS = errors.New("网卡配置由 fnOS 系统设置管理，OpenSurge 不修改宿主机网络")

const resolvConfPath = "/etc/resolv.conf"

// Discover is read-only: it reports the current Linux network state.
// Linux has no "network service" concept; networkService matches the interface.
func Discover(ctx context.Context, networkService, interfaceName string) (Snapshot, error) {
	interfaceName = strings.TrimSpace(interfaceName)
	if interfaceName == "" {
		return Snapshot{}, fmt.Errorf("interface is required")
	}
	networkService = strings.TrimSpace(networkService)
	if networkService == "" {
		networkService = interfaceName
	}
	if networkService != interfaceName {
		return Snapshot{}, fmt.Errorf("network service %q does not match interface %s", networkService, interfaceName)
	}

	addrOutput, err := runCommand(ctx, "ip", "-j", "addr", "show", "dev", interfaceName)
	if err != nil {
		return Snapshot{}, err
	}
	snapshot, err := parseIPAddr(addrOutput, interfaceName)
	if err != nil {
		return Snapshot{}, err
	}
	snapshot.NetworkService = networkService
	snapshot.Interface = interfaceName
	snapshot.IPv4Mode = IPv4ModeDHCP

	routes, err := runCommand(ctx, "ip", "-j", "route", "show", "default")
	if err != nil {
		return Snapshot{}, err
	}
	snapshot.Router = defaultGateway(routes, interfaceName)

	if content, err := os.ReadFile(resolvConfPath); err == nil {
		snapshot.DNS = parseResolvConf(string(content))
	}

	if routes6, err := runCommand(ctx, "ip", "-j", "-6", "route", "show", "default"); err == nil {
		snapshot.IPv6Default = hasDefaultRouteDev(routes6, interfaceName)
	}

	if snapshot.IPv4 == "" || snapshot.SubnetMask == "" || snapshot.Router == "" {
		return Snapshot{}, fmt.Errorf("interface %q does not expose a complete IPv4 configuration", interfaceName)
	}
	return snapshot, nil
}

func DiscoverDefault(ctx context.Context) (Snapshot, error) {
	route, err := LookupRoute(ctx, "default")
	if err != nil {
		return Snapshot{}, fmt.Errorf("discover default IPv4 route: %w", err)
	}
	return Discover(ctx, "", route.Interface)
}

func ListInterfaces(_ context.Context) ([]InterfaceOption, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	services := map[string]string{}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		services[iface.Name] = iface.Name
	}
	options := interfaceOptions(services)
	for index := range options {
		iface, err := net.InterfaceByName(options[index].Interface)
		if err != nil {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		options[index].IPv6LinkLocal = firstLinkLocalIPv6(addrs)
	}
	return options, nil
}

func PingRouter(ctx context.Context, router string) error {
	if net.ParseIP(router).To4() == nil {
		return fmt.Errorf("router must be IPv4")
	}
	_, err := runCommand(ctx, "ping", "-c", "1", "-W", "1", router)
	return err
}

func SetManual(_ context.Context, _ ManualConfig) error { return ErrManagedByFnOS }

func SetDHCP(_ context.Context, _ string) error { return ErrManagedByFnOS }

func ServiceInterface(_ context.Context, _ string) (string, error) { return "", ErrManagedByFnOS }

func NetworkServiceForInterface(_ context.Context, interfaceName string) (string, error) {
	if strings.TrimSpace(interfaceName) == "" {
		return "", fmt.Errorf("interface is required")
	}
	return interfaceName, nil
}

type ipAddrEntry struct {
	IfName   string `json:"ifname"`
	Address  string `json:"address"`
	AddrInfo []struct {
		Family    string `json:"family"`
		Local     string `json:"local"`
		PrefixLen int    `json:"prefixlen"`
	} `json:"addr_info"`
}

func parseIPAddr(output, interfaceName string) (Snapshot, error) {
	var entries []ipAddrEntry
	if err := json.Unmarshal([]byte(output), &entries); err != nil {
		return Snapshot{}, fmt.Errorf("parse ip addr output: %w", err)
	}
	snapshot := Snapshot{DNS: []string{}}
	for _, entry := range entries {
		if entry.IfName != interfaceName {
			continue
		}
		snapshot.HardwareAddr = entry.Address
		for _, addr := range entry.AddrInfo {
			if addr.Family != "inet" || addr.PrefixLen < 1 || addr.PrefixLen > 32 {
				continue
			}
			if net.ParseIP(addr.Local).To4() == nil {
				continue
			}
			snapshot.IPv4 = addr.Local
			snapshot.SubnetMask = net.IP(net.CIDRMask(addr.PrefixLen, 32)).String()
			return snapshot, nil
		}
		return snapshot, nil
	}
	return Snapshot{}, fmt.Errorf("interface %q was not found", interfaceName)
}

type ipRouteEntry struct {
	Dst     string `json:"dst"`
	Gateway string `json:"gateway"`
	Dev     string `json:"dev"`
}

func parseIPRoutes(output string) []ipRouteEntry {
	var entries []ipRouteEntry
	if err := json.Unmarshal([]byte(output), &entries); err != nil {
		return nil
	}
	return entries
}

func defaultGateway(output, interfaceName string) string {
	for _, entry := range parseIPRoutes(output) {
		if entry.Dev == interfaceName && entry.Gateway != "" {
			return entry.Gateway
		}
	}
	return ""
}

func hasDefaultRouteDev(output, interfaceName string) bool {
	for _, entry := range parseIPRoutes(output) {
		if entry.Dev == interfaceName {
			return true
		}
	}
	return false
}

func parseResolvConf(content string) []string {
	result := []string{}
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "nameserver" {
			continue
		}
		if net.ParseIP(fields[1]) != nil {
			result = append(result, fields[1])
		}
	}
	return result
}
