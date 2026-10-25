package mihomo

import (
	"bytes"
	"fmt"
	"net"
	"path/filepath"
	"sort"
	"strings"
	"text/template"

	"open-mihomo-gateway/internal/config"
)

const configTemplate = `mixed-port: {{ .MixedPort }}
allow-lan: true
bind-address: "*"
mode: rule
log-level: info
ipv6: {{ .IPv6Enabled }}
{{- if and .TUNEnabled (not .TUNAutoDetectInterface) }}
interface-name: {{ .UpstreamInterface }}
{{- end }}

external-controller: {{ .APIAddr }}
{{- if .Secret }}
secret: {{ .Secret }}
{{- end }}

profile:
  store-selected: true
  store-fake-ip: {{ .StoreFakeIP }}

# Use MetaCubeX's documented CDN endpoints instead of the GitHub release URLs
# baked into mihomo. Imported profiles can contain GEOIP/GEOSITE/GEOASN rules,
# and engine validation must not depend on a slow GitHub asset download.
geox-url:
  geoip: https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.dat
  geosite: https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geosite.dat
  mmdb: https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.metadb
  asn: https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/GeoLite2-ASN.mmdb

dns:
  enable: true
  listen: "{{ .DNSListen }}"
  ipv6: {{ .DNSIPv6 }}
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
{{- if .DNSIPv6 }}
  fake-ip-range6: {{ .FakeIPv6Range }}
{{- end }}
{{ .DNSResolverFields }}

{{ if .TUNEnabled }}
tun:
  enable: true
  stack: {{ .TUNStack }}
  device: {{ .TUNDevice }}
  auto-route: {{ .TUNAutoRoute }}
  auto-detect-interface: {{ .TUNAutoDetectInterface }}
  strict-route: {{ .TUNStrictRoute }}
{{- if .TUNAutoRedirect }}
  auto-redirect: true
{{- end }}
  inet6-address:
    - {{ .TUNIPv6Address }}
  dns-hijack:
    - any:53
    - tcp://any:53
{{- if .TUNRouteAddresses }}
  route-address:
{{ .TUNRouteAddresses }}
{{- end }}
{{- if not .TUNCustomRoutes }}
  route-exclude-address:
    - {{ .LANPrefix }}
    - 127.0.0.0/8
    - 10.0.0.0/8
    - 172.16.0.0/12
    - 192.168.0.0/16
    - 224.0.0.0/4
    - 255.255.255.255/32
{{- end }}

{{ end }}
{{ if .TUNIPv6Enabled }}
listeners:
  - name: {{ .IPv6PacketListenerName }}
    type: opensurge-packet
    socket: {{ .IPv6PacketSocket }}
    mtu: {{ .IPv6PacketMTU }}
    device-users:
{{ .IPv6DeviceUsers }}

{{ end }}
{{ .PolicySections }}
`

// hostHasIPv6 reports whether this host has a usable non-loopback IPv6
// address. It is a variable so tests can pin the choice instead of depending
// on the runner's network stack.
var hostHasIPv6 = func() bool {
	interfaces, err := net.Interfaces()
	if err != nil {
		return false
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			if ipNet.IP.To4() == nil && !ipNet.IP.IsLoopback() {
				return true
			}
		}
	}
	return false
}

// mihomoDNSListen picks the DNS listener address. With the mihomo engine the
// core owns port 53; when the host has IPv6 it binds the IPv6 wildcard, which
// Linux/Go serve dual-stack (bindv6only=0), so IPv4 clients keep working while
// IPv6 clients can resolve through the NAS as well.
func mihomoDNSListen(cfg config.Config) string {
	if !cfg.DNS.MihomoServesDNS() {
		return "0.0.0.0:1053"
	}
	if hostHasIPv6() {
		return "[::]:53"
	}
	return "0.0.0.0:53"
}

func RenderConfig(cfg config.Config) (string, error) {
	tmpl, err := template.New("mihomo").Parse(configTemplate)
	if err != nil {
		return "", err
	}
	data, err := newTemplateData(cfg)
	if err != nil {
		return "", err
	}
	data.DNSListen = mihomoDNSListen(cfg)
	var out bytes.Buffer
	if err := tmpl.Execute(&out, data); err != nil {
		return "", err
	}
	return out.String(), nil
}

type templateData struct {
	config.MihomoConfig
	TUNEnabled             bool
	TUNDevice              string
	TUNStack               string
	TUNAutoRoute           bool
	TUNAutoDetectInterface bool
	TUNAutoRedirect        bool
	TUNStrictRoute         bool
	TUNRouteAddresses      string
	TUNCustomRoutes        bool
	IPv6Enabled            bool
	TUNIPv6Enabled         bool
	TUNIPv6Address         string
	UpstreamInterface      string
	LANPrefix              string
	UpstreamProxy          config.UpstreamProxyConfig
	DNSIPv6                bool
	DNSListen              string
	FakeIPv6Range          string
	IPv6PacketListenerName string
	IPv6PacketSocket       string
	IPv6PacketMTU          int
	IPv6DeviceUsers        string
	DNSResolverFields      string
	PolicySections         string
}

func newTemplateData(cfg config.Config) (templateData, error) {
	// Rendering consumes one immutable compiled policy snapshot so the rule
	// sections and IPv6 MAC-to-user sideband cannot drift from each other.
	if err := config.PrepareDevicePolicy(&cfg); err != nil {
		return templateData{}, err
	}
	lanPrefix, err := cfg.LANPrefix()
	if err != nil {
		return templateData{}, err
	}
	var imported *importedProfile
	dnsResolverFields := defaultDNSResolverFieldsYAML
	if cfg.Mihomo.ProfileMode == config.MihomoProfileModeImported {
		loaded, err := loadImportedProfile(cfg.Mihomo.Profile)
		if err != nil {
			return templateData{}, err
		}
		imported = &loaded
		dnsResolverFields = loaded.dnsResolverFields
	}
	if err := resolveDevicePolicy(&cfg, imported); err != nil {
		return templateData{}, err
	}
	dnsResolverFields, err = coordinateDNSResolvers(cfg, dnsResolverFields)
	if err != nil {
		return templateData{}, err
	}
	policySections, err := renderPolicySections(cfg, imported)
	if err != nil {
		return templateData{}, err
	}
	transparent := cfg.Transparent
	packetSocket, err := filepath.Abs(cfg.RuntimePath("ipv6-packet.sock"))
	if err != nil {
		return templateData{}, fmt.Errorf("resolve IPv6 packet socket: %w", err)
	}
	tunRouteAddresses := renderTUNRouteAddresses(cfg, lanPrefix)
	return templateData{
		MihomoConfig:           cfg.Mihomo,
		TUNEnabled:             transparent.TUNEnabled(),
		TUNDevice:              transparent.TUNDevice,
		TUNStack:               transparent.TUNStack,
		TUNAutoRoute:           transparent.TUNAutoRoute,
		TUNAutoDetectInterface: transparent.TUNAutoDetectInterface,
		TUNAutoRedirect:        transparent.TUNAutoRedirect && transparent.TUNEnabled(),
		TUNStrictRoute:         transparent.TUNStrictRoute,
		TUNRouteAddresses:      tunRouteAddresses,
		TUNCustomRoutes:        tunRouteAddresses != "",
		IPv6Enabled:            cfg.DNS.IPv6 || transparent.TUNEnabled(),
		TUNIPv6Enabled:         transparent.TUNIPv6 != config.TUNIPv6Off,
		TUNIPv6Address:         config.MihomoTUNIPv6,
		UpstreamInterface:      cfg.Gateway.UpstreamInterface,
		LANPrefix:              lanPrefix,
		UpstreamProxy:          cfg.UpstreamProxy,
		DNSIPv6:                cfg.DNS.IPv6,
		FakeIPv6Range:          config.MihomoFakeIPv6Range,
		IPv6PacketListenerName: config.IPv6PacketListenerName,
		IPv6PacketSocket:       yamlQuote(packetSocket),
		IPv6PacketMTU:          transparent.IPv6PacketMTU,
		IPv6DeviceUsers:        renderIPv6DeviceUsers(cfg),
		DNSResolverFields:      indentYAMLBlock(dnsResolverFields, "  "),
		PolicySections:         policySections,
	}, nil
}

func renderIPv6DeviceUsers(cfg config.Config) string {
	users := map[string]string{}
	if cfg.DevicePolicy.Bundle != nil {
		for _, managed := range cfg.DevicePolicy.Bundle.Compiled.Devices {
			if managed.MAC != "" {
				users[managed.MAC] = DeviceInboundUser(managed.ID)
			}
		}
	}
	keys := make([]string, 0, len(users))
	for mac := range users {
		keys = append(keys, mac)
	}
	sort.Strings(keys)
	if len(keys) == 0 {
		return "      {}"
	}
	var out strings.Builder
	for _, mac := range keys {
		out.WriteString("      " + yamlQuote(mac) + ": " + yamlQuote(users[mac]) + "\n")
	}
	return strings.TrimRight(out.String(), "\n")
}

func indentYAMLBlock(value, indent string) string {
	lines := strings.Split(strings.TrimRight(value, "\n"), "\n")
	for i := range lines {
		lines[i] = indent + lines[i]
	}
	return strings.Join(lines, "\n")
}
