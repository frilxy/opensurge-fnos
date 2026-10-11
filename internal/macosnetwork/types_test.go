package macosnetwork

import (
	"net"
	"testing"
)

func TestInterfaceOptionsAreSortedAndNamed(t *testing.T) {
	options := interfaceOptions(map[string]string{
		"USB 10/100/1000 LAN": "en7",
		"Wi-Fi":               "en0",
		"":                    "en9",
	})
	if len(options) != 2 {
		t.Fatalf("options = %#v", options)
	}
	if options[0].Interface != "en0" || options[0].NetworkService != "Wi-Fi" {
		t.Fatalf("first option = %#v", options[0])
	}
	if options[1].Interface != "en7" || options[1].NetworkService != "USB 10/100/1000 LAN" {
		t.Fatalf("second option = %#v", options[1])
	}
}

func TestFirstLinkLocalIPv6IgnoresOtherAddressesAndScope(t *testing.T) {
	addrs := []net.Addr{
		&net.IPNet{IP: net.ParseIP("192.168.1.20"), Mask: net.CIDRMask(24, 32)},
		stringAddr("2001:db8::20/64"),
		stringAddr("fe80::abcd%en0/64"),
	}
	if got := firstLinkLocalIPv6(addrs); got != "fe80::abcd" {
		t.Fatalf("link-local IPv6 = %q", got)
	}
}

type stringAddr string

func (address stringAddr) Network() string { return "ip" }
func (address stringAddr) String() string  { return string(address) }

func TestValidateManual(t *testing.T) {
	valid := ManualConfig{NetworkService: "Wi-Fi", Interface: "en0", IPv4: "192.168.1.20", SubnetMask: "255.255.255.0", Router: "192.168.1.1", DNS: []string{"1.1.1.1"}}
	if err := ValidateManual(valid); err != nil {
		t.Fatal(err)
	}
	invalid := valid
	invalid.Router = "192.168.2.1"
	if err := ValidateManual(invalid); err == nil {
		t.Fatal("router outside subnet should fail")
	}
}

func TestVerifyManualRequiresManualModeAndExpectedIPv4(t *testing.T) {
	expected := ManualConfig{NetworkService: "Wi-Fi", Interface: "en0", IPv4: "192.168.1.20", SubnetMask: "255.255.255.0", Router: "192.168.1.1"}
	applied := Snapshot{NetworkService: "Wi-Fi", Interface: "en0", IPv4Mode: IPv4ModeManual, IPv4: expected.IPv4, SubnetMask: expected.SubnetMask, Router: expected.Router}
	if err := VerifyManual(applied, expected); err != nil {
		t.Fatal(err)
	}
	applied.IPv4Mode = IPv4ModeDHCP
	if err := VerifyManual(applied, expected); err == nil {
		t.Fatal("DHCP configuration should not verify as fixed IPv4")
	}
	applied.IPv4Mode = IPv4ModeManual
	applied.IPv4 = "192.168.1.99"
	if err := VerifyManual(applied, expected); err == nil {
		t.Fatal("unexpected manual IPv4 should not verify")
	}
}

func TestSnapshotCompetingIPv6DefaultIsConservativeForLegacySnapshots(t *testing.T) {
	if (Snapshot{IPv6Default: true}).CompetingIPv6Default() != true {
		t.Fatal("legacy snapshot with IPv6 default should warn")
	}
	if (Snapshot{IPv6Default: true, IPv6DefaultSelfOnly: true}).CompetingIPv6Default() {
		t.Fatal("self-only IPv6 default should not warn")
	}
}
