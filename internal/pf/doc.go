// Package pf installs host NAT/forwarding rules.
//
// Darwin uses pf anchors. Linux renders nftables into the same
// runtime.Paths.PFAnchor file so callers stay unchanged.
package pf
