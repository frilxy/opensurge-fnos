// Package macosnetwork provides host network discovery and (on macOS) configuration.
//
// The package name is kept for upstream rebase hygiene. Darwin uses
// networksetup / arp / route; Linux uses ip(8). On fnOS, mutating host NIC
// or system proxy/DNS settings returns ErrManagedByFnOS.
package macosnetwork
