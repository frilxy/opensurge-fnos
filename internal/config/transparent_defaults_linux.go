//go:build linux

package config

func defaultTUNAutoRedirect() bool { return true }

func defaultTUNAutoDetectInterface() bool { return false }
