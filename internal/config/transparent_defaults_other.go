//go:build !linux

package config

func defaultTUNAutoRedirect() bool { return false }

func defaultTUNAutoDetectInterface() bool { return false }
