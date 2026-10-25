package controlapi

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"open-mihomo-gateway/internal/config"
	"open-mihomo-gateway/internal/runtime"
)

// captureDNSForensics persists the kernel-visible state of the wedged DNS
// daemon before the gateway is reloaded. The watchdog probe can only prove
// "the listener stopped answering"; the files under /proc are what tell us
// whether dnsmasq is blocked in a socket read, a write, a lock, or a child,
// which is the difference between fixing the cause and restarting around it.
func (s *Server) captureDNSForensics(cfg config.Config, target string) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("OpenSurge DNS forensics: collector panicked: %v", r)
		}
	}()

	paths := runtime.NewPaths(cfg)
	state, _, _ := runtime.LoadState(paths.StateFile)
	dump := collectDNSForensics(state.PIDDNSMasq, paths.DNSMasqLog, target)

	dir := filepath.Join(s.store.Dir(), "dns-incidents")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		log.Printf("OpenSurge DNS forensics: create %s: %v", dir, err)
		return
	}
	path := filepath.Join(dir, time.Now().UTC().Format("20060102T150405Z")+".txt")
	if err := os.WriteFile(path, []byte(dump), 0o600); err != nil {
		log.Printf("OpenSurge DNS forensics: write %s: %v", path, err)
		return
	}
	log.Printf("OpenSurge DNS forensics: captured %s", path)
}

func collectDNSForensics(pid int, dnsmasqLog, target string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# OpenSurge DNS incident\nwhen: %s\ntarget: %s\npid: %d\n\n",
		time.Now().UTC().Format(time.RFC3339), target, pid)

	if pid <= 0 {
		b.WriteString("## /proc\nunavailable: runtime state has no dnsmasq pid\n\n")
	} else {
		for _, name := range []string{"status", "wchan", "syscall", "stack", "io", "limits", "cgroup", "cmdline"} {
			fmt.Fprintf(&b, "## /proc/%d/%s\n", pid, name)
			b.WriteString(readProcFile(pid, name))
			b.WriteString("\n")
		}
		b.WriteString("## socket table (53/1053)\n")
		b.WriteString(runCapture(3*time.Second, "sh", "-c",
			"ss -tanp 2>&1 | grep -E ':(53|1053) ' | head -40"))
		b.WriteString("\n## udp listeners\n")
		b.WriteString(runCapture(3*time.Second, "sh", "-c",
			"ss -ulnp 2>&1 | grep -E ':(53|1053) ' | head -20"))
		b.WriteString("\n## goroutine-free stack via gdb (best effort)\n")
		if gdb, err := exec.LookPath("gdb"); err == nil {
			b.WriteString(runCapture(10*time.Second, gdb, "-p", strconv.Itoa(pid), "-batch",
				"-ex", "thread apply all bt"))
		} else {
			b.WriteString("unavailable: gdb not installed in the image\n")
		}
	}

	if dnsmasqLog != "" {
		b.WriteString("\n## dnsmasq log tail\n")
		b.WriteString(tailFile(dnsmasqLog, 8000))
	}
	return b.String()
}

func readProcFile(pid int, name string) string {
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), name))
	if err != nil {
		return "unavailable: " + err.Error() + "\n"
	}
	if len(data) > 4000 {
		data = data[:4000]
	}
	if name == "cmdline" {
		return strings.ReplaceAll(strings.TrimRight(string(data), "\x00"), "\x00", " ") + "\n"
	}
	return string(data)
}

func runCapture(timeout time.Duration, name string, args ...string) string {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil && len(out) == 0 {
		return "unavailable: " + err.Error() + "\n"
	}
	return string(out)
}

func tailFile(path string, maxBytes int64) string {
	f, err := os.Open(path)
	if err != nil {
		return "unavailable: " + err.Error() + "\n"
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return "unavailable: " + err.Error() + "\n"
	}
	offset := info.Size() - maxBytes
	if offset < 0 {
		offset = 0
	}
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return "unavailable: " + err.Error() + "\n"
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return "unavailable: " + err.Error() + "\n"
	}
	return string(data)
}
