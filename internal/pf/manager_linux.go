//go:build linux

package pf

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"open-mihomo-gateway/internal/config"
	"open-mihomo-gateway/internal/process"
	"open-mihomo-gateway/internal/runtime"
)

type Manager struct {
	cfg   config.Config
	paths runtime.Paths
}

func New(cfg config.Config, paths runtime.Paths) Manager {
	return Manager{cfg: cfg, paths: paths}
}

func (m Manager) Check() error {
	if _, err := exec.LookPath("nft"); err != nil {
		return fmt.Errorf("nft not found in PATH")
	}
	return nil
}

func (m Manager) WriteAnchor() error {
	rendered, err := RenderAnchor(m.cfg)
	if err != nil {
		return err
	}
	return os.WriteFile(m.paths.PFAnchor, []byte(rendered), 0o640)
}

func (m Manager) Enabled() (bool, error) {
	return true, nil
}

func (m Manager) Load(_ bool) error {
	return process.Run("nft", "-f", m.paths.PFAnchor)
}

func (m Manager) Unload(_ bool) error {
	loaded, err := m.Loaded()
	if err != nil {
		return err
	}
	if !loaded {
		return nil
	}
	return process.Run("nft", "delete", "table", "inet", tableName)
}

func (m Manager) Loaded() (bool, error) {
	out, err := process.Output("nft", "list", "tables")
	if err != nil {
		return false, err
	}
	return tablesContain(string(out), tableName), nil
}

func tablesContain(output, name string) bool {
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 3 && fields[0] == "table" && fields[2] == name {
			return true
		}
	}
	return false
}
