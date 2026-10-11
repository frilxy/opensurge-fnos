//go:build linux

package pf

import (
	"bytes"
	"text/template"

	"open-mihomo-gateway/internal/config"
)

const tableName = "opensurge"

const rulesetTemplate = `table inet {{ .TableName }}
delete table inet {{ .TableName }}

table inet {{ .TableName }} {
	chain postrouting {
		type nat hook postrouting priority srcnat; policy accept;
		oifname "{{ .UpstreamInterface }}" ip saddr {{ .LanCIDR }}{{ if .SameLAN }} ip daddr != {{ .LanCIDR }}{{ end }} masquerade
	}

	chain forward {
		type filter hook forward priority filter; policy accept;
	}
}
`

type templateData struct {
	TableName         string
	UpstreamInterface string
	LanCIDR           string
	SameLAN           bool
}

func RenderAnchor(cfg config.Config) (string, error) {
	lanCIDR, err := cfg.LANPrefix()
	if err != nil {
		return "", err
	}
	data := templateData{
		TableName:         tableName,
		UpstreamInterface: cfg.Gateway.UpstreamInterface,
		LanCIDR:           lanCIDR,
		SameLAN:           cfg.Gateway.SameLAN(),
	}

	tmpl, err := template.New("nft-ruleset").Parse(rulesetTemplate)
	if err != nil {
		return "", err
	}
	var out bytes.Buffer
	if err := tmpl.Execute(&out, data); err != nil {
		return "", err
	}
	return out.String(), nil
}
