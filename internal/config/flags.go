package config

import (
	"fmt"

	"github.com/spf13/pflag"
)

// Options is the flags-mode surface. It mirrors the YAML keys one for one;
// the CLI decides whether to load a file or build from these.
type Options struct {
	ConfigPath string

	ListenAddr      string
	DeviceAddr      string
	DeviceLocalAddr string
	DeviceInstance  int
	RequestTimeout  int
	MaxPending      int

	Allow            []string
	SCAllow          []string
	RatePerSec       float64
	DeviceRatePerSec float64
	ReadOnly         bool
	WriteDefault     string
	WriteAllow       []string
	WriteDeny        []string

	SCVMAC     string
	SCUUID     string
	SCHubs     []string
	SCCAFile   string
	SCCertFile string
	SCKeyFile  string

	MetricsAddr string
	AuditFile   string
	AuditMaxMB  int
	LogLevel    string
}

// Register installs every flag on fs and returns the option sink.
func Register(fs *pflag.FlagSet) *Options {
	o := &Options{}
	fs.StringVar(&o.ConfigPath, "config", "", "YAML config file (flags below are then ignored)")
	fs.StringVar(&o.ListenAddr, "listen", ":47808", "client leg address (BACnet/IP)")
	fs.StringVar(&o.DeviceAddr, "device", "", "device leg address (required in flags mode)")
	fs.StringVar(&o.DeviceLocalAddr, "device-local", "", "source address of the device leg (default: ephemeral)")
	fs.IntVar(&o.DeviceInstance, "device-instance", -1, "expected device instance (optional)")
	fs.IntVar(&o.RequestTimeout, "request-timeout", 30, "seconds a forwarded request may stay pending")
	fs.IntVar(&o.MaxPending, "max-pending", 256, "in-flight request cap (1..256)")

	fs.StringArrayVar(&o.Allow, "allow", nil, "client IP/CIDR allow-list entry (repeatable)")
	fs.StringArrayVar(&o.SCAllow, "sc-allow", nil, "BACnet/SC client VMAC allow-list entry (repeatable)")
	fs.Float64Var(&o.RatePerSec, "rate-per-sec", 0, "per-client request rate limit (0 = off)")
	fs.Float64Var(&o.DeviceRatePerSec, "device-rate-per-sec", 0, "shared request rate toward the device, all clients combined (0 = off)")
	fs.BoolVar(&o.ReadOnly, "read-only", false, "refuse every write")
	fs.StringVar(&o.WriteDefault, "write-default", "", "write policy default: allow|deny (enables the policy)")
	fs.StringArrayVar(&o.WriteAllow, "write-allow", nil, "allow rule: <type>:<instance>:<property> (repeatable)")
	fs.StringArrayVar(&o.WriteDeny, "write-deny", nil, "deny rule: <type>:<instance>:<property> (repeatable)")

	fs.StringVar(&o.SCVMAC, "sc-vmac", "", "BACnet/SC virtual MAC (enables the SC leg)")
	fs.StringVar(&o.SCUUID, "sc-uuid", "", "BACnet/SC device UUID")
	fs.StringArrayVar(&o.SCHubs, "sc-hub", nil, "BACnet/SC hub wss:// URL, primary first (repeatable)")
	fs.StringVar(&o.SCCAFile, "sc-ca", "", "PEM CA bundle for hub TLS verification (default: system roots)")
	fs.StringVar(&o.SCCertFile, "sc-cert", "", "PEM client certificate for the SC leg")
	fs.StringVar(&o.SCKeyFile, "sc-key", "", "PEM client private key for the SC leg")

	fs.StringVar(&o.MetricsAddr, "metrics-addr", "", "Prometheus listener address (empty = off)")
	fs.StringVar(&o.AuditFile, "audit-file", "", "structured audit sink, JSON lines (empty = off)")
	fs.IntVar(&o.AuditMaxMB, "audit-max-mb", 64, "rotate the audit file at this size, keeping one backup")
	fs.StringVar(&o.LogLevel, "log-level", "info", "debug|info|warn|error")
	return o
}

// Build validates the flag values into a Config.
func (o *Options) Build() (*Config, error) {
	c := Defaults()
	c.ListenAddr = o.ListenAddr
	c.DeviceAddr = o.DeviceAddr
	c.DeviceLocalAddr = o.DeviceLocalAddr
	c.RequestTimeoutSecs = o.RequestTimeout
	c.MaxPending = o.MaxPending
	c.LogLevel = o.LogLevel
	c.Metrics.Addr = o.MetricsAddr
	c.Audit = Audit{File: o.AuditFile, MaxMB: o.AuditMaxMB}
	if o.DeviceInstance >= 0 {
		v := uint32(o.DeviceInstance)
		c.DeviceInstance = &v
	}
	c.Access = Access{
		Allow:            o.Allow,
		SCAllow:          o.SCAllow,
		RatePerSec:       o.RatePerSec,
		DeviceRatePerSec: o.DeviceRatePerSec,
		ReadOnly:         o.ReadOnly,
	}
	c.SC = SC{
		VMAC:     o.SCVMAC,
		UUID:     o.SCUUID,
		Hubs:     o.SCHubs,
		CAFile:   o.SCCAFile,
		CertFile: o.SCCertFile,
		KeyFile:  o.SCKeyFile,
	}
	if o.WriteDefault != "" || len(o.WriteAllow) > 0 || len(o.WriteDeny) > 0 {
		if o.WriteDefault == "" {
			return nil, fmt.Errorf("config: --write-allow/--write-deny need an explicit --write-default")
		}
		wp := &WritePolicy{Default: o.WriteDefault}
		for _, spec := range o.WriteAllow {
			wp.Rules = append(wp.Rules, WriteRule{OID: spec, Action: "allow"})
		}
		for _, spec := range o.WriteDeny {
			wp.Rules = append(wp.Rules, WriteRule{OID: spec, Action: "deny"})
		}
		c.Access.WritePolicy = wp
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}
