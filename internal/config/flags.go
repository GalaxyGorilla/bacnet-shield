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

	Allow        []string
	RatePerSec   float64
	ReadOnly     bool
	WriteDefault string
	WriteAllow   []string
	WriteDeny    []string

	MetricsAddr string
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
	fs.Float64Var(&o.RatePerSec, "rate-per-sec", 0, "per-client request rate limit (0 = off)")
	fs.BoolVar(&o.ReadOnly, "read-only", false, "refuse every write")
	fs.StringVar(&o.WriteDefault, "write-default", "", "write policy default: allow|deny (enables the policy)")
	fs.StringArrayVar(&o.WriteAllow, "write-allow", nil, "allow rule: <type>:<instance>:<property> (repeatable)")
	fs.StringArrayVar(&o.WriteDeny, "write-deny", nil, "deny rule: <type>:<instance>:<property> (repeatable)")

	fs.StringVar(&o.MetricsAddr, "metrics-addr", "", "Prometheus listener address (empty = off)")
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
	if o.DeviceInstance >= 0 {
		v := uint32(o.DeviceInstance)
		c.DeviceInstance = &v
	}
	c.Access = Access{
		Allow:      o.Allow,
		RatePerSec: o.RatePerSec,
		ReadOnly:   o.ReadOnly,
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
