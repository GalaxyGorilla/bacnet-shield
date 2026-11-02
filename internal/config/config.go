package config

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/GalaxyGorilla/bacnet-shield/internal/access"
	"github.com/GalaxyGorilla/bacnet-shield/internal/bacnet"
	"github.com/GalaxyGorilla/bacnet-shield/internal/bacnet/sc"
)

const (
	// defaultRequestTimeoutSecs bounds how long a forwarded request may stay
	// pending before its invoke ID is reclaimed. 0 in a device entry means
	// this default.
	defaultRequestTimeoutSecs = 30
	// defaultMaxPending caps in-flight requests per device. The BACnet
	// invoke ID is one octet, so the hard maximum is 256. 0 means this
	// default.
	defaultMaxPending = 256
)

// Config is one process: the observability settings plus one or more
// listener<->device pairs. Each Device couples exactly one front-leg listener
// with exactly one legacy device, so an appliance can protect several devices
// with one config, one process and one metrics endpoint (per-device label)
// without becoming a router or a BBMD.
type Config struct {
	// Devices is the list of listener<->device pairs. At least one is
	// required; every listen_addr must be unique (the process binds them
	// all).
	Devices []Device `yaml:"devices"`

	LogLevel string  `yaml:"log_level"`
	Metrics  Metrics `yaml:"metrics"`
	Audit    Audit   `yaml:"audit"`
}

// Device couples one front-leg listener with one upstream legacy device and
// carries that device's own policy. Clients reach a device only through its
// listener: the proxy never routes one device's traffic to another.
type Device struct {
	// Name labels the device in logs, metrics (the `device` label) and
	// reload matching. Empty falls back to DeviceAddr. It must be unique.
	Name string `yaml:"name"`

	// ListenAddr is the client leg for this device: the address managers/BMS
	// workstations send BACnet/IP to. Give each device its own local IP on
	// the standard port 47808, so a client's broadcast Who-Is still reaches
	// the whole building.
	ListenAddr string `yaml:"listen_addr"`
	// DeviceAddr is this device's address on the clear leg.
	DeviceAddr string `yaml:"device_addr"`
	// DeviceLocalAddr is the optional source address of the device leg.
	// Empty means an ephemeral port, which is what a BACnet client does.
	DeviceLocalAddr string `yaml:"device_local_addr"`
	// DeviceInstance optionally pins the expected device instance. It is
	// used to warn about a mismatched I-Am and by selftest; it never gates
	// traffic (the proxy forwards what the device says).
	DeviceInstance *uint32 `yaml:"device_instance"`

	// RequestTimeoutSecs bounds how long a forwarded request may stay
	// pending before its invoke ID is reclaimed. 0 = default 30.
	RequestTimeoutSecs int `yaml:"request_timeout_secs"`
	// MaxPending caps in-flight requests for this device. 0 = default 256.
	MaxPending int `yaml:"max_pending"`

	// Access is this device's front-leg policy. Each device has its own
	// allow-list, rate limit, device budget and write policy.
	Access Access `yaml:"access"`
	// SC is this device's optional BACnet/SC front leg. Each device with an
	// sc block is its own SC node (own VMAC/UUID) on its hub.
	SC SC `yaml:"sc"`
}

// Access is the front-leg policy block. The key names mirror the other
// Shield projects so one policy vocabulary covers the appliance family.
type Access struct {
	Allow            []string     `yaml:"allow"`
	SCAllow          []string     `yaml:"sc_allow"`
	RatePerSec       float64      `yaml:"rate_per_sec"`
	DeviceRatePerSec float64      `yaml:"device_rate_per_sec"`
	ReadOnly         bool         `yaml:"read_only"`
	WritePolicy      *WritePolicy `yaml:"write_policy"`
}

// SC is the optional BACnet/SC front leg. An empty block leaves the leg off;
// the BACnet/IP leg always exists. The proxy attaches to an existing hub as a
// node, so there is no hub listener to configure here.
type SC struct {
	// VMAC is the proxy's 6-octet virtual MAC on the hub.
	VMAC string `yaml:"vmac"`
	// UUID is the proxy's 16-octet device UUID on the hub.
	UUID string `yaml:"uuid"`
	// Hubs are WebSocket URLs, primary first, failover after. They must be
	// wss://; plain ws:// is not a BACnet/SC deployment.
	Hubs []string `yaml:"hubs"`
	// CAFile optionally replaces the system roots for hub verification.
	CAFile string `yaml:"ca_file"`
	// CertFile and KeyFile optionally present a client certificate.
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

// Enabled reports whether any SC field was configured. A partially configured
// block is rejected by Validate, never silently run as "SC off".
func (s SC) Enabled() bool {
	return s.VMAC != "" || s.UUID != "" || len(s.Hubs) > 0 ||
		s.CAFile != "" || s.CertFile != "" || s.KeyFile != ""
}

// WritePolicy is the OID-scoped write policy. It is mutually exclusive with
// read_only.
type WritePolicy struct {
	Default string      `yaml:"default"`
	Rules   []WriteRule `yaml:"rules"`
}

// WriteRule is one rule. OID is "<object-type>:<instance>:<property>", with
// "*" allowed in any part (see internal/access).
type WriteRule struct {
	OID    string `yaml:"oid"`
	Action string `yaml:"action"`
}

// Metrics is the observability block.
type Metrics struct {
	Addr string `yaml:"addr"` // Prometheus HTTP listener; empty disables it
}

// Audit is the optional structured audit stream. An empty File disables it:
// like every Shield control, the audit is opt-in. When enabled, one JSON
// object per line is appended for every security decision the front leg makes
// (allow-list, rate limit, device budget, write policy, unsupported
// subscription), each naming the device it concerns.
type Audit struct {
	// File is the append-only sink. Empty = audit off.
	File string `yaml:"file"`
	// MaxMB rotates the file at this size, keeping one backup
	// ("<file>.1"), so the disk use is bounded at about twice this. Default 64.
	MaxMB int `yaml:"max_mb"`
}

// Defaults returns the values used for every field a config file or flag does
// not set.
func Defaults() *Config {
	return &Config{
		LogLevel: "info",
		Audit:    Audit{MaxMB: 64},
	}
}

// applyDeviceDefaults fills the per-device defaults a device entry may omit.
// It runs after decoding, when the device list is known.
func (c *Config) applyDeviceDefaults() {
	for i := range c.Devices {
		d := &c.Devices[i]
		if d.RequestTimeoutSecs == 0 {
			d.RequestTimeoutSecs = defaultRequestTimeoutSecs
		}
		if d.MaxPending == 0 {
			d.MaxPending = defaultMaxPending
		}
		if d.Name == "" {
			d.Name = d.DeviceAddr
		}
	}
}

// Load reads a YAML config, applies defaults for absent fields, and
// validates it.
//
// Decoding is strict: an unknown key is an error. A misspelled "read_only"
// must fail loudly, not produce a proxy that looks read-only and is not.
func Load(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	defer f.Close()
	return Decode(f)
}

// Decode is Load for an arbitrary reader (used by tests and reload).
func Decode(r io.Reader) (*Config, error) {
	c := Defaults()
	dec := yaml.NewDecoder(r)
	dec.KnownFields(true)
	if err := dec.Decode(c); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("config: %w", err)
	}
	c.applyDeviceDefaults()
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

// Validate checks every field that can be checked without touching the
// network, across the whole process and every device. Access policies are
// compiled here too, so validation and runtime can never disagree about what a
// policy means.
func (c *Config) Validate() error {
	if len(c.Devices) == 0 {
		return fmt.Errorf("config: at least one device entry is required")
	}
	switch c.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("config: log_level %q (want debug|info|warn|error)", c.LogLevel)
	}
	if c.Metrics.Addr != "" {
		if err := validateHostPort("metrics.addr", c.Metrics.Addr); err != nil {
			return fmt.Errorf("config: %s", err)
		}
	}
	if c.Audit.MaxMB < 1 || c.Audit.MaxMB > 10240 {
		return fmt.Errorf("config: audit.max_mb %d outside 1..10240", c.Audit.MaxMB)
	}

	seenNames := make(map[string]bool, len(c.Devices))
	seenListen := make(map[string]string, len(c.Devices))
	seenVMAC := make(map[string]string)
	for i := range c.Devices {
		if err := c.Devices[i].validate(i, seenNames, seenListen, seenVMAC); err != nil {
			return err
		}
	}
	return nil
}

// validate checks one device entry. i is its position (for labels when Name is
// empty); the seen maps enforce process-wide uniqueness.
func (d *Device) validate(i int, seenNames map[string]bool, seenListen map[string]string, seenVMAC map[string]string) error {
	label := d.Name
	if label == "" {
		label = fmt.Sprintf("devices[%d]", i)
	}
	fail := func(format string, args ...any) error {
		return fmt.Errorf("config: device %q: %s", label, fmt.Sprintf(format, args...))
	}

	if d.ListenAddr == "" {
		return fail("listen_addr is required")
	}
	if d.DeviceAddr == "" {
		return fail("device_addr is required")
	}
	if err := validateHostPort("listen_addr", d.ListenAddr); err != nil {
		return fail("%s", err)
	}
	if err := validateHostPort("device_addr", d.DeviceAddr); err != nil {
		return fail("%s", err)
	}
	if d.DeviceLocalAddr != "" {
		if err := validateHostPort("device_local_addr", d.DeviceLocalAddr); err != nil {
			return fail("%s", err)
		}
	}
	if d.ListenAddr == d.DeviceAddr {
		return fail("listen_addr and device_addr are both %q; the proxy would forward to itself", d.ListenAddr)
	}
	if d.DeviceInstance != nil && *d.DeviceInstance > 1<<22-1 {
		return fail("device_instance %d exceeds the 22-bit BACnet instance space", *d.DeviceInstance)
	}
	if d.RequestTimeoutSecs < 1 || d.RequestTimeoutSecs > 600 {
		return fail("request_timeout_secs %d outside 1..600", d.RequestTimeoutSecs)
	}
	if d.MaxPending < 1 || d.MaxPending > 256 {
		return fail("max_pending %d outside 1..256 (the invoke ID is one octet)", d.MaxPending)
	}

	if d.Name != "" {
		if seenNames[d.Name] {
			return fail("name %q is already used by another device", d.Name)
		}
		seenNames[d.Name] = true
	}
	if prev, dup := seenListen[d.ListenAddr]; dup {
		return fail("listen_addr %q is already used by device %q", d.ListenAddr, prev)
	}
	seenListen[d.ListenAddr] = label

	if err := d.validateSC(label, seenVMAC); err != nil {
		return err
	}
	if _, err := d.AccessPolicy(); err != nil {
		return fail("%s", err)
	}
	return nil
}

// validateSC checks the BACnet/SC block. Every field is checked without a
// network: a VMAC or URL typo must fail `validate` instead of producing a node
// that reconnect-loops against a name it can never resolve. A VMAC may be used
// by only one device: two nodes cannot share one identity on a hub.
func (d *Device) validateSC(label string, seenVMAC map[string]string) error {
	s := d.SC
	if !s.Enabled() {
		return nil
	}
	fail := func(format string, args ...any) error {
		return fmt.Errorf("config: device %q: %s", label, fmt.Sprintf(format, args...))
	}
	if s.VMAC == "" {
		return fail("sc.vmac is required when the sc block is configured")
	}
	vmac, err := sc.ParseMAC(s.VMAC)
	if err != nil {
		return fail("sc.vmac: %v", err)
	}
	if vmac.IsZero() || vmac.IsBroadcast() {
		return fail("sc.vmac %q must be a unicast VMAC", s.VMAC)
	}
	key := vmac.String()
	if prev, dup := seenVMAC[key]; dup {
		return fail("sc.vmac %q is already used by device %q", s.VMAC, prev)
	}
	seenVMAC[key] = label
	if s.UUID == "" {
		return fail("sc.uuid is required when the sc block is configured")
	}
	if _, err := sc.ParseUUID(s.UUID); err != nil {
		return fail("sc.uuid: %v", err)
	}
	if len(s.Hubs) == 0 {
		return fail("sc.hubs needs at least one wss:// URL")
	}
	for _, raw := range s.Hubs {
		u, err := url.Parse(raw)
		if err != nil {
			return fail("sc.hubs %q: %v", raw, err)
		}
		if u.Scheme != "wss" || u.Host == "" {
			return fail("sc.hubs %q must be a wss:// URL", raw)
		}
	}
	if (s.CertFile == "") != (s.KeyFile == "") {
		return fail("sc.cert_file and sc.key_file must be set together")
	}
	return nil
}

// AccessPolicy compiles this device's access block into its runtime policy.
func (d *Device) AccessPolicy() (*access.Policy, error) {
	return d.Access.Policy()
}

// Policy compiles the access block into a runtime policy. Each device compiles
// its own, so one device's policy can never leak into another's data plane.
func (a *Access) Policy() (*access.Policy, error) {
	list, err := access.NewList(a.Allow)
	if err != nil {
		return nil, err
	}
	scList, err := access.NewMACList(a.SCAllow)
	if err != nil {
		return nil, err
	}
	limit := access.NewLimit(a.RatePerSec)
	budget := access.NewBudget(a.DeviceRatePerSec)

	var write *access.WritePolicy
	switch {
	case a.ReadOnly:
		if a.WritePolicy != nil {
			return nil, fmt.Errorf("access: read_only and write_policy are mutually exclusive")
		}
		write, err = access.NewWritePolicy(true, "", nil)
	case a.WritePolicy != nil:
		rules := make([]access.Rule, 0, len(a.WritePolicy.Rules))
		for _, r := range a.WritePolicy.Rules {
			rules = append(rules, access.Rule{Spec: r.OID, Action: access.Action(r.Action)})
		}
		write, err = access.NewWritePolicy(false, access.Action(a.WritePolicy.Default), rules)
	default:
		// No write configuration: writes pass. That is the documented
		// "policy not configured" state, not an implicit read-only proxy.
	}
	if err != nil {
		return nil, err
	}
	return access.NewPolicy(list, limit, write).WithSCAllow(scList).WithDeviceBudget(budget), nil
}

// DeviceObjectID returns the pinned device instance as an object id, if one
// is configured.
func (d *Device) DeviceObjectID() (bacnet.ObjectID, bool) {
	if d.DeviceInstance == nil {
		return bacnet.ObjectID{}, false
	}
	return bacnet.ObjectID{Type: bacnet.ObjectDevice, Instance: *d.DeviceInstance}, true
}

// validateHostPort checks a UDP or HTTP listener address. Both are a host
// (possibly empty = wildcard) and a numeric port.
func validateHostPort(field, addr string) error {
	if strings.TrimSpace(addr) == "" {
		return fmt.Errorf("%s is required", field)
	}
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("%s %q: %w", field, addr, err)
	}
	if port == "" {
		return fmt.Errorf("%s %q: missing port", field, addr)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("%s %q: bad port %q", field, addr, port)
	}
	// An empty host means the wildcard address.
	return nil
}
