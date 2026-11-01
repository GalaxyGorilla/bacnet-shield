package config

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/GalaxyGorilla/bacnet-shield/internal/access"
	"github.com/GalaxyGorilla/bacnet-shield/internal/bacnet"
)

// Config is one gateway instance. Roles are subcommands, not config fields:
// v1 has a single role, and inventing a role key before a second role exists
// would be a promise the code cannot keep.
type Config struct {
	// ListenAddr is the client leg: the address managers/BMS workstations
	// send BACnet/IP to. Usually ":47808".
	ListenAddr string `yaml:"listen_addr"`
	// DeviceAddr is the legacy device (or device subnet broadcast address)
	// on the clear leg.
	DeviceAddr string `yaml:"device_addr"`
	// DeviceLocalAddr is the optional source address of the device leg.
	// Empty means an ephemeral port, which is what a BACnet client does.
	DeviceLocalAddr string `yaml:"device_local_addr"`
	// DeviceInstance optionally pins the expected device instance. It is
	// used to warn about a mismatched I-Am and by selftest; it never gates
	// traffic (the proxy forwards what the device says).
	DeviceInstance *uint32 `yaml:"device_instance"`

	// RequestTimeoutSecs bounds how long a forwarded request may stay
	// pending before its invoke ID is reclaimed.
	RequestTimeoutSecs int `yaml:"request_timeout_secs"`
	// MaxPending caps in-flight requests. The BACnet invoke ID is one octet,
	// so the hard maximum is 256.
	MaxPending int `yaml:"max_pending"`

	LogLevel string  `yaml:"log_level"`
	Access   Access  `yaml:"access"`
	Metrics  Metrics `yaml:"metrics"`
}

// Access is the front-leg policy block. The key names mirror the other
// Shield projects so one policy vocabulary covers the appliance family.
type Access struct {
	Allow       []string     `yaml:"allow"`
	RatePerSec  float64      `yaml:"rate_per_sec"`
	ReadOnly    bool         `yaml:"read_only"`
	WritePolicy *WritePolicy `yaml:"write_policy"`
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

// Defaults returns the values used for every field a config file or flag
// does not set.
func Defaults() *Config {
	return &Config{
		ListenAddr:         ":47808",
		RequestTimeoutSecs: 30,
		MaxPending:         256,
		LogLevel:           "info",
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
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

// Validate checks every field that can be checked without touching the
// network. AccessPolicy is compiled here too, so validation and runtime can
// never disagree about what a policy means.
func (c *Config) Validate() error {
	if err := validateHostPort("listen_addr", c.ListenAddr); err != nil {
		return err
	}
	if err := validateHostPort("device_addr", c.DeviceAddr); err != nil {
		return err
	}
	if c.DeviceLocalAddr != "" {
		if err := validateHostPort("device_local_addr", c.DeviceLocalAddr); err != nil {
			return err
		}
	}
	if c.ListenAddr == c.DeviceAddr {
		return fmt.Errorf("config: listen_addr and device_addr are both %q; the proxy would forward to itself", c.ListenAddr)
	}
	if c.DeviceInstance != nil && *c.DeviceInstance > 1<<22-1 {
		return fmt.Errorf("config: device_instance %d exceeds the 22-bit BACnet instance space", *c.DeviceInstance)
	}
	if c.RequestTimeoutSecs < 1 || c.RequestTimeoutSecs > 600 {
		return fmt.Errorf("config: request_timeout_secs %d outside 1..600", c.RequestTimeoutSecs)
	}
	if c.MaxPending < 1 || c.MaxPending > 256 {
		return fmt.Errorf("config: max_pending %d outside 1..256 (the invoke ID is one octet)", c.MaxPending)
	}
	switch c.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("config: log_level %q (want debug|info|warn|error)", c.LogLevel)
	}
	if c.Metrics.Addr != "" {
		if err := validateHostPort("metrics.addr", c.Metrics.Addr); err != nil {
			return err
		}
	}
	if _, err := c.AccessPolicy(); err != nil {
		return err
	}
	return nil
}

// AccessPolicy compiles the access block into the runtime policy.
func (c *Config) AccessPolicy() (*access.Policy, error) {
	list, err := access.NewList(c.Access.Allow)
	if err != nil {
		return nil, err
	}
	limit := access.NewLimit(c.Access.RatePerSec)

	var write *access.WritePolicy
	switch {
	case c.Access.ReadOnly:
		if c.Access.WritePolicy != nil {
			return nil, fmt.Errorf("access: read_only and write_policy are mutually exclusive")
		}
		write, err = access.NewWritePolicy(true, "", nil)
	case c.Access.WritePolicy != nil:
		rules := make([]access.Rule, 0, len(c.Access.WritePolicy.Rules))
		for _, r := range c.Access.WritePolicy.Rules {
			rules = append(rules, access.Rule{Spec: r.OID, Action: access.Action(r.Action)})
		}
		write, err = access.NewWritePolicy(false, access.Action(c.Access.WritePolicy.Default), rules)
	default:
		// No write configuration: writes pass. That is the documented
		// "policy not configured" state, not an implicit read-only proxy.
	}
	if err != nil {
		return nil, err
	}
	return access.NewPolicy(list, limit, write), nil
}

// DeviceObjectID returns the pinned device instance as an object id, if one
// is configured.
func (c *Config) DeviceObjectID() (bacnet.ObjectID, bool) {
	if c.DeviceInstance == nil {
		return bacnet.ObjectID{}, false
	}
	return bacnet.ObjectID{Type: bacnet.ObjectDevice, Instance: *c.DeviceInstance}, true
}

// validateHostPort checks a UDP or HTTP listener address. Both are a host
// (possibly empty = wildcard) and a numeric port.
func validateHostPort(field, addr string) error {
	if strings.TrimSpace(addr) == "" {
		return fmt.Errorf("config: %s is required", field)
	}
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("config: %s %q: %w", field, addr, err)
	}
	if port == "" {
		return fmt.Errorf("config: %s %q: missing port", field, addr)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("config: %s %q: bad port %q", field, addr, port)
	}
	// An empty host means the wildcard address.
	return nil
}
