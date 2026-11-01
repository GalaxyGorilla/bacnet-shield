package config

import (
	"strings"
	"testing"
	"time"

	"github.com/spf13/pflag"

	"github.com/GalaxyGorilla/bacnet-shield/internal/access"
	"github.com/GalaxyGorilla/bacnet-shield/internal/bacnet"
	"github.com/GalaxyGorilla/bacnet-shield/internal/bacnet/sc"
)

func decode(t *testing.T, yaml string) (*Config, error) {
	t.Helper()
	return Decode(strings.NewReader(yaml))
}

func TestDecodeDefaults(t *testing.T) {
	c, err := decode(t, "device_addr: 192.0.2.10:47808\n")
	if err != nil {
		t.Fatal(err)
	}
	if c.ListenAddr != ":47808" {
		t.Fatalf("listen_addr = %q", c.ListenAddr)
	}
	if c.RequestTimeoutSecs != 30 || c.MaxPending != 256 || c.LogLevel != "info" {
		t.Fatalf("defaults not applied: %+v", c)
	}
	if c.DeviceInstance != nil {
		t.Fatal("device_instance defaulted to a value")
	}
	pol, err := c.AccessPolicy()
	if err != nil {
		t.Fatal(err)
	}
	// No write configuration means "policy not configured", so writes pass.
	if !pol.AllowWrite(bacnet.APDU{Type: bacnet.PDUConfirmedRequest, HasService: true, Service: bacnet.ServiceWriteProperty}) {
		t.Fatal("unconfigured policy denied a write")
	}
}

func TestDecodeFull(t *testing.T) {
	c, err := decode(t, `
listen_addr: 0.0.0.0:47808
device_addr: 192.0.2.10:47808
device_local_addr: 192.0.2.1:47808
device_instance: 1001
request_timeout_secs: 12
max_pending: 64
log_level: debug
access:
  allow: ["10.0.0.0/8", "192.0.2.7"]
  rate_per_sec: 25
  write_policy:
    default: deny
    rules:
      - oid: "analog-value:5:present-value"
        action: allow
      - oid: "device:*:description"
        action: deny
metrics:
  addr: 127.0.0.1:9090
`)
	if err != nil {
		t.Fatal(err)
	}
	if c.DeviceInstance == nil || *c.DeviceInstance != 1001 {
		t.Fatalf("device_instance = %v", c.DeviceInstance)
	}
	if c.RequestTimeoutSecs != 12 || c.MaxPending != 64 || c.LogLevel != "debug" {
		t.Fatalf("config = %+v", c)
	}
	if len(c.Access.Allow) != 2 || c.Access.RatePerSec != 25 {
		t.Fatalf("access = %+v", c.Access)
	}
	if c.Access.WritePolicy == nil || len(c.Access.WritePolicy.Rules) != 2 {
		t.Fatalf("write policy = %+v", c.Access.WritePolicy)
	}
	if c.Metrics.Addr != "127.0.0.1:9090" {
		t.Fatalf("metrics = %+v", c.Metrics)
	}
}

func TestDecodeSC(t *testing.T) {
	c, err := decode(t, `
device_addr: 192.0.2.10:47808
sc:
  vmac: "02:00:00:00:00:01"
  uuid: "00112233-4455-6677-8899-aabbccddeeff"
  hubs:
    - wss://hub1.example:47808/
    - wss://hub2.example:47808/
  ca_file: /etc/bacnet-shield/hub-ca.pem
  cert_file: /etc/bacnet-shield/node.pem
  key_file: /etc/bacnet-shield/node.key
access:
  sc_allow: ["02:00:00:00:00:0a", "02:00:00:00:00:0b"]
`)
	if err != nil {
		t.Fatal(err)
	}
	if !c.SC.Enabled() {
		t.Fatal("SC block not recognized as enabled")
	}
	if c.SC.VMAC != "02:00:00:00:00:01" || len(c.SC.Hubs) != 2 {
		t.Fatalf("sc = %+v", c.SC)
	}
	if len(c.Access.SCAllow) != 2 {
		t.Fatalf("sc_allow = %v", c.Access.SCAllow)
	}
	pol, err := c.AccessPolicy()
	if err != nil {
		t.Fatal(err)
	}
	allowed, _ := sc.ParseMAC("02:00:00:00:00:0a")
	denied, _ := sc.ParseMAC("02:00:00:00:00:0c")
	if !polWithSC(t, pol, allowed) {
		t.Fatal("sc_allow entry did not admit its VMAC")
	}
	if polWithSC(t, pol, denied) {
		t.Fatal("sc_allow admitted an unlisted VMAC")
	}

	// An empty block leaves the SC leg off.
	off, err := decode(t, "device_addr: 192.0.2.10:47808\n")
	if err != nil {
		t.Fatal(err)
	}
	if off.SC.Enabled() {
		t.Fatal("empty sc block reported enabled")
	}
}

// polWithSC asks a compiled policy for an SC decision without depending on
// the access package's Decision type name in the config test.
func polWithSC(t *testing.T, pol *access.Policy, vmac sc.MAC) bool {
	t.Helper()
	return pol.CheckSC(vmac, time.Unix(0, 0)) == access.Allow
}

func TestDecodeUnknownKeyFails(t *testing.T) {
	// A misspelled read_only must not silently produce a writable proxy.
	if _, err := decode(t, "device_addr: 192.0.2.10:47808\naccess:\n  read_onyl: true\n"); err == nil {
		t.Fatal("unknown key accepted")
	}
}

func TestValidateRejections(t *testing.T) {
	cases := []struct {
		name string
		yaml string
	}{
		{"missing device", "listen_addr: :47808\n"},
		{"bad listen", "device_addr: 192.0.2.10:47808\nlisten_addr: nope\n"},
		{"same legs", "device_addr: :47808\nlisten_addr: :47808\n"},
		{"bad device port", "device_addr: 192.0.2.10:99999\n"},
		{"instance too large", "device_addr: 192.0.2.10:47808\ndevice_instance: 4194304\n"},
		{"timeout zero", "device_addr: 192.0.2.10:47808\nrequest_timeout_secs: 0\n"},
		{"timeout huge", "device_addr: 192.0.2.10:47808\nrequest_timeout_secs: 601\n"},
		{"max pending zero", "device_addr: 192.0.2.10:47808\nmax_pending: 0\n"},
		{"max pending over 256", "device_addr: 192.0.2.10:47808\nmax_pending: 257\n"},
		{"bad log level", "device_addr: 192.0.2.10:47808\nlog_level: loud\n"},
		{"bad metrics addr", "device_addr: 192.0.2.10:47808\nmetrics:\n  addr: nope\n"},
		{"read only and write policy", "device_addr: 192.0.2.10:47808\naccess:\n  read_only: true\n  write_policy:\n    default: deny\n"},
		{"write policy without default", "device_addr: 192.0.2.10:47808\naccess:\n  write_policy:\n    rules:\n      - {oid: \"*\", action: allow}\n"},
		{"write policy bad default", "device_addr: 192.0.2.10:47808\naccess:\n  write_policy:\n    default: maybe\n"},
		{"bad allow entry", "device_addr: 192.0.2.10:47808\naccess:\n  allow: [\"not-an-ip\"]\n"},
		{"bad rule", "device_addr: 192.0.2.10:47808\naccess:\n  write_policy:\n    default: deny\n    rules:\n      - {oid: \"nope\", action: allow}\n"},
		{"sc missing uuid", "device_addr: 192.0.2.10:47808\nsc:\n  vmac: \"02:00:00:00:00:01\"\n  hubs: [wss://hub/]\n"},
		{"sc missing hubs", "device_addr: 192.0.2.10:47808\nsc:\n  vmac: \"02:00:00:00:00:01\"\n  uuid: \"00112233-4455-6677-8899-aabbccddeeff\"\n"},
		{"sc zero vmac", "device_addr: 192.0.2.10:47808\nsc:\n  vmac: \"00:00:00:00:00:00\"\n  uuid: \"00112233-4455-6677-8899-aabbccddeeff\"\n  hubs: [wss://hub/]\n"},
		{"sc broadcast vmac", "device_addr: 192.0.2.10:47808\nsc:\n  vmac: \"ff:ff:ff:ff:ff:ff\"\n  uuid: \"00112233-4455-6677-8899-aabbccddeeff\"\n  hubs: [wss://hub/]\n"},
		{"sc bad vmac", "device_addr: 192.0.2.10:47808\nsc:\n  vmac: \"not-a-mac\"\n  uuid: \"00112233-4455-6677-8899-aabbccddeeff\"\n  hubs: [wss://hub/]\n"},
		{"sc bad uuid", "device_addr: 192.0.2.10:47808\nsc:\n  vmac: \"02:00:00:00:00:01\"\n  uuid: \"nope\"\n  hubs: [wss://hub/]\n"},
		{"sc insecure hub", "device_addr: 192.0.2.10:47808\nsc:\n  vmac: \"02:00:00:00:00:01\"\n  uuid: \"00112233-4455-6677-8899-aabbccddeeff\"\n  hubs: [ws://hub/]\n"},
		{"sc bad hub scheme", "device_addr: 192.0.2.10:47808\nsc:\n  vmac: \"02:00:00:00:00:01\"\n  uuid: \"00112233-4455-6677-8899-aabbccddeeff\"\n  hubs: [https://hub/]\n"},
		{"sc cert without key", "device_addr: 192.0.2.10:47808\nsc:\n  vmac: \"02:00:00:00:00:01\"\n  uuid: \"00112233-4455-6677-8899-aabbccddeeff\"\n  hubs: [wss://hub/]\n  cert_file: /tmp/node.pem\n"},
		{"sc key without cert", "device_addr: 192.0.2.10:47808\nsc:\n  vmac: \"02:00:00:00:00:01\"\n  uuid: \"00112233-4455-6677-8899-aabbccddeeff\"\n  hubs: [wss://hub/]\n  key_file: /tmp/node.key\n"},
		{"sc bad allow entry", "device_addr: 192.0.2.10:47808\naccess:\n  sc_allow: [\"not-a-mac\"]\n"},
	}
	for _, c := range cases {
		if _, err := decode(t, c.yaml); err == nil {
			t.Fatalf("%s: accepted", c.name)
		}
	}
}

func TestFlagsBuild(t *testing.T) {
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	o := Register(fs)
	err := fs.Parse([]string{
		"--listen", ":47808",
		"--device", "192.0.2.10:47808",
		"--device-instance", "1001",
		"--request-timeout", "9",
		"--max-pending", "32",
		"--allow", "10.0.0.0/8",
		"--allow", "192.0.2.7",
		"--rate-per-sec", "12.5",
		"--write-default", "deny",
		"--write-allow", "analog-value:5:present-value",
		"--write-deny", "device:*:description",
		"--sc-vmac", "02:00:00:00:00:01",
		"--sc-uuid", "00112233-4455-6677-8899-aabbccddeeff",
		"--sc-hub", "wss://hub1.example/",
		"--sc-hub", "wss://hub2.example/",
		"--sc-ca", "/tmp/hub-ca.pem",
		"--sc-allow", "02:00:00:00:00:0a",
		"--metrics-addr", "127.0.0.1:9090",
		"--log-level", "warn",
	})
	if err != nil {
		t.Fatal(err)
	}
	c, err := o.Build()
	if err != nil {
		t.Fatal(err)
	}
	if c.DeviceAddr != "192.0.2.10:47808" || c.DeviceInstance == nil || *c.DeviceInstance != 1001 {
		t.Fatalf("config = %+v", c)
	}
	if c.RequestTimeoutSecs != 9 || c.MaxPending != 32 || c.LogLevel != "warn" {
		t.Fatalf("config = %+v", c)
	}
	if len(c.Access.Allow) != 2 || c.Access.RatePerSec != 12.5 {
		t.Fatalf("access = %+v", c.Access)
	}
	if c.Access.WritePolicy == nil || len(c.Access.WritePolicy.Rules) != 2 ||
		c.Access.WritePolicy.Rules[0].Action != "allow" || c.Access.WritePolicy.Rules[1].Action != "deny" {
		t.Fatalf("write policy = %+v", c.Access.WritePolicy)
	}
	if !c.SC.Enabled() || c.SC.VMAC != "02:00:00:00:00:01" ||
		len(c.SC.Hubs) != 2 || c.SC.CAFile != "/tmp/hub-ca.pem" {
		t.Fatalf("sc = %+v", c.SC)
	}
	if len(c.Access.SCAllow) != 1 {
		t.Fatalf("sc_allow = %v", c.Access.SCAllow)
	}
}

func TestFlagsBuildRejections(t *testing.T) {
	cases := [][]string{
		{"--listen", ":47808", "--device", ":47808"},
		{"--listen", ":47808", "--device", "192.0.2.10:47808", "--write-allow", "*"},
		{"--listen", ":47808", "--device", "192.0.2.10:47808", "--read-only", "--write-default", "deny"},
		{"--listen", ":47808", "--device", "192.0.2.10:47808", "--device-instance", "4194304"},
	}
	for _, args := range cases {
		fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
		o := Register(fs)
		if err := fs.Parse(args); err != nil {
			t.Fatalf("%v: parse: %v", args, err)
		}
		if _, err := o.Build(); err == nil {
			t.Fatalf("%v: accepted", args)
		}
	}
}

func TestAccessPolicySemantics(t *testing.T) {
	c, err := decode(t, `
device_addr: 192.0.2.10:47808
access:
  read_only: true
`)
	if err != nil {
		t.Fatal(err)
	}
	pol, err := c.AccessPolicy()
	if err != nil {
		t.Fatal(err)
	}
	w := bacnet.APDU{Type: bacnet.PDUConfirmedRequest, HasService: true, Service: bacnet.ServiceWriteProperty,
		Payload: mustHex(t, "0c0080000519553e443f8000003f")}
	if pol.AllowWrite(w) {
		t.Fatal("read_only policy allowed a write")
	}

	c, err = decode(t, `
device_addr: 192.0.2.10:47808
access:
  write_policy:
    default: deny
    rules:
      - {oid: "analog-value:5:present-value", action: allow}
`)
	if err != nil {
		t.Fatal(err)
	}
	pol, err = c.AccessPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if !pol.AllowWrite(w) {
		t.Fatal("allow rule did not authorize the write")
	}
	other := bacnet.APDU{Type: bacnet.PDUConfirmedRequest, HasService: true, Service: bacnet.ServiceWriteProperty,
		Payload: mustHex(t, "0c0080000619553e443f8000003f")}
	if pol.AllowWrite(other) {
		t.Fatal("allow rule authorized another instance")
	}
}

func TestDeviceObjectID(t *testing.T) {
	c, err := decode(t, "device_addr: 192.0.2.10:47808\ndevice_instance: 1001\n")
	if err != nil {
		t.Fatal(err)
	}
	oid, ok := c.DeviceObjectID()
	if !ok || oid.Type != bacnet.ObjectDevice || oid.Instance != 1001 {
		t.Fatalf("object id = %v, %v", oid, ok)
	}
	if _, ok := Defaults().DeviceObjectID(); ok {
		t.Fatal("unset instance produced an object id")
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b := make([]byte, len(s)/2)
	for i := range b {
		var v byte
		for j := 0; j < 2; j++ {
			c := s[i*2+j]
			switch {
			case c >= '0' && c <= '9':
				v = v<<4 | (c - '0')
			case c >= 'a' && c <= 'f':
				v = v<<4 | (c - 'a' + 10)
			case c >= 'A' && c <= 'F':
				v = v<<4 | (c - 'A' + 10)
			default:
				t.Fatalf("bad hex %q", s)
			}
		}
		b[i] = v
	}
	return b
}
