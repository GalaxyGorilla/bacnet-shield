package config

import (
	"net"
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

// oneDevice wraps a single device entry in the devices: list the multi-device
// config now uses, so the field-level rejection cases stay one entry. The
// first line becomes the list item and every following line is shifted under
// it, preserving the block's own indentation. A listen_addr is injected when
// the entry does not set one, so a case that means to test another field is
// not rejected for a missing listener first.
func oneDevice(entry string) string {
	entry = strings.TrimRight(entry, "\n")
	if !strings.Contains(entry, "listen_addr:") {
		entry = "listen_addr: 127.0.0.1:47808\n" + entry
	}
	var b strings.Builder
	b.WriteString("devices:\n")
	for i, line := range strings.Split(entry, "\n") {
		if i == 0 {
			b.WriteString("  - " + line + "\n")
			continue
		}
		b.WriteString("    " + line + "\n")
	}
	return b.String()
}

func TestDecodeDefaults(t *testing.T) {
	c, err := decode(t, oneDevice("device_addr: 192.0.2.10:47808\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Devices) != 1 {
		t.Fatalf("devices = %d", len(c.Devices))
	}
	d := c.Devices[0]
	if d.ListenAddr != "127.0.0.1:47808" {
		t.Fatalf("listen_addr = %q", d.ListenAddr)
	}
	if d.RequestTimeoutSecs != 30 || d.MaxPending != 256 || c.LogLevel != "info" {
		t.Fatalf("defaults not applied: %+v", c)
	}
	if d.DeviceInstance != nil {
		t.Fatal("device_instance defaulted to a value")
	}
	// An omitted name falls back to the device address, so every log, metric
	// and audit record can name the device.
	if d.Name != "192.0.2.10:47808" {
		t.Fatalf("name = %q", d.Name)
	}
	pol, err := d.AccessPolicy()
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
devices:
  - name: boiler
    listen_addr: 0.0.0.0:47808
    device_addr: 192.0.2.10:47808
    device_local_addr: 192.0.2.1:47808
    device_instance: 1001
    request_timeout_secs: 12
    max_pending: 64
    access:
      allow: ["10.0.0.0/8", "192.0.2.7"]
      rate_per_sec: 25
      device_rate_per_sec: 20
      write_policy:
        default: deny
        rules:
          - oid: "analog-value:5:present-value"
            action: allow
          - oid: "device:*:description"
            action: deny
log_level: debug
metrics:
  addr: 127.0.0.1:9090
audit:
  file: /var/log/bacnet-shield/audit.jsonl
  max_mb: 32
`)
	if err != nil {
		t.Fatal(err)
	}
	d := c.Devices[0]
	if d.Name != "boiler" {
		t.Fatalf("name = %q", d.Name)
	}
	if d.DeviceInstance == nil || *d.DeviceInstance != 1001 {
		t.Fatalf("device_instance = %v", d.DeviceInstance)
	}
	if d.RequestTimeoutSecs != 12 || d.MaxPending != 64 || c.LogLevel != "debug" {
		t.Fatalf("config = %+v", c)
	}
	if len(d.Access.Allow) != 2 || d.Access.RatePerSec != 25 || d.Access.DeviceRatePerSec != 20 {
		t.Fatalf("access = %+v", d.Access)
	}
	if d.Access.WritePolicy == nil || len(d.Access.WritePolicy.Rules) != 2 {
		t.Fatalf("write policy = %+v", d.Access.WritePolicy)
	}
	if c.Metrics.Addr != "127.0.0.1:9090" {
		t.Fatalf("metrics = %+v", c.Metrics)
	}
	if c.Audit.File != "/var/log/bacnet-shield/audit.jsonl" || c.Audit.MaxMB != 32 {
		t.Fatalf("audit = %+v", c.Audit)
	}
}

// TestDecodeMultipleDevices: two co-hosted devices each carry their own policy
// and SC identity, and one device's policy never leaks into the other's.
func TestDecodeMultipleDevices(t *testing.T) {
	c, err := decode(t, `
devices:
  - name: boiler
    listen_addr: 192.0.2.10:47808
    device_addr: 10.0.0.42:47808
    access:
      read_only: true
  - name: ahu
    listen_addr: 192.0.2.11:47808
    device_addr: 10.0.0.43:47808
    access:
      allow: ["192.0.2.0/24"]
      write_policy:
        default: deny
        rules:
          - {oid: "analog-value:1:present-value", action: allow}
    sc:
      vmac: "02:00:00:00:00:02"
      uuid: "00112233-4455-6677-8899-aabbccddeeff"
      hubs: [wss://hub.example/]
`)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Devices) != 2 {
		t.Fatalf("devices = %d", len(c.Devices))
	}

	boiler := &c.Devices[0]
	ahu := &c.Devices[1]

	bp, err := boiler.AccessPolicy()
	if err != nil {
		t.Fatal(err)
	}
	w := bacnet.APDU{Type: bacnet.PDUConfirmedRequest, HasService: true, Service: bacnet.ServiceWriteProperty}
	if bp.AllowWrite(w) {
		t.Fatal("boiler is read-only but allowed a write")
	}

	// The ahu's allow must not have leaked into the boiler's policy, and vice
	// versa: the ahu is not read-only.
	if len(ahu.Access.Allow) != 1 || ahu.Access.ReadOnly {
		t.Fatalf("ahu access = %+v", ahu.Access)
	}
	if !ahu.SC.Enabled() || ahu.SC.VMAC != "02:00:00:00:00:02" {
		t.Fatalf("ahu sc = %+v", ahu.SC)
	}
	if boiler.SC.Enabled() {
		t.Fatal("boiler inherited an SC block")
	}
}

func TestDecodeSC(t *testing.T) {
	c, err := decode(t, `
devices:
  - listen_addr: 127.0.0.1:47808
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
	d := &c.Devices[0]
	if !d.SC.Enabled() {
		t.Fatal("SC block not recognized as enabled")
	}
	if d.SC.VMAC != "02:00:00:00:00:01" || len(d.SC.Hubs) != 2 {
		t.Fatalf("sc = %+v", d.SC)
	}
	if len(d.Access.SCAllow) != 2 {
		t.Fatalf("sc_allow = %v", d.Access.SCAllow)
	}
	pol, err := d.AccessPolicy()
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
	off, err := decode(t, oneDevice("device_addr: 192.0.2.10:47808\n"))
	if err != nil {
		t.Fatal(err)
	}
	if off.Devices[0].SC.Enabled() {
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
	if _, err := decode(t, oneDevice("device_addr: 192.0.2.10:47808\naccess:\n  read_onyl: true\n")); err == nil {
		t.Fatal("unknown key accepted")
	}
	// A misspelled device key must fail too, now that devices are entries.
	if _, err := decode(t, "devices:\n  - device_addr: 192.0.2.10:47808\n    device_addrx: x\n"); err == nil {
		t.Fatal("unknown device key accepted")
	}
}

func TestValidateIPv6FrontLeg(t *testing.T) {
	// The front leg may be IPv6 while the device leg stays IPv4; that is one
	// supported mixed shape.
	c, err := decode(t, oneDevice("listen_addr: \"[::1]:47808\"\ndevice_addr: 192.0.2.10:47808\n"))
	if err != nil {
		t.Fatalf("IPv6 front leg rejected: %v", err)
	}
	if got := c.Devices[0].ListenAddr; got != "[::1]:47808" {
		t.Fatalf("listen_addr = %q", got)
	}
}

func TestExtraListenParsing(t *testing.T) {
	c, err := decode(t, oneDevice("device_addr: 192.0.2.10:47808\nextra_listen: [\"192.0.2.11:47808\", \"[::1]:47808\"]\n"))
	if err != nil {
		t.Fatalf("extra_listen rejected: %v", err)
	}
	got := c.Devices[0].ExtraListen
	if len(got) != 2 || got[0] != "192.0.2.11:47808" || got[1] != "[::1]:47808" {
		t.Fatalf("extra_listen = %v", got)
	}
}

func TestExtraListenRejections(t *testing.T) {
	cases := []struct {
		name string
		yaml string
	}{
		{"duplicate primary", oneDevice("device_addr: 192.0.2.10:47808\nextra_listen: [\"127.0.0.1:47808\"]\n")},
		{"duplicate extra", oneDevice("device_addr: 192.0.2.10:47808\nextra_listen: [\"192.0.2.11:47808\", \"192.0.2.11:47808\"]\n")},
		{"device address", oneDevice("device_addr: 192.0.2.10:47808\nextra_listen: [\"192.0.2.10:47808\"]\n")},
		{"bad address", oneDevice("device_addr: 192.0.2.10:47808\nextra_listen: [\"nope\"]\n")},
	}
	for _, tc := range cases {
		if _, err := decode(t, tc.yaml); err == nil {
			t.Errorf("%s: accepted", tc.name)
		}
	}
}

func TestValidateIPv6Combinations(t *testing.T) {
	sc := "sc:\n  vmac: \"02:00:00:00:00:01\"\n  uuid: \"00112233-4455-6677-8899-aabbccddeeff\"\n  hubs: [wss://hub/]\n"
	cases := []string{
		oneDevice("listen_addr: \"[::]:47808\"\ndevice_addr: \"[2001:db8:20::42]:47808\"\ndevice_local_addr: \"[2001:db8:20::2]:47809\"\n"),
		oneDevice("listen_addr: 192.0.2.10:47808\ndevice_addr: \"[2001:db8:20::42]:47808\"\nextra_listen: [\"[::1]:47808\"]\n"),
		oneDevice("listen_addr: \"[::]:47808\"\ndevice_addr: 192.0.2.10:47808\n" + sc),
	}
	for _, entry := range cases {
		if _, err := decode(t, entry); err != nil {
			t.Fatalf("valid IPv6 combination rejected: %v\n%s", err, entry)
		}
	}

	dup := "devices:\n" +
		"  - {name: a, listen_addr: \"[::1]:47808\", device_addr: 10.0.0.1:47808}\n" +
		"  - {name: b, listen_addr: \"[::1]:47808\", device_addr: 10.0.0.2:47808}\n"
	if _, err := decode(t, dup); err == nil {
		t.Fatal("duplicate IPv6 listen address accepted")
	}
}

func TestValidateIPv6DeviceLeg(t *testing.T) {
	// The other mixed shape: an IPv4 (or IPv6) front leg in front of an IPv6
	// device.
	for _, entry := range []string{
		"listen_addr: 192.0.2.10:47808\ndevice_addr: \"[::1]:47808\"\n",
		"listen_addr: \"[::1]:47808\"\ndevice_addr: \"[::1]:47809\"\n",
	} {
		c, err := decode(t, oneDevice(entry))
		if err != nil {
			t.Fatalf("%q rejected: %v", entry, err)
		}
		if got := c.Devices[0].DeviceAddr; got != "[::1]:47808" && got != "[::1]:47809" {
			t.Fatalf("device_addr = %q", got)
		}
	}
}

func TestValidateRejections(t *testing.T) {
	cases := []struct {
		name string
		yaml string
	}{
		{"no devices", "log_level: info\n"},
		{"empty devices list", "devices: []\n"},
		{"missing device addr", oneDevice("listen_addr: :47808\n")},
		{"missing listen", oneDevice("device_addr: 192.0.2.10:47808\nlisten_addr: \"\"\n")},
		{"bad listen", oneDevice("device_addr: 192.0.2.10:47808\nlisten_addr: nope\n")},
		{"same legs", oneDevice("device_addr: :47808\nlisten_addr: :47808\n")},
		{"bad device port", oneDevice("device_addr: 192.0.2.10:99999\n")},
		{"mixed device families", oneDevice("device_addr: \"[::1]:47808\"\ndevice_local_addr: 192.0.2.1:47808\n")},
		{"mixed device families reverse", oneDevice("device_addr: 192.0.2.10:47808\ndevice_local_addr: \"[::1]:47808\"\n")},
		{"instance too large", oneDevice("device_addr: 192.0.2.10:47808\ndevice_instance: 4194304\n")},
		{"timeout zero", oneDevice("device_addr: 192.0.2.10:47808\nrequest_timeout_secs: -1\n")},
		{"timeout huge", oneDevice("device_addr: 192.0.2.10:47808\nrequest_timeout_secs: 601\n")},
		{"max pending over 256", oneDevice("device_addr: 192.0.2.10:47808\nmax_pending: 257\n")},
		{"bad log level", oneDevice("device_addr: 192.0.2.10:47808\n") + "log_level: loud\n"},
		{"bad metrics addr", oneDevice("device_addr: 192.0.2.10:47808\n") + "metrics:\n  addr: nope\n"},
		{"audit max_mb zero", oneDevice("device_addr: 192.0.2.10:47808\n") + "audit:\n  file: /tmp/a.log\n  max_mb: 0\n"},
		{"audit max_mb huge", oneDevice("device_addr: 192.0.2.10:47808\n") + "audit:\n  max_mb: 20000\n"},
		{"read only and write policy", oneDevice("device_addr: 192.0.2.10:47808\naccess:\n  read_only: true\n  write_policy:\n    default: deny\n")},
		{"write policy without default", oneDevice("device_addr: 192.0.2.10:47808\naccess:\n  write_policy:\n    rules:\n      - {oid: \"*\", action: allow}\n")},
		{"write policy bad default", oneDevice("device_addr: 192.0.2.10:47808\naccess:\n  write_policy:\n    default: maybe\n")},
		{"bad allow entry", oneDevice("device_addr: 192.0.2.10:47808\naccess:\n  allow: [\"not-an-ip\"]\n")},
		{"bad rule", oneDevice("device_addr: 192.0.2.10:47808\naccess:\n  write_policy:\n    default: deny\n    rules:\n      - {oid: \"nope\", action: allow}\n")},
		{"sc missing uuid", oneDevice("device_addr: 192.0.2.10:47808\nsc:\n  vmac: \"02:00:00:00:00:01\"\n  hubs: [wss://hub/]\n")},
		{"sc missing hubs", oneDevice("device_addr: 192.0.2.10:47808\nsc:\n  vmac: \"02:00:00:00:00:01\"\n  uuid: \"00112233-4455-6677-8899-aabbccddeeff\"\n")},
		{"sc zero vmac", oneDevice("device_addr: 192.0.2.10:47808\nsc:\n  vmac: \"00:00:00:00:00:00\"\n  uuid: \"00112233-4455-6677-8899-aabbccddeeff\"\n  hubs: [wss://hub/]\n")},
		{"sc broadcast vmac", oneDevice("device_addr: 192.0.2.10:47808\nsc:\n  vmac: \"ff:ff:ff:ff:ff:ff\"\n  uuid: \"00112233-4455-6677-8899-aabbccddeeff\"\n  hubs: [wss://hub/]\n")},
		{"sc bad vmac", oneDevice("device_addr: 192.0.2.10:47808\nsc:\n  vmac: \"not-a-mac\"\n  uuid: \"00112233-4455-6677-8899-aabbccddeeff\"\n  hubs: [wss://hub/]\n")},
		{"sc bad uuid", oneDevice("device_addr: 192.0.2.10:47808\nsc:\n  vmac: \"02:00:00:00:00:01\"\n  uuid: \"nope\"\n  hubs: [wss://hub/]\n")},
		{"sc insecure hub", oneDevice("device_addr: 192.0.2.10:47808\nsc:\n  vmac: \"02:00:00:00:00:01\"\n  uuid: \"00112233-4455-6677-8899-aabbccddeeff\"\n  hubs: [ws://hub/]\n")},
		{"sc bad hub scheme", oneDevice("device_addr: 192.0.2.10:47808\nsc:\n  vmac: \"02:00:00:00:00:01\"\n  uuid: \"00112233-4455-6677-8899-aabbccddeeff\"\n  hubs: [https://hub/]\n")},
		{"sc cert without key", oneDevice("device_addr: 192.0.2.10:47808\nsc:\n  vmac: \"02:00:00:00:00:01\"\n  uuid: \"00112233-4455-6677-8899-aabbccddeeff\"\n  hubs: [wss://hub/]\n  cert_file: /tmp/node.pem\n")},
		{"sc key without cert", oneDevice("device_addr: 192.0.2.10:47808\nsc:\n  vmac: \"02:00:00:00:00:01\"\n  uuid: \"00112233-4455-6677-8899-aabbccddeeff\"\n  hubs: [wss://hub/]\n  key_file: /tmp/node.key\n")},
		{"sc bad allow entry", oneDevice("device_addr: 192.0.2.10:47808\naccess:\n  sc_allow: [\"not-a-mac\"]\n")},
		{"duplicate listen", "devices:\n  - {name: a, listen_addr: 192.0.2.10:47808, device_addr: 10.0.0.1:47808}\n  - {name: b, listen_addr: 192.0.2.10:47808, device_addr: 10.0.0.2:47808}\n"},
		{"duplicate name", "devices:\n  - {name: a, listen_addr: 192.0.2.10:47808, device_addr: 10.0.0.1:47808}\n  - {name: a, listen_addr: 192.0.2.11:47808, device_addr: 10.0.0.2:47808}\n"},
		{"duplicate vmac", "devices:\n  - {name: a, listen_addr: 192.0.2.10:47808, device_addr: 10.0.0.1:47808, sc: {vmac: \"02:00:00:00:00:01\", uuid: \"00112233-4455-6677-8899-aabbccddeeff\", hubs: [wss://hub/]}}\n  - {name: b, listen_addr: 192.0.2.11:47808, device_addr: 10.0.0.2:47808, sc: {vmac: \"02:00:00:00:00:01\", uuid: \"00112233-4455-6677-8899-aabbccddeeff\", hubs: [wss://hub/]}}\n"},
		{"duplicate vmac case-insensitive", "devices:\n  - {name: a, listen_addr: 192.0.2.10:47808, device_addr: 10.0.0.1:47808, sc: {vmac: \"02:00:00:00:00:0A\", uuid: \"00112233-4455-6677-8899-aabbccddeeff\", hubs: [wss://hub/]}}\n  - {name: b, listen_addr: 192.0.2.11:47808, device_addr: 10.0.0.2:47808, sc: {vmac: \"02:00:00:00:00:0a\", uuid: \"00112233-4455-6677-8899-aabbccddeeff\", hubs: [wss://hub/]}}\n"},
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
		"--device-rate-per-sec", "8",
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
		"--audit-file", "/tmp/audit.jsonl",
		"--audit-max-mb", "16",
		"--log-level", "warn",
	})
	if err != nil {
		t.Fatal(err)
	}
	c, err := o.Build()
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Devices) != 1 {
		t.Fatalf("flags mode built %d devices", len(c.Devices))
	}
	d := c.Devices[0]
	if d.DeviceAddr != "192.0.2.10:47808" || d.DeviceInstance == nil || *d.DeviceInstance != 1001 {
		t.Fatalf("device = %+v", d)
	}
	if d.Name != "192.0.2.10:47808" {
		t.Fatalf("flags device name = %q", d.Name)
	}
	if d.RequestTimeoutSecs != 9 || d.MaxPending != 32 || c.LogLevel != "warn" {
		t.Fatalf("config = %+v", c)
	}
	if len(d.Access.Allow) != 2 || d.Access.RatePerSec != 12.5 || d.Access.DeviceRatePerSec != 8 {
		t.Fatalf("access = %+v", d.Access)
	}
	if d.Access.WritePolicy == nil || len(d.Access.WritePolicy.Rules) != 2 ||
		d.Access.WritePolicy.Rules[0].Action != "allow" || d.Access.WritePolicy.Rules[1].Action != "deny" {
		t.Fatalf("write policy = %+v", d.Access.WritePolicy)
	}
	if !d.SC.Enabled() || d.SC.VMAC != "02:00:00:00:00:01" ||
		len(d.SC.Hubs) != 2 || d.SC.CAFile != "/tmp/hub-ca.pem" {
		t.Fatalf("sc = %+v", d.SC)
	}
	if len(d.Access.SCAllow) != 1 {
		t.Fatalf("sc_allow = %v", d.Access.SCAllow)
	}
	if c.Audit.File != "/tmp/audit.jsonl" || c.Audit.MaxMB != 16 {
		t.Fatalf("audit = %+v", c.Audit)
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
	c, err := decode(t, oneDevice("device_addr: 192.0.2.10:47808\naccess:\n  read_only: true\n"))
	if err != nil {
		t.Fatal(err)
	}
	pol, err := c.Devices[0].AccessPolicy()
	if err != nil {
		t.Fatal(err)
	}
	w := bacnet.APDU{Type: bacnet.PDUConfirmedRequest, HasService: true, Service: bacnet.ServiceWriteProperty,
		Payload: mustHex(t, "0c0080000519553e443f8000003f")}
	if pol.AllowWrite(w) {
		t.Fatal("read_only policy allowed a write")
	}

	c, err = decode(t, oneDevice("device_addr: 192.0.2.10:47808\naccess:\n  write_policy:\n    default: deny\n    rules:\n      - {oid: \"analog-value:5:present-value\", action: allow}\n"))
	if err != nil {
		t.Fatal(err)
	}
	pol, err = c.Devices[0].AccessPolicy()
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

func TestAccessPolicyDeviceBudget(t *testing.T) {
	c, err := decode(t, oneDevice("device_addr: 192.0.2.10:47808\naccess:\n  device_rate_per_sec: 1\n"))
	if err != nil {
		t.Fatal(err)
	}
	pol, err := c.Devices[0].AccessPolicy()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(0, 0)
	// Two different clients, no per-client limit: the shared device budget is
	// what refuses the second one.
	if d := pol.Check(net.ParseIP("10.0.0.1"), now); d != access.Allow {
		t.Fatalf("first client = %v, want allow", d)
	}
	if d := pol.Check(net.ParseIP("10.0.0.2"), now); d != access.DenyDevice {
		t.Fatalf("second client = %v, want device-budget denial", d)
	}
}

func TestDeviceObjectID(t *testing.T) {
	c, err := decode(t, oneDevice("device_addr: 192.0.2.10:47808\ndevice_instance: 1001\n"))
	if err != nil {
		t.Fatal(err)
	}
	oid, ok := c.Devices[0].DeviceObjectID()
	if !ok || oid.Type != bacnet.ObjectDevice || oid.Instance != 1001 {
		t.Fatalf("object id = %v, %v", oid, ok)
	}
	off, err := decode(t, oneDevice("device_addr: 192.0.2.10:47808\n"))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := off.Devices[0].DeviceObjectID(); ok {
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
