package main

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/pflag"
	"go.uber.org/zap"

	"github.com/GalaxyGorilla/bacnet-shield/internal/access"
	"github.com/GalaxyGorilla/bacnet-shield/internal/bacnet"
	"github.com/GalaxyGorilla/bacnet-shield/internal/config"
	"github.com/GalaxyGorilla/bacnet-shield/internal/observ"
	"github.com/GalaxyGorilla/bacnet-shield/internal/proxy"
)

// fakeDevice is a minimal BACnet device on a real UDP socket: it answers
// Who-Is with an I-Am and ReadProperty with a ComplexACK. The selftest tests
// drive the production probe path, not a mock.
type fakeDevice struct {
	conn *net.UDPConn
}

func newFakeDevice(t *testing.T, instance uint32) *fakeDevice {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("fake device bind: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	d := &fakeDevice{conn: conn}
	go d.serve(instance)
	return d
}

func (d *fakeDevice) addr() string { return d.conn.LocalAddr().String() }

func (d *fakeDevice) serve(instance uint32) {
	buf := make([]byte, 65535)
	for {
		n, src, err := d.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		b, err := bacnet.ParseBVLC(buf[:n])
		if err != nil {
			continue
		}
		np, err := bacnet.ParseNPDU(b.Data)
		if err != nil {
			continue
		}
		a, err := bacnet.ParseAPDU(np.APDU)
		if err != nil {
			continue
		}
		var reply bacnet.APDU
		switch a.Service {
		case bacnet.ServiceWhoIs:
			oid := bacnet.ObjectID{Type: bacnet.ObjectDevice, Instance: instance}
			payload := append([]byte{0x0C}, oid.AppendTo(nil)...)
			payload = append(payload, 0x19, 0x05, 0x29, 0x00, 0x3A, 0x00, 0x05)
			reply = bacnet.APDU{Type: bacnet.PDUUnconfirmedRequest, HasService: true,
				Service: bacnet.ServiceIAm, Payload: payload}
		case bacnet.ServiceReadProperty:
			payload := append([]byte(nil), a.Payload...)
			payload = append(payload, 0x3E, 0x75, 0x04, 't', 'e', 's', 't', 0x3F)
			reply = bacnet.APDU{Type: bacnet.PDUComplexACK, InvokeID: a.InvokeID, HasInvokeID: true,
				HasService: true, Service: bacnet.ServiceReadProperty, Payload: payload}
		case bacnet.ServiceWriteProperty:
			reply = bacnet.APDU{Type: bacnet.PDUSimpleACK, InvokeID: a.InvokeID, HasInvokeID: true,
				HasService: true, Service: bacnet.ServiceWriteProperty}
		default:
			continue
		}
		frame := bacnet.BVLC{Function: bacnet.BVLCOriginalUnicastNPDU,
			Data: bacnet.NPDU{APDU: reply.Marshal()}.Marshal()}.Marshal()
		_, _ = d.conn.WriteToUDP(frame, src)
	}
}

func TestRunValidate(t *testing.T) {
	if code := runValidate([]string{"--listen", "127.0.0.1:47808", "--device", "127.0.0.1:47809"}); code != 0 {
		t.Fatalf("valid config exit = %d, want 0", code)
	}
	if code := runValidate([]string{"--listen", "127.0.0.1:47808"}); code != 1 {
		t.Fatalf("missing --device exit = %d, want 1", code)
	}
	if code := runValidate([]string{"--listen", "127.0.0.1:47808", "--device", "127.0.0.1:47808"}); code != 1 {
		t.Fatalf("self-forwarding config exit = %d, want 1", code)
	}
	if code := runValidate([]string{"--nope"}); code != 2 {
		t.Fatalf("unknown flag exit = %d, want 2", code)
	}
	if code := runValidate([]string{"extra"}); code != 2 {
		t.Fatalf("unexpected argument exit = %d, want 2", code)
	}
}

func TestRunSelftestProbeWhoIs(t *testing.T) {
	dev := newFakeDevice(t, 1001)
	if code := runSelftest([]string{"--listen", "127.0.0.1:47808", "--device", dev.addr()}); code != 0 {
		t.Fatalf("selftest exit = %d, want 0", code)
	}
}

func TestRunSelftestProbePinnedInstance(t *testing.T) {
	dev := newFakeDevice(t, 1001)
	if code := runSelftest([]string{
		"--listen", "127.0.0.1:47808", "--device", dev.addr(), "--device-instance", "1001",
	}); code != 0 {
		t.Fatalf("selftest exit = %d, want 0", code)
	}
}

func TestRunSelftestProbeDisabled(t *testing.T) {
	// With --probe=false nothing may touch the network, so a dead address
	// still passes: this is the config-only mode for commissioning scripts.
	if code := runSelftest([]string{
		"--listen", "127.0.0.1:47808", "--device", "192.0.2.1:47808", "--probe=false",
	}); code != 0 {
		t.Fatalf("config-only selftest exit = %d, want 0", code)
	}
}

func TestRunSelftestConfigError(t *testing.T) {
	if code := runSelftest([]string{"--listen", "127.0.0.1:47808"}); code != 1 {
		t.Fatalf("selftest without --device exit = %d, want 1", code)
	}
}

func TestLoadCheckedFlags(t *testing.T) {
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	o := config.Register(fs)
	if err := fs.Parse([]string{
		"--listen", "127.0.0.1:47808",
		"--device", "127.0.0.1:47809",
		"--write-default", "deny",
		"--write-allow", "analog-value:5:present-value",
		"--allow", "127.0.0.0/8",
		"--rate-per-sec", "10",
		"--device-rate-per-sec", "40",
		"--audit-file", "/tmp/audit.jsonl",
		"--audit-max-mb", "8",
		"--max-pending", "16",
	}); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadChecked(o)
	if err != nil {
		t.Fatalf("loadChecked: %v", err)
	}
	d := cfg.Devices[0]
	if d.MaxPending != 16 || d.Access.RatePerSec != 10 || d.Access.DeviceRatePerSec != 40 || len(d.Access.Allow) != 1 {
		t.Fatalf("flags were not mapped: %+v", cfg)
	}
	if cfg.Audit.File != "/tmp/audit.jsonl" || cfg.Audit.MaxMB != 8 {
		t.Fatalf("audit flags were not mapped: %+v", cfg.Audit)
	}
	pol, err := d.AccessPolicy()
	if err != nil {
		t.Fatal(err)
	}
	allowed := writeAPDU(bacnet.ObjectID{Type: bacnet.ObjectAnalogValue, Instance: 5}, bacnet.PropertyPresentValue)
	if !pol.AllowWrite(allowed) {
		t.Fatal("the configured allow rule did not authorize the write")
	}
	denied := writeAPDU(bacnet.ObjectID{Type: bacnet.ObjectAnalogValue, Instance: 6}, bacnet.PropertyPresentValue)
	if pol.AllowWrite(denied) {
		t.Fatal("an uncovered write was authorized")
	}
}

func TestFlagsWriteRulesNeedDefault(t *testing.T) {
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	o := config.Register(fs)
	if err := fs.Parse([]string{
		"--listen", "127.0.0.1:47808",
		"--device", "127.0.0.1:47809",
		"--write-allow", "analog-value:5:present-value",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := o.Build(); err == nil {
		t.Fatal("a write rule without --write-default was accepted")
	}
}

func writeAPDU(oid bacnet.ObjectID, prop bacnet.PropertyID) bacnet.APDU {
	payload := append([]byte{0x0C}, oid.AppendTo(nil)...)
	payload = append(payload, 0x19, byte(prop), 0x3E, 0x44, 0x3F, 0x80, 0x00, 0x00, 0x3F)
	return bacnet.APDU{Type: bacnet.PDUConfirmedRequest, InvokeID: 1, HasInvokeID: true,
		HasService: true, Service: bacnet.ServiceWriteProperty, Payload: payload}
}

func TestConfigChecks(t *testing.T) {
	c := config.Defaults()
	c.Devices = []config.Device{{
		Name:       "boiler",
		ListenAddr: "127.0.0.1:47808",
		DeviceAddr: "127.0.0.1:47809",
		Access: config.Access{
			ReadOnly:   true,
			Allow:      []string{"127.0.0.0/8"},
			RatePerSec: 5,
		},
	}}
	inst := uint32(1001)
	c.Devices[0].DeviceInstance = &inst
	c.Devices[0].Name = "boiler"

	checks := configChecks(c)
	if len(checks) != 2 {
		t.Fatalf("checks = %+v, want config + device", checks)
	}
	if checks[0].Name != "config" || !strings.Contains(checks[0].Detail, "1 device(s)") {
		t.Fatalf("config check = %+v", checks[0])
	}
	if checks[1].Name != "device boiler" {
		t.Fatalf("device check name = %q", checks[1].Name)
	}
	if !strings.Contains(checks[1].Detail, "read-only") ||
		!strings.Contains(checks[1].Detail, "allowlist(1)") ||
		!strings.Contains(checks[1].Detail, "rate 5.00/s") ||
		!strings.Contains(checks[1].Detail, "device,1001") {
		t.Fatalf("device detail = %q", checks[1].Detail)
	}
}

func TestRestartOnlyChanges(t *testing.T) {
	a := config.Defaults()
	a.Devices = []config.Device{{
		Name:               "boiler",
		ListenAddr:         "127.0.0.1:47808",
		DeviceAddr:         "127.0.0.1:47809",
		RequestTimeoutSecs: 30,
		MaxPending:         256,
	}}
	b := *a
	b.Devices = append([]config.Device(nil), a.Devices...)
	if got := topLevelRestartOnlyChanges(a, &b); len(got) != 0 {
		t.Fatalf("identical configs reported top-level changes: %v", got)
	}
	if got := deviceRestartOnlyChanges("boiler", &a.Devices[0], &b.Devices[0]); len(got) != 0 {
		t.Fatalf("identical devices reported changes: %v", got)
	}

	b.Metrics.Addr = "127.0.0.1:9203"
	if got := topLevelRestartOnlyChanges(a, &b); len(got) == 0 || !strings.Contains(got[0], "metrics.addr") {
		t.Fatalf("metrics.addr change not reported: %v", got)
	}

	b.Devices[0].ListenAddr = "0.0.0.0:47808"
	b.Devices[0].RequestTimeoutSecs = 5
	b.Devices[0].MaxPending = 8
	inst := uint32(42)
	b.Devices[0].DeviceInstance = &inst
	got := deviceRestartOnlyChanges("boiler", &a.Devices[0], &b.Devices[0])
	for _, want := range []string{"listen_addr", "request_timeout_secs", "max_pending", "device_instance"} {
		found := false
		for _, w := range got {
			if strings.Contains(w, want) {
				found = true
			}
		}
		if !found {
			t.Errorf("%s change not reported: %v", want, got)
		}
	}
}

// TestReloadSwapsAccessPolicy drives the real reload path on a running
// gateway: the previous unit tests only covered restartOnlyChanges, so a bug
// that compiled the new policy but never installed it would have slipped
// through. It is deliberately end to end — a real client datagram against a
// real bound socket and a fake device — because the policy is only observable
// in the forwarding decision.
func TestReloadSwapsAccessPolicy(t *testing.T) {
	dev := newFakeDevice(t, 1001)
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "gateway.yaml")

	// Bind first (port 0 = ephemeral), then write a config that names the real
	// port. The listener address in the file is only used for the restart-only
	// comparison; the policy is what reload installs.
	readOnly, err := access.NewWritePolicy(true, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	log := zap.NewNop()
	g, err := proxy.New(proxy.Config{
		ListenAddr:     "127.0.0.1:0",
		DeviceAddr:     dev.addr(),
		RequestTimeout: 2 * time.Second,
		MaxPending:     16,
	}, access.NewPolicy(nil, nil, readOnly), log, observ.NewMetrics())
	if err != nil {
		t.Fatalf("gateway: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = g.Serve(ctx) }()
	t.Cleanup(func() { cancel(); _ = g.Close() })

	base := "devices:\n  - listen_addr: " + g.ClientAddr().String() + "\n    device_addr: " + dev.addr() + "\n"
	writeCfg := func(accessBlock string) {
		t.Helper()
		var b strings.Builder
		b.WriteString(base)
		for _, line := range strings.Split(strings.TrimRight(accessBlock, "\n"), "\n") {
			b.WriteString("    " + line + "\n")
		}
		if err := os.WriteFile(cfgPath, []byte(b.String()), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeCfg("access:\n  read_only: true\n")

	cur, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	rd := &runningDevice{
		dev: config.Device{
			Name:               dev.addr(),
			ListenAddr:         g.ClientAddr().String(),
			DeviceAddr:         dev.addr(),
			RequestTimeoutSecs: 2,
			MaxPending:         16,
		},
		gw: g,
	}

	conn, err := net.DialUDP("udp4", nil, g.ClientAddr())
	if err != nil {
		t.Fatalf("client dial: %v", err)
	}
	defer conn.Close()

	write := writeAPDU(bacnet.ObjectID{Type: bacnet.ObjectAnalogValue, Instance: 1}, bacnet.PropertyPresentValue)

	// Read-only: the write is refused locally and the device never sees it.
	if got := sendRecvAPDU(t, conn, writeFrame(write)); got.Type != bacnet.PDUError {
		t.Fatalf("read-only write reply = %s, want error", got.Type)
	}

	// Flip the file to a default-deny policy that allows exactly this write,
	// then run the real reload path on the running gateway.
	writeCfg("access:\n  write_policy:\n    default: deny\n    rules:\n" +
		"      - oid: \"analog-value:1:present-value\"\n        action: allow\n")
	reload(&config.Options{ConfigPath: cfgPath}, cur, []*runningDevice{rd}, log)

	// Same client, same process: the write now reaches the fake device and its
	// SimpleACK is relayed back.
	got := sendRecvAPDU(t, conn, writeFrame(write))
	if got.Type != bacnet.PDUSimpleACK || got.Service != bacnet.ServiceWriteProperty {
		t.Fatalf("post-reload write reply = %s/%d, want simple-ack/write-property", got.Type, got.Service)
	}
}

// writeFrame wraps a client APDU as a unicast BACnet/IP frame.
func writeFrame(a bacnet.APDU) []byte {
	return bacnet.BVLC{Function: bacnet.BVLCOriginalUnicastNPDU,
		Data: bacnet.NPDU{APDU: a.Marshal()}.Marshal()}.Marshal()
}

// sendRecvAPDU sends one frame and decodes the first reply APDU.
func sendRecvAPDU(t *testing.T, conn *net.UDPConn, frame []byte) bacnet.APDU {
	t.Helper()
	if _, err := conn.Write(frame); err != nil {
		t.Fatalf("send: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 65535)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("recv: %v", err)
	}
	b, err := bacnet.ParseBVLC(buf[:n])
	if err != nil {
		t.Fatalf("reply bvlc: %v", err)
	}
	np, err := bacnet.ParseNPDU(b.Data)
	if err != nil {
		t.Fatalf("reply npdu: %v", err)
	}
	a, err := bacnet.ParseAPDU(np.APDU)
	if err != nil {
		t.Fatalf("reply apdu: %v", err)
	}
	return a
}

// freeUDPAddr reserves and releases a UDP port on loopback, returning the
// address a test may bind. The tiny window between release and bind is
// acceptable for a test; a real deployment names a fixed port.
func freeUDPAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("reserve udp port: %v", err)
	}
	addr := ln.LocalAddr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("release udp port: %v", err)
	}
	return addr
}

// TestMultiDeviceCoHosting proves the co-hosting shape end to end: one process
// serves two listener<->device pairs, each request reaches its own device, and
// each device's policy gates only its own front leg. It is the property a
// single-device test cannot show.
func TestMultiDeviceCoHosting(t *testing.T) {
	devA := newFakeDevice(t, 1001)
	devB := newFakeDevice(t, 2002)

	cfg := config.Defaults()
	cfg.Devices = []config.Device{
		{
			Name:               "boiler",
			ListenAddr:         freeUDPAddr(t),
			DeviceAddr:         devA.addr(),
			RequestTimeoutSecs: 30,
			MaxPending:         256,
			Access:             config.Access{ReadOnly: true},
		},
		{
			Name:               "ahu",
			ListenAddr:         freeUDPAddr(t),
			DeviceAddr:         devB.addr(),
			RequestTimeoutSecs: 30,
			MaxPending:         256,
			// No write policy: the ahu accepts writes.
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("config: %v", err)
	}

	registry := observ.NewRegistry()
	devices, err := buildDevices(cfg, zap.NewNop(), registry, nil)
	if err != nil {
		t.Fatalf("buildDevices: %v", err)
	}
	gws := make([]*proxy.Gateway, len(devices))
	for i, rd := range devices {
		gws[i] = rd.gw
	}
	runner := proxy.NewRunner(gws)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = runner.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		for _, rd := range devices {
			_ = rd.gw.Close()
		}
	})

	connA := dialClient(t, devices[0].gw.ClientAddr())
	connB := dialClient(t, devices[1].gw.ClientAddr())

	// Each listener reaches its own device: Who-Is is answered by the device
	// behind that listener, not by its co-hosted neighbour.
	if got := whoIsInstance(t, connA); got != 1001 {
		t.Fatalf("listener boiler answered for device %d, want 1001", got)
	}
	if got := whoIsInstance(t, connB); got != 2002 {
		t.Fatalf("listener ahu answered for device %d, want 2002", got)
	}

	// The boiler is read-only; the ahu is not. Same write, opposite verdicts,
	// which proves the policy is per device and does not leak across the
	// shared process.
	write := writeAPDU(bacnet.ObjectID{Type: bacnet.ObjectAnalogValue, Instance: 1}, bacnet.PropertyPresentValue)
	if got := sendRecvAPDU(t, connA, writeFrame(write)); got.Type != bacnet.PDUError {
		t.Fatalf("boiler write reply = %s, want error (read-only)", got.Type)
	}
	if got := sendRecvAPDU(t, connB, writeFrame(write)); got.Type != bacnet.PDUSimpleACK {
		t.Fatalf("ahu write reply = %s, want simple-ack (writable)", got.Type)
	}

	// The scrape carries both devices, labelled, on the one shared registry.
	seen := map[string]bool{}
	mfs, err := registry.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() != "bacnet_shield_requests_total" {
			continue
		}
		for _, m := range mf.GetMetric() {
			for _, l := range m.GetLabel() {
				if l.GetName() == "device" {
					seen[l.GetValue()] = true
				}
			}
		}
	}
	if !seen["boiler"] || !seen["ahu"] {
		t.Fatalf("per-device metric labels = %v, want boiler and ahu", seen)
	}
}

// TestBuildDevicesPortConflict: a listener already in use is a startup error,
// not a goroutine that dies after the process announced readiness.
func TestBuildDevicesPortConflict(t *testing.T) {
	dev := newFakeDevice(t, 1001)
	ln, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("occupy port: %v", err)
	}
	defer ln.Close()

	cfg := config.Defaults()
	cfg.Devices = []config.Device{{
		Name:               "boiler",
		ListenAddr:         ln.LocalAddr().String(),
		DeviceAddr:         dev.addr(),
		RequestTimeoutSecs: 30,
		MaxPending:         256,
	}}
	if _, err := buildDevices(cfg, zap.NewNop(), observ.NewRegistry(), nil); err == nil {
		t.Fatal("a port already in use was not reported")
	}
}

// dialClient opens a UDP client socket to a gateway listener.
func dialClient(t *testing.T, addr *net.UDPAddr) *net.UDPConn {
	t.Helper()
	conn, err := net.DialUDP("udp4", nil, addr)
	if err != nil {
		t.Fatalf("client dial %s: %v", addr, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// whoIsInstance sends a Who-Is and returns the instance of the answering I-Am.
func whoIsInstance(t *testing.T, conn *net.UDPConn) uint32 {
	t.Helper()
	apdu := bacnet.APDU{Type: bacnet.PDUUnconfirmedRequest, HasService: true, Service: bacnet.ServiceWhoIs}
	got := sendRecvAPDU(t, conn, writeFrame(apdu))
	if got.Type != bacnet.PDUUnconfirmedRequest || got.Service != bacnet.ServiceIAm {
		t.Fatalf("who-is reply = %s/%d, want unconfirmed/i-am", got.Type, got.Service)
	}
	// I-Am carries the object identifier as context tag 0: 0x0C then 4 bytes.
	if len(got.Payload) < 5 || got.Payload[0] != 0x0C {
		t.Fatalf("i-am payload = %x", got.Payload)
	}
	oid, err := bacnet.ParseObjectID(got.Payload[1:5])
	if err != nil {
		t.Fatalf("i-am object id: %v", err)
	}
	return oid.Instance
}

func TestParseFlagsHelpAndArguments(t *testing.T) {
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	config.Register(fs)
	ok, code := parseFlags(fs, []string{"--help"})
	if ok || code != 0 {
		t.Fatalf("--help = (%v, %d), want (false, 0)", ok, code)
	}

	fs = pflag.NewFlagSet("test", pflag.ContinueOnError)
	config.Register(fs)
	ok, code = parseFlags(fs, []string{"--listen", "127.0.0.1:1", "stray"})
	if ok || code != 2 {
		t.Fatalf("stray argument = (%v, %d), want (false, 2)", ok, code)
	}
}
