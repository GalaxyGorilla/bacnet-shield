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
		"--max-pending", "16",
	}); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadChecked(o)
	if err != nil {
		t.Fatalf("loadChecked: %v", err)
	}
	if cfg.MaxPending != 16 || cfg.Access.RatePerSec != 10 || cfg.Access.DeviceRatePerSec != 40 || len(cfg.Access.Allow) != 1 {
		t.Fatalf("flags were not mapped: %+v", cfg)
	}
	pol, err := cfg.AccessPolicy()
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
	c.ListenAddr = "127.0.0.1:47808"
	c.DeviceAddr = "127.0.0.1:47809"
	c.Access.ReadOnly = true
	c.Access.Allow = []string{"127.0.0.0/8"}
	c.Access.RatePerSec = 5
	inst := uint32(1001)
	c.DeviceInstance = &inst

	checks := configChecks(c)
	if len(checks) != 2 {
		t.Fatalf("checks = %+v, want config + device-instance", checks)
	}
	if !strings.Contains(checks[0].Detail, "read-only") ||
		!strings.Contains(checks[0].Detail, "allowlist(1)") ||
		!strings.Contains(checks[0].Detail, "rate 5.00/s") {
		t.Fatalf("config detail = %q", checks[0].Detail)
	}
	if checks[1].Name != "device-instance" || !strings.Contains(checks[1].Detail, "device,1001") {
		t.Fatalf("instance check = %+v", checks[1])
	}
}

func TestRestartOnlyChanges(t *testing.T) {
	a := config.Defaults()
	a.ListenAddr, a.DeviceAddr = "127.0.0.1:47808", "127.0.0.1:47809"
	b := *a
	if got := restartOnlyChanges(a, &b); len(got) != 0 {
		t.Fatalf("identical configs reported changes: %v", got)
	}

	b.ListenAddr = "0.0.0.0:47808"
	b.RequestTimeoutSecs = 5
	b.MaxPending = 8
	inst := uint32(42)
	b.DeviceInstance = &inst
	got := restartOnlyChanges(a, &b)
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

	base := "listen_addr: " + g.ClientAddr().String() + "\ndevice_addr: " + dev.addr() + "\n"
	writeCfg := func(accessBlock string) {
		t.Helper()
		if err := os.WriteFile(cfgPath, []byte(base+accessBlock), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeCfg("access:\n  read_only: true\n")

	cur, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("load: %v", err)
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
	reload(&config.Options{ConfigPath: cfgPath}, cur, g, log)

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
