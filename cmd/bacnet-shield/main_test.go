package main

import (
	"net"
	"strings"
	"testing"

	"github.com/spf13/pflag"

	"github.com/GalaxyGorilla/bacnet-shield/internal/bacnet"
	"github.com/GalaxyGorilla/bacnet-shield/internal/config"
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
		"--max-pending", "16",
	}); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadChecked(o)
	if err != nil {
		t.Fatalf("loadChecked: %v", err)
	}
	if cfg.MaxPending != 16 || cfg.Access.RatePerSec != 10 || len(cfg.Access.Allow) != 1 {
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
