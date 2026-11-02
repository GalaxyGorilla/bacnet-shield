package main

import (
	"bytes"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/GalaxyGorilla/bacnet-shield/internal/bacnet"
)

// TestMain lets the lifecycle test re-exec this test binary as the real
// command. Running the gateway in a subprocess is what makes SIGTERM, SIGHUP,
// the metrics endpoint and the readiness path testable without killing the test
// process.
func TestMain(m *testing.M) {
	if os.Getenv("BACNET_SHIELD_HELPER") == "gateway" {
		os.Args = []string{"bacnet-shield", "gateway", "--config", os.Getenv("BACNET_SHIELD_HELPER_CONFIG")}
		os.Exit(run())
	}
	os.Exit(m.Run())
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func waitForText(t *testing.T, buf *syncBuffer, text string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if strings.Contains(buf.String(), text) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("command output never contained %q:\n%s", text, buf.String())
}

func freeUDPPort(t *testing.T) int {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).Port
}

func freeTCPPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func lifecycleRead(invoke byte) bacnet.APDU {
	oid := bacnet.ObjectID{Type: bacnet.ObjectAnalogValue, Instance: 1}
	payload := append([]byte{0x0C}, oid.AppendTo(nil)...)
	payload = append(payload, 0x19, byte(bacnet.PropertyPresentValue))
	return bacnet.APDU{Type: bacnet.PDUConfirmedRequest, InvokeID: invoke, HasInvokeID: true,
		HasService: true, Service: bacnet.ServiceReadProperty, Payload: payload}
}

func lifecycleWrite(invoke byte) bacnet.APDU {
	oid := bacnet.ObjectID{Type: bacnet.ObjectAnalogValue, Instance: 1}
	payload := append([]byte{0x0C}, oid.AppendTo(nil)...)
	payload = append(payload, 0x19, byte(bacnet.PropertyPresentValue))
	payload = append(payload, 0x3E, 0x44, 0x3F, 0x80, 0x00, 0x00, 0x3F)
	return bacnet.APDU{Type: bacnet.PDUConfirmedRequest, InvokeID: invoke, HasInvokeID: true,
		HasService: true, Service: bacnet.ServiceWriteProperty, Payload: payload}
}

type lifecycleClient struct {
	t    *testing.T
	conn *net.UDPConn
}

func newLifecycleClient(t *testing.T) *lifecycleClient {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return &lifecycleClient{t: t, conn: conn}
}

func (c *lifecycleClient) send(a bacnet.APDU, to *net.UDPAddr) {
	c.t.Helper()
	frame := bacnet.BVLC{Function: bacnet.BVLCOriginalUnicastNPDU,
		Data: bacnet.NPDU{APDU: a.Marshal()}.Marshal()}.Marshal()
	if _, err := c.conn.WriteToUDP(frame, to); err != nil {
		c.t.Fatalf("client send: %v", err)
	}
}

func (c *lifecycleClient) recv(timeout time.Duration) (bacnet.APDU, error) {
	_ = c.conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 65535)
	n, _, err := c.conn.ReadFromUDP(buf)
	if err != nil {
		return bacnet.APDU{}, err
	}
	b, err := bacnet.ParseBVLC(buf[:n])
	if err != nil {
		return bacnet.APDU{}, err
	}
	np, err := bacnet.ParseNPDU(b.Data)
	if err != nil {
		return bacnet.APDU{}, err
	}
	return bacnet.ParseAPDU(np.APDU)
}

func writeLifecycleConfig(t *testing.T, path, listen, device, metrics string, readOnly bool) {
	t.Helper()
	policy := "      read_only: true\n"
	if !readOnly {
		policy = "      write_policy:\n        default: deny\n        rules:\n" +
			"          - {oid: \"analog-value:1:present-value\", action: allow}\n"
	}
	cfg := fmt.Sprintf(`devices:
  - name: lifecycle
    listen_addr: %q
    device_addr: %q
    access:
%slog_level: info
metrics:
  addr: %q
`, listen, device, policy, metrics)
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestGatewayLifecycle runs the real command in a subprocess: readiness, a
// read, SIGHUP to an allow rule, an allowed write, the health endpoints and a
// graceful SIGTERM. It is the closest thing to the systemd unit that can run
// inside `go test`.
func TestGatewayLifecycle(t *testing.T) {
	dev := newFakeDevice(t, 1001)
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "gateway.yaml")
	listenPort := freeUDPPort(t)
	metricsPort := freeTCPPort(t)
	listen := fmt.Sprintf("127.0.0.1:%d", listenPort)
	metrics := fmt.Sprintf("127.0.0.1:%d", metricsPort)
	writeLifecycleConfig(t, cfgPath, listen, dev.addr(), metrics, true)

	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(),
		"BACNET_SHIELD_HELPER=gateway",
		"BACNET_SHIELD_HELPER_CONFIG="+cfgPath)
	var out syncBuffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Start(); err != nil {
		t.Fatalf("start command: %v", err)
	}
	defer func() {
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()

	waitForText(t, &out, "device serving", 5*time.Second)

	// Health endpoints are up once the command has bound every listener.
	ready := false
	for i := 0; i < 100; i++ {
		resp, err := http.Get("http://" + metrics + "/readyz")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				ready = true
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !ready {
		t.Fatalf("readyz never became 200:\n%s", out.String())
	}

	proxyAddr, err := net.ResolveUDPAddr("udp4", listen)
	if err != nil {
		t.Fatal(err)
	}
	c := newLifecycleClient(t)
	c.send(lifecycleRead(7), proxyAddr)
	ack, err := c.recv(2 * time.Second)
	if err != nil {
		t.Fatalf("read through the command: %v\n%s", err, out.String())
	}
	if ack.Type != bacnet.PDUComplexACK || ack.InvokeID != 7 {
		t.Fatalf("read answer = %+v", ack)
	}

	// A write is refused under the read-only policy...
	c.send(lifecycleWrite(8), proxyAddr)
	denied, err := c.recv(2 * time.Second)
	if err != nil {
		t.Fatalf("denied write: %v", err)
	}
	if denied.Type != bacnet.PDUError {
		t.Fatalf("write under read-only = %+v", denied)
	}

	// ...and allowed after a SIGHUP reload, without a restart.
	writeLifecycleConfig(t, cfgPath, listen, dev.addr(), metrics, false)
	if err := cmd.Process.Signal(syscall.SIGHUP); err != nil {
		t.Fatalf("SIGHUP: %v", err)
	}
	waitForText(t, &out, "device policy reloaded", 5*time.Second)

	c.send(lifecycleWrite(9), proxyAddr)
	allowed, err := c.recv(2 * time.Second)
	if err != nil {
		t.Fatalf("allowed write: %v", err)
	}
	if allowed.Type != bacnet.PDUSimpleACK || allowed.InvokeID != 9 {
		t.Fatalf("write after reload = %+v", allowed)
	}

	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("SIGTERM: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("command exited with %v:\n%s", err, out.String())
		}
	case <-time.After(10 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatalf("command did not exit after SIGTERM:\n%s", out.String())
	}
}
