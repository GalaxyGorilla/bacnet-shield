package watchdog

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// startFakeSystemd starts a Unix-socket fake of systemd's NOTIFY_SOCKET and
// returns the socket path plus a channel delivering every received state
// string. The socket lives in a SHORT MkdirTemp path: macOS caps unix socket
// paths at 104 bytes (sun_path), and t.TempDir() embeds the test name.
func startFakeSystemd(t *testing.T) (string, <-chan string) {
	t.Helper()
	dir, err := os.MkdirTemp("", "sdnw")
	if err != nil {
		t.Fatalf("mkdir temp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sockPath := filepath.Join(dir, "s.sock")
	ln, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: sockPath, Net: "unixgram"})
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	states := make(chan string, 32)
	go func() {
		defer close(states)
		buf := make([]byte, 512)
		for {
			n, _, err := ln.ReadFromUnix(buf)
			if err != nil {
				return
			}
			if n > 0 {
				states <- string(buf[:n])
			}
		}
	}()
	return sockPath, states
}

// withFakeSystemd points NOTIFY_SOCKET and WATCHDOG_USEC at the fake socket
// for the duration of fn.
func withFakeSystemd(t *testing.T, sockPath, usec string, fn func()) {
	t.Helper()
	t.Setenv("NOTIFY_SOCKET", sockPath)
	if usec != "" {
		t.Setenv("WATCHDOG_USEC", usec)
	} else {
		os.Unsetenv("WATCHDOG_USEC")
	}
	fn()
}

func TestNoopWithoutSystemd(t *testing.T) {
	os.Unsetenv("NOTIFY_SOCKET")
	os.Unsetenv("WATCHDOG_USEC")
	if d := Interval(); d != 0 {
		t.Fatalf("Interval() = %v, want 0 without systemd", d)
	}
	if ok, err := NotifyReady(); ok || err != nil {
		t.Fatalf("NotifyReady() = (%v, %v), want (false, nil) without systemd", ok, err)
	}
	if ok, err := Notify("WATCHDOG=1"); ok || err != nil {
		t.Fatalf("Notify() = (%v, %v), want (false, nil) without systemd", ok, err)
	}
}

func TestWatchdogEnabledAndPing(t *testing.T) {
	sockPath, states := startFakeSystemd(t)
	withFakeSystemd(t, sockPath, "1000000", func() { // WatchdogSec = 1s
		d := Interval()
		if d != time.Second {
			t.Fatalf("Interval() = %v, want 1s", d)
		}
		if ok, err := NotifyReady(); !ok || err != nil {
			t.Fatalf("NotifyReady() = (%v, %v), want (true, nil)", ok, err)
		}
		done := make(chan struct{})
		go Start(d, done)
		select {
		case s := <-states:
			if s != "READY=1" {
				t.Fatalf("first notification = %q, want READY=1", s)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for READY=1")
		}
		select {
		case s := <-states:
			if s != "WATCHDOG=1" {
				t.Fatalf("ping = %q, want WATCHDOG=1", s)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for WATCHDOG=1")
		}
		close(done)
	})
}

func TestWatchdogDisabledWhenUsecMissing(t *testing.T) {
	sockPath, states := startFakeSystemd(t)
	withFakeSystemd(t, sockPath, "", func() {
		if d := Interval(); d != 0 {
			t.Fatalf("Interval() = %v with NOTIFY_SOCKET but no WATCHDOG_USEC, want 0", d)
		}
		if ok, err := NotifyReady(); !ok || err != nil {
			t.Fatalf("NotifyReady() = (%v, %v), want (true, nil) — ready still notifiable", ok, err)
		}
		select {
		case s := <-states:
			if s != "READY=1" {
				t.Fatalf("notification = %q, want READY=1", s)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for READY=1")
		}
	})
}

func TestIntervalBadUsec(t *testing.T) {
	t.Setenv("WATCHDOG_USEC", "not-a-number")
	if d := Interval(); d != 0 {
		t.Fatalf("Interval() = %v for a non-numeric WATCHDOG_USEC, want 0", d)
	}
	t.Setenv("WATCHDOG_USEC", "0")
	if d := Interval(); d != 0 {
		t.Fatalf("Interval() = %v for WATCHDOG_USEC=0, want 0", d)
	}
}

func TestStartStopsOnDone(t *testing.T) {
	sockPath, states := startFakeSystemd(t)
	withFakeSystemd(t, sockPath, "1000000", func() {
		done := make(chan struct{})
		stopped := make(chan struct{})
		go func() {
			Start(Interval(), done)
			close(stopped)
		}()
		select {
		case <-states:
		case <-time.After(2 * time.Second):
			t.Fatal("no watchdog ping")
		}
		close(done)
		select {
		case <-stopped:
		case <-time.After(2 * time.Second):
			t.Fatal("Start did not stop when done closed")
		}
	})
}

func TestNotifyReportsDialError(t *testing.T) {
	// A NOTIFY_SOCKET that does not exist: Notify must report that systemd
	// was expected (ok=true) and carry the failure, so the command can warn
	// instead of pretending it announced readiness.
	t.Setenv("NOTIFY_SOCKET", filepath.Join(t.TempDir(), "missing.sock"))
	ok, err := NotifyReady()
	if !ok {
		t.Fatal("NotifyReady did not report that a notify socket was configured")
	}
	if err == nil {
		t.Fatal("NotifyReady succeeded against a socket that does not exist")
	}
}
