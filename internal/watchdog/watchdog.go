// Package watchdog speaks the systemd sd_notify protocol directly.
//
// Under systemd with WatchdogSec set, the gateway announces readiness and
// then pings WATCHDOG=1; a wedged process is restarted by the host. That
// matters more here than for a normal service: the box *is* the device's
// network path, so a silent hang looks like a dead building controller.
//
// Without systemd (no NOTIFY_SOCKET) every function is a cheap no-op. The
// protocol is a datagram to a unix socket — a dozen lines — so this package
// deliberately does not take a dependency on a systemd library.
package watchdog

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// socketPath returns the notify socket, converting the abstract-socket
// spelling ("@name", Linux) to the NUL-prefixed form net.UnixAddr expects.
func socketPath() string {
	p := os.Getenv("NOTIFY_SOCKET")
	if p == "" {
		return ""
	}
	if strings.HasPrefix(p, "@") {
		return "\x00" + p[1:]
	}
	return p
}

// Notify sends one state string ("READY=1", "WATCHDOG=1", ...).
// Returns (false, nil) when not running under systemd.
func Notify(state string) (bool, error) {
	path := socketPath()
	if path == "" {
		return false, nil
	}
	conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		return true, fmt.Errorf("watchdog: dial %q: %w", path, err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte(state)); err != nil {
		return true, fmt.Errorf("watchdog: notify %q: %w", path, err)
	}
	return true, nil
}

// NotifyReady sends READY=1. Call it only after every listener has bound:
// announcing readiness before a bind failure makes systemd report a
// short-lived success instead of a failed start.
func NotifyReady() (bool, error) { return Notify("READY=1") }

// Interval reports the systemd watchdog interval (WATCHDOG_USEC), or 0 when
// the service does not run under a watchdog.
func Interval() time.Duration {
	usec, err := strconv.ParseUint(os.Getenv("WATCHDOG_USEC"), 10, 64)
	if err != nil || usec == 0 {
		return 0
	}
	return time.Duration(usec) * time.Microsecond
}

// Start pings WATCHDOG=1 every interval/2 (systemd restarts the service when
// two intervals pass without a ping) until done is closed. Only call it when
// Interval() > 0.
func Start(interval time.Duration, done <-chan struct{}) {
	tick := interval / 2
	if tick <= 0 {
		tick = time.Second
	}
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		select {
		case <-done:
			return
		case <-t.C:
			_, _ = Notify("WATCHDOG=1")
		}
	}
}
