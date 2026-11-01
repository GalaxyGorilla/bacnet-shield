package observ

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
)

// This package is small but it is what an operator touches first: the logger
// decides whether a failure is visible, and the metrics endpoint is the only
// Prometheus surface. A broken handler or a listener that is not released on
// shutdown would only show up in production.

func TestNewLoggerLevels(t *testing.T) {
	for _, level := range []string{"debug", "info", "warn", "error"} {
		log, err := NewLogger(level)
		if err != nil {
			t.Fatalf("NewLogger(%q): %v", level, err)
		}
		if log == nil {
			t.Fatalf("NewLogger(%q) returned nil", level)
		}
	}

	// An unknown level is a startup error, not a silent fallback to info.
	if _, err := NewLogger("verbose"); err == nil {
		t.Fatal("NewLogger accepted an unknown level")
	} else if !strings.Contains(err.Error(), `"verbose"`) {
		t.Fatalf("error does not name the level: %v", err)
	}
}

func TestNewLoggerHonoursLevel(t *testing.T) {
	log, err := NewLogger("error")
	if err != nil {
		t.Fatal(err)
	}
	if log.Core().Enabled(zap.InfoLevel) {
		t.Fatal(`NewLogger("error") has info enabled`)
	}
	if !log.Core().Enabled(zap.ErrorLevel) {
		t.Fatal(`NewLogger("error") does not have error enabled`)
	}

	log, err = NewLogger("debug")
	if err != nil {
		t.Fatal(err)
	}
	if !log.Core().Enabled(zap.DebugLevel) {
		t.Fatal(`NewLogger("debug") does not have debug enabled`)
	}
}

// TestMetricsScrape covers NewMetrics + Handler as one unit: the failure that
// matters is "the instrument exists but is not on the scrape page", and the
// registry is private, so only the handler proves registration.
func TestMetricsScrape(t *testing.T) {
	m := NewMetrics()
	m.Requests.Inc()
	m.Forwarded.Inc()
	m.Pending.Set(3)
	m.Subscriptions.Set(2)
	m.SCConnected.Set(1)
	m.SCReconnects.Inc()

	body := scrape(t, m.Handler())
	for _, want := range []string{
		"bacnet_shield_requests_total 1",
		"bacnet_shield_forwarded_total 1",
		"bacnet_shield_pending 3",
		"bacnet_shield_cov_subscriptions 2",
		"bacnet_shield_sc_connected 1",
		"bacnet_shield_sc_reconnects_total 1",
		// Every named instrument must be registered. This list is the
		// contract the gateway's counters rely on.
		"bacnet_shield_responses_total",
		"bacnet_shield_acl_denied_total",
		"bacnet_shield_rate_limited_total",
		"bacnet_shield_device_rate_limited_total",
		"bacnet_shield_writes_denied_total",
		"bacnet_shield_parse_errors_total",
		"bacnet_shield_pending_full_total",
		"bacnet_shield_unsupported_total",
		"bacnet_shield_replayed_total",
		"bacnet_shield_retransmits_dropped_total",
		"bacnet_shield_notifications_dropped_total",
		"go_goroutines",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("scrape output is missing %q", want)
		}
	}
}

// TestMetricsRegistriesAreIsolated: two gateways in one process (a test, or a
// future multi-instance command) must not share counters. The private registry
// is the whole reason this package exists.
func TestMetricsRegistriesAreIsolated(t *testing.T) {
	a, b := NewMetrics(), NewMetrics()
	a.Requests.Add(7)
	if got := scrape(t, b.Handler()); strings.Contains(got, "bacnet_shield_requests_total 7") {
		t.Fatal("two Metrics instances share a counter")
	}
}

// TestServeAndShutdown drives the real listener: it must serve /metrics,
// answer 404 elsewhere, and release the port on shutdown.
func TestServeAndShutdown(t *testing.T) {
	addr := freeTCPAddr(t)
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- Serve(ctx, addr, NewMetrics().Handler(), zap.NewNop()) }()

	body := get(t, "http://"+addr+"/metrics", 5*time.Second)
	if !strings.Contains(body, "bacnet_shield_requests_total") {
		t.Fatalf("/metrics body does not look like a scrape: %.120q", body)
	}

	resp, err := http.Get("http://" + addr + "/nope")
	if err != nil {
		t.Fatalf("GET /nope: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("GET /nope = %d, want 404 (only /metrics is exposed)", resp.StatusCode)
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Serve returned %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after cancellation")
	}

	// The port must be usable again.
	deadline := time.Now().Add(5 * time.Second)
	for {
		ln, err := net.Listen("tcp", addr)
		if err == nil {
			_ = ln.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("metrics port was not released after shutdown: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestServeBindError: a port already in use is a startup error, not a
// goroutine that dies quietly.
func TestServeBindError(t *testing.T) {
	addr := freeTCPAddr(t)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("reserve %s: %v", addr, err)
	}
	defer ln.Close()

	err = Serve(context.Background(), addr, NewMetrics().Handler(), zap.NewNop())
	if err == nil {
		t.Fatal("Serve succeeded on a port that is in use")
	}
	if !strings.Contains(err.Error(), "in use") {
		t.Fatalf("error does not carry the cause: %v", err)
	}
}

// --- helpers -------------------------------------------------------------------

func freeTCPAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve tcp port: %v", err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("release tcp port: %v", err)
	}
	return addr
}

func scrape(t *testing.T, h http.Handler) string {
	t.Helper()
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 5 * time.Second}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("scrape listener: %v", err)
	}
	go func() { _ = srv.Serve(ln) }()
	defer func() { _ = srv.Close() }()
	return get(t, "http://"+ln.Addr().String()+"/metrics", 5*time.Second)
}

func get(t *testing.T, url string, timeout time.Duration) string {
	t.Helper()
	client := &http.Client{Timeout: time.Second}
	deadline := time.Now().Add(timeout)
	var lastErr error
	for {
		resp, err := client.Get(url)
		if err == nil {
			body, rerr := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if rerr != nil {
				t.Fatalf("read %s: %v", url, rerr)
			}
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("GET %s = %d", url, resp.StatusCode)
			}
			return string(body)
		}
		lastErr = err
		if time.Now().After(deadline) {
			t.Fatalf("GET %s never answered: %v", url, lastErr)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
