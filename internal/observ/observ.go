// Package observ is the logging and metrics baseline: one zap logger and one
// Prometheus registry per process.
//
// The registry is local, not the package-global default, so a test can build
// two gateways without their counters colliding.
package observ

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// NewLogger builds a console-encoded logger. Console (not JSON) because the
// primary consumer is journald on an appliance and a human reading it.
func NewLogger(level string) (*zap.Logger, error) {
	var lvl zapcore.Level
	if err := lvl.UnmarshalText([]byte(level)); err != nil {
		return nil, fmt.Errorf("observ: log level %q: %w", level, err)
	}
	cfg := zap.NewProductionConfig()
	cfg.Encoding = "console"
	cfg.Level = zap.NewAtomicLevelAt(lvl)
	cfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	cfg.EncoderConfig.EncodeDuration = zapcore.StringDurationEncoder
	cfg.DisableCaller = true
	return cfg.Build()
}

// Metrics holds every counter and gauge the data plane touches. Names use
// the Shield prefix so an appliance dashboard can group the products.
type Metrics struct {
	reg *prometheus.Registry

	Requests             prometheus.Counter
	Forwarded            prometheus.Counter
	Responses            prometheus.Counter
	ACLDenied            prometheus.Counter
	RateLimited          prometheus.Counter
	DeviceRateLimited    prometheus.Counter
	WritesDenied         prometheus.Counter
	ParseErrors          prometheus.Counter
	PendingFull          prometheus.Counter
	Unsupported          prometheus.Counter
	Replayed             prometheus.Counter
	Retransmits          prometheus.Counter
	NotificationsDropped prometheus.Counter
	AuditDropped         prometheus.Counter

	Pending       prometheus.Gauge
	Subscriptions prometheus.Gauge
	SCConnected   prometheus.Gauge

	SCReconnects prometheus.Counter
}

// NewRegistry builds a fresh registry with the process-wide Go and process
// collectors registered once. A multi-device process shares one registry and
// registers every device's instrument set on it.
func NewRegistry() *prometheus.Registry {
	reg := prometheus.NewRegistry()
	reg.MustRegister(collectors.NewGoCollector())
	reg.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	return reg
}

// NewMetrics builds an isolated registry with a full, unlabelled instrument
// set. It is what a test uses. A running process (even a single-device one)
// registers its per-device set with NewMetricsForDevice so every metric carries
// the same `device` label, and the process-wide audit counter with
// NewProcessMetrics on the same shared registry.
func NewMetrics() *Metrics {
	reg := NewRegistry()
	m := NewMetricsForDevice(reg, "")
	m.AuditDropped = NewProcessMetrics(reg).AuditDropped
	return m
}

// NewMetricsForDevice registers a device-labelled data-plane instrument set on
// reg. With several devices in one process, each device gets its own counters
// carrying a `device` const label, and the registry (with its process
// collectors) is shared, so a scrape stays one endpoint. An empty device omits
// the label. The process-wide counters (NewProcessMetrics) are registered
// separately so they are not duplicated per device.
func NewMetricsForDevice(reg *prometheus.Registry, device string) *Metrics {
	var cl prometheus.Labels
	if device != "" {
		cl = prometheus.Labels{"device": device}
	}
	c := func(name, help string) prometheus.CounterOpts {
		return prometheus.CounterOpts{Name: name, Help: help, ConstLabels: cl}
	}
	g := func(name, help string) prometheus.GaugeOpts {
		return prometheus.GaugeOpts{Name: name, Help: help, ConstLabels: cl}
	}
	f := promauto.With(reg)
	return &Metrics{
		reg:                  reg,
		Requests:             f.NewCounter(c("bacnet_shield_requests_total", "Client-leg datagrams received.")),
		Forwarded:            f.NewCounter(c("bacnet_shield_forwarded_total", "Requests forwarded to the device leg.")),
		Responses:            f.NewCounter(c("bacnet_shield_responses_total", "Device answers relayed to a client.")),
		ACLDenied:            f.NewCounter(c("bacnet_shield_acl_denied_total", "Datagrams dropped by the client allow-list.")),
		RateLimited:          f.NewCounter(c("bacnet_shield_rate_limited_total", "Datagrams dropped by the per-client rate limit.")),
		DeviceRateLimited:    f.NewCounter(c("bacnet_shield_device_rate_limited_total", "Datagrams dropped by the shared per-device rate budget.")),
		WritesDenied:         f.NewCounter(c("bacnet_shield_writes_denied_total", "Writes refused by the write policy.")),
		ParseErrors:          f.NewCounter(c("bacnet_shield_parse_errors_total", "Undecodable datagrams dropped.")),
		PendingFull:          f.NewCounter(c("bacnet_shield_pending_full_total", "Requests dropped because every invoke ID was in flight.")),
		Unsupported:          f.NewCounter(c("bacnet_shield_unsupported_total", "Frames or services the proxy cannot serve.")),
		Replayed:             f.NewCounter(c("bacnet_shield_replayed_total", "Retransmissions answered from the finished-response cache.")),
		Retransmits:          f.NewCounter(c("bacnet_shield_retransmits_dropped_total", "Retransmissions dropped because the request is still in flight.")),
		NotificationsDropped: f.NewCounter(c("bacnet_shield_notifications_dropped_total", "Device notifications with no client to receive them.")),
		Pending:              f.NewGauge(g("bacnet_shield_pending", "Requests currently in flight toward the device.")),
		Subscriptions:        f.NewGauge(g("bacnet_shield_cov_subscriptions", "Active COV subscriptions routed by the proxy.")),
		SCConnected:          f.NewGauge(g("bacnet_shield_sc_connected", "1 while the BACnet/SC leg is attached to a hub, 0 otherwise.")),
		SCReconnects:         f.NewCounter(c("bacnet_shield_sc_reconnects_total", "Successful re-attaches to a hub after the first connection.")),
	}
}

// NewProcessMetrics registers the process-wide instruments on reg: counters
// that are not tied to one device. The audit drop counter belongs to the one
// shared audit queue, so it lives here rather than on a device's instrument
// set, which would otherwise count the same drops once per device.
func NewProcessMetrics(reg *prometheus.Registry) *Metrics {
	return &Metrics{
		reg: reg,
		AuditDropped: promauto.With(reg).NewCounter(prometheus.CounterOpts{
			Name: "bacnet_shield_audit_dropped_total",
			Help: "Audit records dropped because the audit queue was full.",
		}),
	}
}

// HandlerFor serves a shared registry at /metrics. With several device
// instrument sets on one registry, this is the single scrape endpoint.
func HandlerFor(reg *prometheus.Registry) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	return mux
}

// Handler is the metrics endpoint. It serves /metrics and nothing else: a
// root-mounted promhttp handler would answer every path with the scrape, which
// makes the surface larger than it needs to be and hides a typo in a probe URL.
func (m *Metrics) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(m.reg, promhttp.HandlerOpts{}))
	return mux
}

// Listen binds the metrics listener synchronously, so a bad address (or a
// port already in use) is a startup error rather than a goroutine that dies
// quietly after the proxy has already announced readiness.
func Listen(addr string) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("observ: metrics listener %q: %w", addr, err)
	}
	return ln, nil
}

// Serve runs the metrics listener until ctx is cancelled. It binds first, so
// a bad address is reported before serving.
func Serve(ctx context.Context, addr string, h http.Handler, log *zap.Logger) error {
	ln, err := Listen(addr)
	if err != nil {
		return err
	}
	return ServeListener(ctx, ln, h, log)
}

// ServeListener serves h on an already-bound listener until ctx is cancelled.
// The command uses this so a metrics bind failure can fail startup.
func ServeListener(ctx context.Context, ln net.Listener, h http.Handler, log *zap.Logger) error {
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 5 * time.Second}
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Serve(ln) }()
	if log != nil {
		log.Info("metrics listening", zap.String("addr", ln.Addr().String()))
	}
	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
		return nil
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}
