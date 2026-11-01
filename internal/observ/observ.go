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
	WritesDenied         prometheus.Counter
	ParseErrors          prometheus.Counter
	PendingFull          prometheus.Counter
	Unsupported          prometheus.Counter
	Replayed             prometheus.Counter
	Retransmits          prometheus.Counter
	NotificationsDropped prometheus.Counter

	Pending       prometheus.Gauge
	Subscriptions prometheus.Gauge
}

// NewMetrics builds an isolated registry with the gateway instruments.
func NewMetrics() *Metrics {
	reg := prometheus.NewRegistry()
	reg.MustRegister(prometheus.NewGoCollector())
	reg.MustRegister(prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}))
	f := promauto.With(reg)
	return &Metrics{
		reg:                  reg,
		Requests:             f.NewCounter(prometheus.CounterOpts{Name: "bacnet_shield_requests_total", Help: "Client-leg datagrams received."}),
		Forwarded:            f.NewCounter(prometheus.CounterOpts{Name: "bacnet_shield_forwarded_total", Help: "Requests forwarded to the device leg."}),
		Responses:            f.NewCounter(prometheus.CounterOpts{Name: "bacnet_shield_responses_total", Help: "Device answers relayed to a client."}),
		ACLDenied:            f.NewCounter(prometheus.CounterOpts{Name: "bacnet_shield_acl_denied_total", Help: "Datagrams dropped by the client allow-list."}),
		RateLimited:          f.NewCounter(prometheus.CounterOpts{Name: "bacnet_shield_rate_limited_total", Help: "Datagrams dropped by the per-client rate limit."}),
		WritesDenied:         f.NewCounter(prometheus.CounterOpts{Name: "bacnet_shield_writes_denied_total", Help: "Writes refused by the write policy."}),
		ParseErrors:          f.NewCounter(prometheus.CounterOpts{Name: "bacnet_shield_parse_errors_total", Help: "Undecodable datagrams dropped."}),
		PendingFull:          f.NewCounter(prometheus.CounterOpts{Name: "bacnet_shield_pending_full_total", Help: "Requests dropped because every invoke ID was in flight."}),
		Unsupported:          f.NewCounter(prometheus.CounterOpts{Name: "bacnet_shield_unsupported_total", Help: "Frames or services the single-device gateway cannot serve."}),
		Replayed:             f.NewCounter(prometheus.CounterOpts{Name: "bacnet_shield_replayed_total", Help: "Retransmissions answered from the finished-response cache."}),
		Retransmits:          f.NewCounter(prometheus.CounterOpts{Name: "bacnet_shield_retransmits_dropped_total", Help: "Retransmissions dropped because the request is still in flight."}),
		NotificationsDropped: f.NewCounter(prometheus.CounterOpts{Name: "bacnet_shield_notifications_dropped_total", Help: "Device notifications with no client to receive them."}),
		Pending:              f.NewGauge(prometheus.GaugeOpts{Name: "bacnet_shield_pending", Help: "Requests currently in flight toward the device."}),
		Subscriptions:        f.NewGauge(prometheus.GaugeOpts{Name: "bacnet_shield_cov_subscriptions", Help: "Active COV subscriptions routed by the proxy."}),
	}
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
