// Command bacnet-shield runs one process of the BACnet/IP security proxy. The
// process is configured either by a YAML file (--config) or entirely by flags,
// for plug-and-play deployments without config files. A file may describe one
// device or several co-hosted listener<->device pairs; flags always describe a
// single device.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"reflect"
	"strings"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/spf13/pflag"
	"go.uber.org/zap"

	"github.com/GalaxyGorilla/bacnet-shield/internal/bacnet/sc"
	"github.com/GalaxyGorilla/bacnet-shield/internal/config"
	"github.com/GalaxyGorilla/bacnet-shield/internal/observ"
	"github.com/GalaxyGorilla/bacnet-shield/internal/proxy"
	"github.com/GalaxyGorilla/bacnet-shield/internal/scnet"
	"github.com/GalaxyGorilla/bacnet-shield/internal/watchdog"
)

// version is overridden for releases via ldflags.
var version = "0.1.0"

func main() {
	os.Exit(run())
}

func run() int {
	if len(os.Args) < 2 {
		usage(os.Stderr)
		return 2
	}
	switch os.Args[1] {
	case "version", "--version", "-v":
		fmt.Printf("bacnet-shield %s\n", version)
		return 0
	case "gateway":
		return runGateway(os.Args[2:])
	case "validate":
		return runValidate(os.Args[2:])
	case "selftest":
		return runSelftest(os.Args[2:])
	case "help", "--help", "-h":
		usage(os.Stdout)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		usage(os.Stderr)
		return 2
	}
}

// parseFlags parses args, treating --help as a successful request for usage.
func parseFlags(fs *pflag.FlagSet, args []string) (bool, int) {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, pflag.ErrHelp) {
			usage(os.Stdout)
			return false, 0
		}
		return false, 2
	}
	if len(fs.Args()) > 0 {
		fmt.Fprintf(os.Stderr, "unexpected argument %q\n", fs.Args()[0])
		return false, 2
	}
	return true, 0
}

// loadChecked builds a validated Config the way the gateway subcommand does:
// --config YAML, or direct flags.
func loadChecked(o *config.Options) (*config.Config, error) {
	if o.ConfigPath != "" {
		return config.Load(o.ConfigPath)
	}
	return o.Build()
}

// runningDevice is one co-hosted device: its validated config, its gateway
// and (when configured) its own BACnet/SC node.
type runningDevice struct {
	dev config.Device
	gw  *proxy.Gateway
	met *observ.Metrics
	sc  *scnet.Node
}

// buildDevices builds and binds every configured device. Binding happens here,
// not in Serve, so a port conflict is a startup error rather than a goroutine
// that dies quietly after the process has already announced readiness. A
// failure closes the gateways already built.
func buildDevices(cfg *config.Config, log *zap.Logger, reg *prometheus.Registry, audit *observ.Audit) ([]*runningDevice, error) {
	out := make([]*runningDevice, 0, len(cfg.Devices))
	closeAll := func() {
		for _, rd := range out {
			_ = rd.gw.Close()
		}
	}
	for i := range cfg.Devices {
		d := cfg.Devices[i]
		pol, err := d.AccessPolicy()
		if err != nil {
			closeAll()
			return nil, fmt.Errorf("device %q: %w", d.Name, err)
		}
		met := observ.NewMetricsForDevice(reg, d.Name)
		g, err := proxy.New(proxy.Config{
			ListenAddr:      d.ListenAddr,
			DeviceAddr:      d.DeviceAddr,
			DeviceLocalAddr: d.DeviceLocalAddr,
			RequestTimeout:  time.Duration(d.RequestTimeoutSecs) * time.Second,
			MaxPending:      d.MaxPending,
			DeviceInstance:  d.DeviceInstance,
			DeviceName:      d.Name,
			Audit:           audit,
		}, pol, log, met)
		if err != nil {
			closeAll()
			return nil, fmt.Errorf("device %q: %w", d.Name, err)
		}
		rd := &runningDevice{dev: d, gw: g, met: met}
		if d.SC.Enabled() {
			node, err := buildSCNode(d.SC, log)
			if err != nil {
				_ = g.Close()
				closeAll()
				return nil, fmt.Errorf("device %q: %w", d.Name, err)
			}
			// Attach before Serve: a hub can deliver an NPDU as soon as the
			// node connects, and the handler must already be in place.
			g.AttachSC(node)
			// Expose the link state per device. The handler runs on the
			// node's goroutine, so the "already attached" flag needs no lock.
			attached := false
			node.SetStateHandler(func(connected bool, hub string) {
				if !connected {
					met.SCConnected.Set(0)
					return
				}
				if attached {
					met.SCReconnects.Inc()
				}
				attached = true
				met.SCConnected.Set(1)
			})
			rd.sc = node
		}
		out = append(out, rd)
	}
	return out, nil
}

// runGateway runs the proxy until a signal arrives.
func runGateway(args []string) int {
	fs := pflag.NewFlagSet("gateway", pflag.ContinueOnError)
	o := config.Register(fs)
	ok, code := parseFlags(fs, args)
	if !ok {
		return code
	}

	cfg, err := loadChecked(o)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config: %v\n", err)
		return 2
	}
	log, err := observ.NewLogger(cfg.LogLevel)
	if err != nil {
		fmt.Fprintf(os.Stderr, "logger: %v\n", err)
		return 1
	}
	defer func() { _ = log.Sync() }()

	// One registry for the whole process: every device registers its own
	// instrument set on it, so /metrics stays a single, per-device-labelled
	// scrape.
	registry := observ.NewRegistry()
	var metricsLn net.Listener
	if cfg.Metrics.Addr != "" {
		metricsLn, err = observ.Listen(cfg.Metrics.Addr)
		if err != nil {
			log.Error("metrics listener", zap.Error(err))
			return 1
		}
	}

	// The audit stream is opt-in and process-wide. It is a bounded,
	// non-blocking sink: a full queue drops records (and counts them) rather
	// than stalling the data plane, so an on-list client cannot flood the
	// disk through the log path. Each record names the device it concerns.
	// The drop counter is a process property (one queue serves every device),
	// so it is registered once on the shared registry, not per device.
	var audit *observ.Audit
	if cfg.Audit.File != "" {
		audit, err = observ.NewAuditFile(cfg.Audit.File, int64(cfg.Audit.MaxMB)<<20, observ.NewProcessMetrics(registry).AuditDropped)
		if err != nil {
			if metricsLn != nil {
				_ = metricsLn.Close()
			}
			log.Error("open audit file", zap.Error(err))
			return 1
		}
		defer func() { _ = audit.Close() }()
		log.Info("audit stream enabled", zap.String("file", cfg.Audit.File), zap.Int("max_mb", cfg.Audit.MaxMB))
	}

	devices, err := buildDevices(cfg, log, registry, audit)
	if err != nil {
		if metricsLn != nil {
			_ = metricsLn.Close()
		}
		log.Error("build gateway", zap.Error(err))
		return 1
	}

	gws := make([]*proxy.Gateway, len(devices))
	for i, rd := range devices {
		gws[i] = rd.gw
	}
	runner := proxy.NewRunner(gws)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	served := make(chan struct{})
	go func() {
		defer close(served)
		_ = runner.Serve(ctx)
	}()
	for _, rd := range devices {
		if rd.sc == nil {
			continue
		}
		rd := rd
		go func() {
			if err := rd.sc.Run(ctx); err != nil && ctx.Err() == nil {
				log.Error("bacnet/sc node stopped", zap.String("device", rd.dev.Name), zap.Error(err))
			}
		}()
	}
	if metricsLn != nil {
		go func() {
			if err := observ.ServeListener(ctx, metricsLn, observ.HandlerFor(registry), log); err != nil {
				log.Error("metrics listener", zap.Error(err))
			}
		}()
	}

	log.Info("bacnet-shield gateway listening", zap.Int("devices", len(devices)))
	for _, rd := range devices {
		fields := []zap.Field{
			zap.String("device", rd.dev.Name),
			zap.String("listen", rd.gw.ClientAddr().String()),
			zap.String("device_addr", rd.dev.DeviceAddr),
			zap.String("device_local", rd.gw.DeviceLocalAddr().String()),
			zap.Int("max_pending", rd.dev.MaxPending),
		}
		if rd.sc != nil {
			fields = append(fields, zap.String("sc_vmac", rd.dev.SC.VMAC), zap.Strings("sc_hubs", rd.dev.SC.Hubs))
		}
		log.Info("device serving", fields...)
	}

	if wd := watchdog.Interval(); wd > 0 {
		log.Info("systemd watchdog enabled", zap.Duration("interval", wd))
	}
	if _, err := watchdog.NotifyReady(); err != nil {
		log.Warn("sd_notify READY failed", zap.Error(err))
	}

	// SIGINT/SIGTERM shut down; SIGHUP re-reads the config file and applies
	// the reloadable parts (each device's front-leg policy). A bad file on
	// SIGHUP is logged and the running configuration is kept: an operator
	// typo must never take the proxy down.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigCh)

	watchdogDone := make(chan struct{})
	defer close(watchdogDone)
	if wd := watchdog.Interval(); wd > 0 {
		go watchdog.Start(wd, watchdogDone)
	}

	for {
		select {
		case sig := <-sigCh:
			if sig == syscall.SIGHUP {
				reload(o, cfg, devices, log)
				continue
			}
			log.Info("shutdown signal received", zap.String("signal", sig.String()))
			cancel()
			<-served
			return 0
		case <-served:
			// Serve only returns after cancellation; reaching here without
			// a signal means it stopped on its own.
			return 0
		}
	}
}

// reload applies the parts of a new config that do not need a restart. Each
// device's front-leg policy (allow-list, rate limit, device budget, write
// rules) is swapped atomically, so in-flight requests keep the policy they
// started under. Devices are matched by name; adding or removing a device, or
// changing anything bound to a socket or the SC identity, needs a restart and
// is reported rather than silently ignored.
func reload(o *config.Options, cur *config.Config, devices []*runningDevice, log *zap.Logger) {
	if o.ConfigPath == "" {
		log.Warn("SIGHUP ignored: reload requires --config (flags-mode settings come from the command line)")
		return
	}
	cfg, err := config.Load(o.ConfigPath)
	if err != nil {
		log.Error("reload: new config invalid, keeping the running configuration", zap.Error(err))
		return
	}

	for _, w := range topLevelRestartOnlyChanges(cur, cfg) {
		log.Warn("reload: " + w)
	}

	running := make(map[string]bool, len(devices))
	for _, rd := range devices {
		running[rd.dev.Name] = true
	}

	for _, rd := range devices {
		nd := findDevice(cfg, rd.dev.Name)
		if nd == nil {
			log.Warn("reload: device no longer in the config; still serving until restart",
				zap.String("device", rd.dev.Name))
			continue
		}
		for _, w := range deviceRestartOnlyChanges(rd.dev.Name, &rd.dev, nd) {
			log.Warn("reload: " + w)
		}
		pol, err := nd.AccessPolicy()
		if err != nil {
			log.Error("reload: device policy invalid, keeping the running policy",
				zap.String("device", rd.dev.Name), zap.Error(err))
			continue
		}
		rd.gw.SetPolicy(pol)
		log.Info("reload: device policy reloaded", zap.String("device", rd.dev.Name))
	}
	for i := range cfg.Devices {
		if !running[cfg.Devices[i].Name] {
			log.Warn("reload: device is new in the config; not serving until restart",
				zap.String("device", cfg.Devices[i].Name))
		}
	}

	*cur = *cfg
	log.Info("SIGHUP: configuration reloaded", zap.Int("devices", len(devices)))
}

// findDevice returns the config entry for a running device (matched by name,
// the identity the logs, metrics and the audit use).
func findDevice(cfg *config.Config, name string) *config.Device {
	for i := range cfg.Devices {
		if cfg.Devices[i].Name == name {
			return &cfg.Devices[i]
		}
	}
	return nil
}

// buildSCNode turns the validated sc block into a node. Validation already
// checked the VMAC/UUID/URL shapes; this is the point where a bad certificate
// or key file becomes a startup error rather than a reconnect loop.
func buildSCNode(s config.SC, log *zap.Logger) (*scnet.Node, error) {
	vmac, err := sc.ParseMAC(s.VMAC)
	if err != nil {
		return nil, err
	}
	uuid, err := sc.ParseUUID(s.UUID)
	if err != nil {
		return nil, err
	}
	tlsCfg, err := scnet.ClientTLS(s.CAFile, s.CertFile, s.KeyFile)
	if err != nil {
		return nil, err
	}
	return scnet.NewNode(scnet.NodeConfig{
		VMAC: vmac,
		UUID: uuid,
		Hubs: s.Hubs,
		TLS:  tlsCfg,
	}, log)
}

// topLevelRestartOnlyChanges names the process-wide fields a reload cannot
// apply. Device fields are compared per device.
func topLevelRestartOnlyChanges(old, next *config.Config) []string {
	var out []string
	if old.LogLevel != next.LogLevel {
		out = append(out, fmt.Sprintf("log_level changed (%q -> %q); restart required", old.LogLevel, next.LogLevel))
	}
	if old.Metrics.Addr != next.Metrics.Addr {
		out = append(out, fmt.Sprintf("metrics.addr changed (%q -> %q); restart required", old.Metrics.Addr, next.Metrics.Addr))
	}
	if !reflect.DeepEqual(old.Audit, next.Audit) {
		out = append(out, "audit.* changed; restart required")
	}
	return out
}

// deviceRestartOnlyChanges names the fields of one device a reload cannot
// apply: everything bound to a socket or to the SC identity.
func deviceRestartOnlyChanges(name string, old, next *config.Device) []string {
	var out []string
	add := func(field, a, b string) {
		if a != b {
			out = append(out, fmt.Sprintf("device %s: %s changed (%q -> %q); restart required", name, field, a, b))
		}
	}
	add("listen_addr", old.ListenAddr, next.ListenAddr)
	add("device_addr", old.DeviceAddr, next.DeviceAddr)
	add("device_local_addr", old.DeviceLocalAddr, next.DeviceLocalAddr)
	if old.RequestTimeoutSecs != next.RequestTimeoutSecs {
		out = append(out, fmt.Sprintf("device %s: request_timeout_secs changed (%d -> %d); restart required",
			name, old.RequestTimeoutSecs, next.RequestTimeoutSecs))
	}
	if old.MaxPending != next.MaxPending {
		out = append(out, fmt.Sprintf("device %s: max_pending changed (%d -> %d); restart required",
			name, old.MaxPending, next.MaxPending))
	}
	if instanceChanged(old.DeviceInstance, next.DeviceInstance) {
		out = append(out, fmt.Sprintf("device %s: device_instance changed; restart required", name))
	}
	if !reflect.DeepEqual(old.SC, next.SC) {
		out = append(out, fmt.Sprintf("device %s: sc.* changed (vmac, uuid, hubs or TLS); restart required", name))
	}
	return out
}

func instanceChanged(a, b *uint32) bool {
	if (a == nil) != (b == nil) {
		return true
	}
	return a != nil && *a != *b
}

// check is one validate/selftest result line.
type check struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
}

// report is the JSON document printed by validate --json and selftest --json.
type report struct {
	OK     bool    `json:"ok"`
	Error  string  `json:"error,omitempty"`
	Checks []check `json:"checks,omitempty"`
}

func finishReport(rep report, jsonOut bool, kind string) int {
	rep.OK = rep.Error == ""
	if jsonOut {
		out, _ := json.Marshal(rep)
		fmt.Println(string(out))
	}
	if !rep.OK {
		if !jsonOut {
			fmt.Fprintf(os.Stderr, "invalid: %s\n", rep.Error)
		}
		return 1
	}
	if !jsonOut {
		fmt.Printf("%s ok\n", kind)
	}
	return 0
}

// runValidate loads and validates a configuration without running the proxy.
// Exit 0 = valid, 1 = invalid. This is the pre-apply hook for tooling and
// appliance commissioning.
func runValidate(args []string) int {
	fs := pflag.NewFlagSet("validate", pflag.ContinueOnError)
	o := config.Register(fs)
	jsonOut := fs.Bool("json", false, "machine-readable JSON output")
	ok, code := parseFlags(fs, args)
	if !ok {
		return code
	}

	var rep report
	cfg, err := loadChecked(o)
	if err != nil {
		rep.Error = err.Error()
		return finishReport(rep, *jsonOut, "validate")
	}
	rep.Checks = configChecks(cfg)
	return finishReport(rep, *jsonOut, "validate")
}

// configChecks summarizes a validated config for a human or a tool: one line
// per configured device plus the process-wide settings.
func configChecks(cfg *config.Config) []check {
	out := []check{{Name: "config", OK: true,
		Detail: fmt.Sprintf("%d device(s), log_level %s", len(cfg.Devices), cfg.LogLevel)}}
	if cfg.Audit.File != "" {
		out = append(out, check{Name: "audit", OK: true,
			Detail: fmt.Sprintf("%s (rotate at %d MiB)", cfg.Audit.File, cfg.Audit.MaxMB)})
	}
	for i := range cfg.Devices {
		out = append(out, deviceCheck(&cfg.Devices[i]))
	}
	return out
}

// deviceCheck summarizes one device entry.
func deviceCheck(d *config.Device) check {
	detail := fmt.Sprintf("%s -> %s", d.ListenAddr, d.DeviceAddr)
	if d.Access.ReadOnly {
		detail += " (read-only)"
	}
	if n := len(d.Access.Allow); n > 0 {
		detail += fmt.Sprintf(" (allowlist(%d))", n)
	}
	if d.Access.RatePerSec > 0 {
		detail += fmt.Sprintf(" (rate %.2f/s per client)", d.Access.RatePerSec)
	}
	if d.Access.DeviceRatePerSec > 0 {
		detail += fmt.Sprintf(" (device rate %.2f/s)", d.Access.DeviceRatePerSec)
	}
	if d.DeviceInstance != nil {
		detail += fmt.Sprintf(" (device,%d)", *d.DeviceInstance)
	}
	if d.SC.Enabled() {
		detail += fmt.Sprintf(" [sc vmac %s -> %s]", d.SC.VMAC, strings.Join(d.SC.Hubs, ", "))
		if n := len(d.Access.SCAllow); n > 0 {
			detail += fmt.Sprintf(" (sc_allow(%d))", n)
		}
	}
	return check{Name: "device " + d.Name, OK: true, Detail: detail}
}

// runSelftest validates the configuration and probes each device leg directly
// from this host with a real BACnet request, proving reachability. It is
// designed for commissioning and health checks. Exit 0 = all checks passed.
func runSelftest(args []string) int {
	fs := pflag.NewFlagSet("selftest", pflag.ContinueOnError)
	o := config.Register(fs)
	jsonOut := fs.Bool("json", false, "machine-readable JSON output")
	probe := fs.Bool("probe", true, "run the network probe (--probe=false checks config only)")
	ok, code := parseFlags(fs, args)
	if !ok {
		return code
	}

	var rep report
	cfg, err := loadChecked(o)
	if err != nil {
		rep.Error = "config: " + err.Error()
		return finishSelftest(rep, *jsonOut)
	}
	rep.Checks = configChecks(cfg)

	if *probe {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		for i := range cfg.Devices {
			d := cfg.Devices[i]
			res, err := proxy.ProbeDevice(ctx, d.DeviceAddr, d.DeviceInstance)
			c := check{Name: "device " + d.Name}
			if err != nil {
				c.Detail = err.Error()
			} else {
				c.OK = true
				c.Detail = res.Detail
			}
			rep.Checks = append(rep.Checks, c)
		}
	}

	for _, ch := range rep.Checks {
		if !ch.OK {
			rep.Error = ch.Name + ": " + ch.Detail
			break
		}
	}
	return finishSelftest(rep, *jsonOut)
}

func finishSelftest(rep report, jsonOut bool) int {
	rep.OK = rep.Error == ""
	if jsonOut {
		out, _ := json.Marshal(rep)
		fmt.Println(string(out))
	} else {
		for _, ch := range rep.Checks {
			status := "ok"
			if !ch.OK {
				status = "FAIL"
			}
			if ch.Detail != "" {
				fmt.Printf("  %-16s %-4s %s\n", ch.Name, status, ch.Detail)
			} else {
				fmt.Printf("  %-16s %-4s\n", ch.Name, status)
			}
		}
		if rep.OK {
			fmt.Println("selftest passed")
		}
	}
	if !rep.OK {
		fmt.Fprintf(os.Stderr, "selftest FAILED: %s\n", rep.Error)
		return 1
	}
	return 0
}

func usage(w *os.File) {
	fmt.Fprintf(w, `bacnet-shield — BACnet/IP security proxy for one or more legacy devices

Usage (config file, one or more devices):
  bacnet-shield gateway --config <file>

Usage (flags, no config file — one device, plug and play):
  bacnet-shield gateway --listen <ip:port> --device <legacy-device:port> \
      [--read-only] [--allow <ip|cidr>]... [--rate-per-sec <n>] \
      [--device-rate-per-sec <n>] \
      [--write-default deny|allow] [--write-allow <spec>]... \
      [--write-deny <spec>]... [--request-timeout <secs>] \
      [--max-pending <n>] [--device-instance <n>] \
      [--device-local <ip:port>] [--metrics-addr <addr>] \
      [--audit-file <path>] [--audit-max-mb <n>] \
      [--log-level <lvl>] \
      [--sc-vmac <vmac> --sc-uuid <uuid> --sc-hub <wss://url>... \
       [--sc-ca <pem>] [--sc-cert <pem>] [--sc-key <pem>] \
       [--sc-allow <vmac>]...]

The process sits between a building's clients and one or more legacy devices.
Each devices: entry in the file couples exactly one front-leg listener with one
device and carries that device's own policy, so one process can protect several
devices without becoming a router:

  devices:
    - name: boiler            # label in logs, metrics and the audit
      listen_addr: 192.0.2.10:47808   # this device's own local IP, port 47808
      device_addr: 10.0.0.42:47808
      access:
        allow: ["192.0.2.0/24"]
        read_only: true
    - name: ahu
      listen_addr: 192.0.2.11:47808
      device_addr: 10.0.0.43:47808

Give each device its own local IP on the standard port 47808, so a client's
broadcast Who-Is still reaches the whole building. Flags mode always configures
exactly one device.

It rewrites only the network layer and the APDU invoke ID; the service
payload is forwarded byte for byte, so vendor quirks survive. Client-leg
policy is enforced before anything reaches the device: an allow-list, a
per-client rate limit (plus an optional shared device budget), and an
object/property-scoped write policy. ACL and
rate denials are silent; a refused write is answered with a BACnet Error
PDU (class security, code write-access-denied) so the client is not left
waiting for a timeout.

Write policy (object-scoped, instead of all-or-nothing --read-only):
  --write-allow '<object-type>:<instance>:<property>'   repeatable
  --write-deny  '<object-type>:<instance>:<property>'   repeatable
  --write-default deny|allow   verdict for uncovered writes
    'analog-value:5:present-value'   one property
    'analog-value:*:present-value'   every instance of a type
    '*:*:present-value'              every present-value
  Deny wins over allow; an allow must cover the whole write target, so a
  WritePropertyMultiple can never straddle an allowed rule. An undecodable
  or segmented write is denied. Mutually exclusive with --read-only.

BACnet/SC front leg: with an sc: block (or the --sc-* flags) the device's
proxy attaches to an existing hub as a node, never as a hub. A client is
identified by its VMAC, so SC nodes share the same pending table, replay cache,
COV routing and write policy as IP clients and are independent of each other.
Each device with an sc block is its own SC node (own VMAC) — give each a
distinct vmac. --sc-allow opts into a VMAC allow-list; with none configured
every node the hub delivers is accepted and only the write policy gates it.
--sc-ca replaces the system roots; --sc-cert/--sc-key present a client
certificate. The clear device leg stays plain BACnet/IP.

Reload: send SIGHUP to re-read --config and swap each device's access policy
(including sc_allow) in place, matched by device name. Adding or removing a
device, and any listener, device address, timeout, max_pending or SC
identity/hub/TLS change, needs a restart and is reported as a warning.

Audit: with --audit-file (or audit.file in YAML) every security decision the
front leg makes (ACL, rate limit, device budget, write policy, unsupported
subscription) is appended as one JSON object per line, naming the device and,
for a refused write, the decoded object/property target. The file rotates at
--audit-max-mb, keeping one backup, so it is bounded; a full in-memory queue
drops records and counts them (bacnet_shield_audit_dropped_total) rather than
stalling the data plane. The audit is off unless a file is configured.

Other commands:
  bacnet-shield validate [--config <file> | same flags as gateway] [--json]
      check a configuration without running (pre-apply for tooling)
  bacnet-shield selftest [--config <file> | same flags as gateway]
      [--probe=false] [--json]
      validate + probe each device with a real BACnet ReadProperty or Who-Is
  bacnet-shield version
`)
}
