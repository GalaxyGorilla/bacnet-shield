// Command bacnet-shield runs one gateway instance of the BACnet/IP security
// proxy. The instance is configured either by a YAML file (--config) or
// entirely by flags, for plug-and-play deployments without config files.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/pflag"
	"go.uber.org/zap"

	"github.com/GalaxyGorilla/bacnet-shield/internal/config"
	"github.com/GalaxyGorilla/bacnet-shield/internal/observ"
	"github.com/GalaxyGorilla/bacnet-shield/internal/proxy"
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

	pol, err := cfg.AccessPolicy()
	if err != nil {
		log.Error("compile access policy", zap.Error(err))
		return 1
	}
	metrics := observ.NewMetrics()
	var metricsLn net.Listener
	if cfg.Metrics.Addr != "" {
		metricsLn, err = observ.Listen(cfg.Metrics.Addr)
		if err != nil {
			log.Error("metrics listener", zap.Error(err))
			return 1
		}
	}
	g, err := proxy.New(proxy.Config{
		ListenAddr:      cfg.ListenAddr,
		DeviceAddr:      cfg.DeviceAddr,
		DeviceLocalAddr: cfg.DeviceLocalAddr,
		RequestTimeout:  time.Duration(cfg.RequestTimeoutSecs) * time.Second,
		MaxPending:      cfg.MaxPending,
		DeviceInstance:  cfg.DeviceInstance,
	}, pol, log, metrics)
	if err != nil {
		if metricsLn != nil {
			_ = metricsLn.Close()
		}
		log.Error("build gateway", zap.Error(err))
		return 1
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	served := make(chan struct{})
	go func() {
		defer close(served)
		_ = g.Serve(ctx)
	}()

	if metricsLn != nil {
		go func() {
			if err := observ.ServeListener(ctx, metricsLn, metrics.Handler(), log); err != nil {
				log.Error("metrics listener", zap.Error(err))
			}
		}()
	}

	log.Info("bacnet-shield gateway listening",
		zap.String("listen", g.ClientAddr().String()),
		zap.String("device", cfg.DeviceAddr),
		zap.String("device_local", g.DeviceLocalAddr().String()),
		zap.Int("max_pending", cfg.MaxPending))

	if wd := watchdog.Interval(); wd > 0 {
		log.Info("systemd watchdog enabled", zap.Duration("interval", wd))
	}
	if _, err := watchdog.NotifyReady(); err != nil {
		log.Warn("sd_notify READY failed", zap.Error(err))
	}

	// SIGINT/SIGTERM shut down; SIGHUP re-reads the config file and applies
	// the reloadable parts (the front-leg policy). A bad file on SIGHUP is
	// logged and the running configuration is kept: an operator typo must
	// never take the proxy down.
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
				reload(o, cfg, g, log)
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

// reload applies the parts of a new config that do not need a restart. The
// front-leg policy (allow-list, rate limit, write rules) is swapped atomically,
// so in-flight requests keep the policy they started under.
func reload(o *config.Options, cur *config.Config, g *proxy.Gateway, log *zap.Logger) {
	if o.ConfigPath == "" {
		log.Warn("SIGHUP ignored: reload requires --config (flags-mode settings come from the command line)")
		return
	}
	cfg, err := config.Load(o.ConfigPath)
	if err != nil {
		log.Error("reload: new config invalid, keeping the running configuration", zap.Error(err))
		return
	}
	pol, err := cfg.AccessPolicy()
	if err != nil {
		log.Error("reload: policy invalid, keeping the running configuration", zap.Error(err))
		return
	}
	g.SetPolicy(pol)

	for _, w := range restartOnlyChanges(cur, cfg) {
		log.Warn("reload: " + w)
	}
	*cur = *cfg
	log.Info("SIGHUP: access policy reloaded")
}

// restartOnlyChanges names the fields a reload cannot apply. Reporting them is
// the honest half of a partial reload: silently keeping the old listener while
// the file says otherwise is how an operator ends up debugging the wrong box.
func restartOnlyChanges(old, next *config.Config) []string {
	var out []string
	add := func(name, a, b string) {
		if a != b {
			out = append(out, fmt.Sprintf("%s changed (%q -> %q); restart required", name, a, b))
		}
	}
	add("listen_addr", old.ListenAddr, next.ListenAddr)
	add("device_addr", old.DeviceAddr, next.DeviceAddr)
	add("device_local_addr", old.DeviceLocalAddr, next.DeviceLocalAddr)
	add("log_level", old.LogLevel, next.LogLevel)
	add("metrics.addr", old.Metrics.Addr, next.Metrics.Addr)
	if old.RequestTimeoutSecs != next.RequestTimeoutSecs {
		out = append(out, "request_timeout_secs changed; restart required")
	}
	if old.MaxPending != next.MaxPending {
		out = append(out, "max_pending changed; restart required")
	}
	if (old.DeviceInstance == nil) != (next.DeviceInstance == nil) ||
		(old.DeviceInstance != nil && next.DeviceInstance != nil && *old.DeviceInstance != *next.DeviceInstance) {
		out = append(out, "device_instance changed; restart required")
	}
	return out
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

// configChecks summarizes a validated config for a human or a tool.
func configChecks(cfg *config.Config) []check {
	detail := fmt.Sprintf("%s -> %s", cfg.ListenAddr, cfg.DeviceAddr)
	if cfg.Access.ReadOnly {
		detail += " (read-only)"
	}
	if len(cfg.Access.Allow) > 0 {
		detail += fmt.Sprintf(" (allowlist(%d))", len(cfg.Access.Allow))
	}
	if cfg.Access.RatePerSec > 0 {
		detail += fmt.Sprintf(" (rate %.2f/s per client)", cfg.Access.RatePerSec)
	}
	out := []check{{Name: "config", OK: true, Detail: detail}}
	if cfg.DeviceInstance != nil {
		out = append(out, check{Name: "device-instance", OK: true,
			Detail: fmt.Sprintf("pinned to device,%d", *cfg.DeviceInstance)})
	}
	return out
}

// runSelftest validates the configuration and probes the device leg directly
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
		res, err := proxy.ProbeDevice(ctx, cfg.DeviceAddr, cfg.DeviceInstance)
		c := check{Name: "device " + cfg.DeviceAddr}
		if err != nil {
			c.Detail = err.Error()
		} else {
			c.OK = true
			c.Detail = res.Detail
		}
		rep.Checks = append(rep.Checks, c)
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
	fmt.Fprintf(w, `bacnet-shield — BACnet/IP security proxy for one legacy device

Usage (config file):
  bacnet-shield gateway --config <file>

Usage (flags, no config file — plug and play):
  bacnet-shield gateway --listen <ip:port> --device <legacy-device:port> \
      [--read-only] [--allow <ip|cidr>]... [--rate-per-sec <n>] \
      [--write-default deny|allow] [--write-allow <spec>]... \
      [--write-deny <spec>]... [--request-timeout <secs>] \
      [--max-pending <n>] [--device-instance <n>] \
      [--device-local <ip:port>] [--metrics-addr <addr>] \
      [--log-level <lvl>]

The gateway sits between a building's BACnet/IP clients and ONE legacy
device:

  [N clients] --BACnet/IP--> [bacnet-shield] --BACnet/IP--> [legacy device]

It rewrites only the network layer and the APDU invoke ID; the service
payload is forwarded byte for byte, so vendor quirks survive. Client-leg
policy is enforced before anything reaches the device: an allow-list, a
per-client rate limit, and an object/property-scoped write policy. ACL and
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

Reload: send SIGHUP to re-read --config and swap the access policy in
place. Listener, device address, timeouts and log level need a restart and
are reported as warnings.

Other commands:
  bacnet-shield validate [--config <file> | same flags as gateway] [--json]
      check a configuration without running (pre-apply for tooling)
  bacnet-shield selftest [--config <file> | same flags as gateway]
      [--probe=false] [--json]
      validate + probe the device with a real BACnet ReadProperty or Who-Is
  bacnet-shield version
`)
}
