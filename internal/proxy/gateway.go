// Package proxy is the BACnet/IP retrofit gateway. A Gateway is one box
// between a building's clients and ONE legacy device; a Runner composes
// several independent Gateways into one process (co-hosting), without routing
// traffic between them.
//
//	[N clients] --BACnet/IP--> [bacnet-shield] --BACnet/IP--> [legacy device]
//
// The proxy is not a BACnet device stack and does not translate services. It
// decodes just enough of the link, network and application layers to route a
// request to the device, correlate the answer back to the client that asked,
// and enforce the front-leg policy (ACL, rate limit, write rules). The service
// payload itself is forwarded byte for byte, so vendor quirks survive.
//
// Two pieces of state make the one-device-per-Gateway model work:
//
//   - invoke-ID translation: every client has its own one-octet invoke-ID
//     space, so two clients may have request 7 in flight at once. The proxy
//     allocates a device-leg ID per client request and rewrites the octet in
//     place on the way out and back.
//   - COV subscriber tracking: a SubscribeCOV forwarded from the proxy's
//     device socket makes the device notify the proxy. The proxy remembers
//     which client asked for which monitored object and forwards the
//     notification to that client.
//
// Everything else is deliberately pass-through. In particular the proxy never
// caches property values: a read always reaches the device, because a stale
// setpoint in a building is worse than a slow one.
package proxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"

	"github.com/GalaxyGorilla/bacnet-shield/internal/access"
	"github.com/GalaxyGorilla/bacnet-shield/internal/bacnet"
	"github.com/GalaxyGorilla/bacnet-shield/internal/observ"
	"github.com/GalaxyGorilla/bacnet-shield/internal/safego"
)

// Config is the gateway's runtime shape. The command layer maps the YAML/flags
// config onto it; the proxy does not read files.
type Config struct {
	// ListenAddr is the client leg. ":47808" is the BACnet/IP port. An IPv6
	// literal (for example "[::]:47808") selects the BACnet/IPv6 link layer
	// for this listener; the device leg remains IPv4.
	ListenAddr string
	// DeviceAddr is the one legacy device on the clear leg. It must be a
	// unicast IPv4 address: the proxy accepts device-leg datagrams only from
	// this host.
	DeviceAddr string
	// DeviceLocalAddr optionally pins the source address of the device leg.
	// Empty means an ephemeral port, which is what a BACnet client uses.
	DeviceLocalAddr string
	// RequestTimeout bounds how long a forwarded request stays pending.
	RequestTimeout time.Duration
	// MaxPending caps in-flight client requests (1..256; the invoke ID is
	// one octet).
	MaxPending int
	// DeviceInstance optionally pins the expected device instance. It never
	// gates traffic; a mismatch is a warning (and a selftest failure).
	DeviceInstance *uint32
	// DeviceName labels the device in logs, metrics and audit records. It is
	// the config entry's `name` (or its device address).
	DeviceName string
	// Audit, when non-nil, receives one structured record per security
	// decision. A nil audit records nothing.
	Audit *observ.Audit
}

const (
	// clientIdle is how long a client stays in the active table for
	// unsolicited notifications (I-Am, events). It is longer than a typical
	// poll interval so a quiet workstation still receives broadcasts.
	clientIdle = 5 * time.Minute
	// maxClients bounds the active table. It is a table of addresses that
	// have already passed the ACL, so it is not attacker-controlled in the
	// same way the rate-limit table is; the cap is still a hard backstop.
	maxClients = 1024
	// completedTTL is how long a finished response is replayed to a
	// retransmitted request. BACnet's APDU retry timer is seconds, not
	// minutes; 30s covers a lossy building network without holding state.
	completedTTL = 30 * time.Second
	// maxCompleted bounds the replay cache.
	maxCompleted = 2048
	// segmentGrace keeps a completed segmented exchange routable for the
	// client's final SegmentACK.
	segmentGrace = 10 * time.Second
	// sweepInterval is the expiry cadence. One second is cheap at the table
	// sizes above and keeps a dead request from occupying an invoke ID for
	// noticeably longer than its deadline.
	sweepInterval = time.Second
	// maxSubscriptions bounds the COV routing table. A client can create
	// subscriptions for arbitrary object identifiers; without a cap, a
	// hostile client with an ACK-happy device could grow the table without
	// bound. At the cap new subscriptions are accepted by the device but
	// not routed, and the client sees no notifications (the same visible
	// result as a device that never notifies).
	maxSubscriptions = 4096
	// drainGrace bounds how long shutdown waits for already-forwarded
	// requests to be answered. A building controller must not lose a write
	// because the service was restarted between the request and its ACK,
	// but a wedged device must not hold the process open either. Two
	// seconds covers a slow LAN round trip; the rest of the request timeout
	// is the client's problem, not shutdown's.
	drainGrace = 2 * time.Second
)

// Gateway is one running proxy instance.
type Gateway struct {
	cfg     Config
	name    string
	log     *zap.Logger
	metrics *observ.Metrics
	audit   *observ.Audit
	policy  atomic.Pointer[access.Policy]

	clientConn *net.UDPConn
	clientIPv6 bool
	clientVMAC bacnet.VMAC
	deviceConn *net.UDPConn
	deviceAddr *net.UDPAddr
	deviceIP   net.IP
	scLeg      SCLeg

	mu         sync.Mutex
	pending    map[byte]*pendingReq     // device invoke ID -> client request
	byClient   map[clientKey]byte       // (client, client ID) -> device ID
	done       map[clientKey]*completed // finished response replay cache
	segWrites  map[clientKey]*segWrite  // in-progress segmented writes
	usedIDs    [4]uint64                // device invoke IDs in use
	fromDevice map[byte]*deviceExchange // device invoke ID -> forwarded client request
	toDevice   map[clientKey]byte       // (client, client ID) -> device ID
	clients    map[string]*clientState
	cov        map[bacnet.ObjectID]map[covSubKey]*subscription
	subCount   int

	closeOnce sync.Once
	draining  atomic.Bool
	wg        sync.WaitGroup

	// drainTimeout bounds the shutdown drain. New sets it to drainGrace;
	// tests shorten it so an unanswered request does not make every test
	// wait two seconds.
	drainTimeout time.Duration
}

// New resolves the device, binds both legs, and returns a gateway ready for
// Serve. Binding here (not in Serve) makes a port conflict a startup error
// instead of a goroutine that dies quietly.
func New(cfg Config, pol *access.Policy, log *zap.Logger, m *observ.Metrics) (*Gateway, error) {
	if log == nil {
		log = zap.NewNop()
	}
	if m == nil {
		m = observ.NewMetrics()
	}
	if cfg.RequestTimeout <= 0 {
		cfg.RequestTimeout = 30 * time.Second
	}
	if cfg.MaxPending <= 0 || cfg.MaxPending > 256 {
		return nil, fmt.Errorf("proxy: max_pending %d outside 1..256", cfg.MaxPending)
	}
	deviceAddr, err := net.ResolveUDPAddr("udp4", cfg.DeviceAddr)
	if err != nil {
		return nil, fmt.Errorf("proxy: device address %q: %w", cfg.DeviceAddr, err)
	}
	if deviceAddr.IP == nil || deviceAddr.IP.To4() == nil {
		return nil, fmt.Errorf("proxy: device address %q is not IPv4 (the device leg is IPv4-only)", cfg.DeviceAddr)
	}
	listenAddr, network, err := resolveListen(cfg.ListenAddr)
	if err != nil {
		return nil, fmt.Errorf("proxy: listen address %q: %w", cfg.ListenAddr, err)
	}
	clientConn, err := net.ListenUDP(network, listenAddr)
	if err != nil {
		return nil, fmt.Errorf("proxy: bind client leg %q: %w", cfg.ListenAddr, err)
	}
	clientIPv6 := network == "udp6"
	var clientVMAC bacnet.VMAC
	if clientIPv6 {
		clientVMAC = deriveVMAC(listenAddr)
	}
	var local *net.UDPAddr
	if cfg.DeviceLocalAddr != "" {
		local, err = net.ResolveUDPAddr("udp4", cfg.DeviceLocalAddr)
		if err != nil {
			_ = clientConn.Close()
			return nil, fmt.Errorf("proxy: device local address %q: %w", cfg.DeviceLocalAddr, err)
		}
	}
	deviceConn, err := net.ListenUDP("udp4", local)
	if err != nil {
		_ = clientConn.Close()
		return nil, fmt.Errorf("proxy: bind device leg: %w", err)
	}
	g := &Gateway{
		cfg:          cfg,
		name:         cfg.DeviceName,
		log:          log,
		metrics:      m,
		audit:        cfg.Audit,
		clientConn:   clientConn,
		clientIPv6:   clientIPv6,
		clientVMAC:   clientVMAC,
		deviceConn:   deviceConn,
		deviceAddr:   deviceAddr,
		deviceIP:     deviceAddr.IP.To4(),
		pending:      make(map[byte]*pendingReq),
		byClient:     make(map[clientKey]byte),
		done:         make(map[clientKey]*completed),
		segWrites:    make(map[clientKey]*segWrite),
		fromDevice:   make(map[byte]*deviceExchange),
		toDevice:     make(map[clientKey]byte),
		clients:      make(map[string]*clientState),
		cov:          make(map[bacnet.ObjectID]map[covSubKey]*subscription),
		drainTimeout: drainGrace,
	}
	g.policy.Store(pol)
	return g, nil
}

// ClientAddr is the bound client-leg address. Tests use it with ":0"; the
// command uses it for the readiness log.
func (g *Gateway) ClientAddr() *net.UDPAddr {
	return g.clientConn.LocalAddr().(*net.UDPAddr)
}

// DeviceLocalAddr is the bound source address of the device leg.
func (g *Gateway) DeviceLocalAddr() *net.UDPAddr {
	return g.deviceConn.LocalAddr().(*net.UDPAddr)
}

// Name is the device label (the config entry's name, or its device address).
func (g *Gateway) Name() string { return g.name }

// SetPolicy swaps the front-leg policy. It is safe while Serve is running;
// a SIGHUP reload uses it.
func (g *Gateway) SetPolicy(p *access.Policy) { g.policy.Store(p) }

// Serve runs both read loops until ctx is cancelled, then drains in-flight
// requests and closes the sockets. A bind error is reported by New, so Serve
// only returns after shutdown.
func (g *Gateway) Serve(ctx context.Context) error {
	g.wg.Add(3)
	safego.Go(g.log, "gateway client loop", func() { defer g.wg.Done(); g.clientLoop(ctx) })
	safego.Go(g.log, "gateway device loop", func() { defer g.wg.Done(); g.deviceLoop(ctx) })
	safego.Go(g.log, "gateway sweeper", func() { defer g.wg.Done(); g.sweepLoop(ctx) })

	<-ctx.Done()
	g.drain()
	g.Close()
	g.wg.Wait()
	return nil
}

// drain stops accepting new front-leg datagrams and waits, briefly, for the
// device to answer requests that were already forwarded. The client socket
// stays open for writing: closing it would also destroy the answers the drain
// is waiting for. A read deadline is the only way to interrupt a blocked UDP
// read without closing the socket.
func (g *Gateway) drain() {
	g.draining.Store(true)
	_ = g.clientConn.SetReadDeadline(time.Now())
	grace := g.drainTimeout
	if grace <= 0 {
		grace = drainGrace
	}
	deadline := time.Now().Add(grace)
	for {
		g.mu.Lock()
		open := 0
		for _, p := range g.pending {
			// A request whose data was already delivered is only waiting
			// for the client's final SegmentACK; it is not worth holding
			// shutdown open for.
			if !p.complete {
				open++
			}
		}
		g.mu.Unlock()
		if open == 0 || !time.Now().Before(deadline) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// Close closes both sockets. It is idempotent.
func (g *Gateway) Close() error {
	var err error
	g.closeOnce.Do(func() {
		err = errors.Join(g.clientConn.Close(), g.deviceConn.Close())
	})
	return err
}

func (g *Gateway) clientLoop(ctx context.Context) {
	buf := make([]byte, 65535)
	for {
		n, src, err := g.clientConn.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			g.log.Warn("client leg read", zap.Error(err))
			continue
		}
		dg := buf[:n]
		safego.Dispatch(g.log, "gateway client datagram", func() { g.handleClient(dg, src) })
	}
}

func (g *Gateway) deviceLoop(ctx context.Context) {
	buf := make([]byte, 65535)
	for {
		n, src, err := g.deviceConn.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			g.log.Warn("device leg read", zap.Error(err))
			continue
		}
		dg := buf[:n]
		safego.Dispatch(g.log, "gateway device datagram", func() { g.handleDevice(dg, src) })
	}
}

func (g *Gateway) sweepLoop(ctx context.Context) {
	t := time.NewTicker(sweepInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			g.sweep(now)
		}
	}
}

// sweep expires pending requests, replay entries, device-initiated requests,
// subscriptions and idle clients. All tables are bounded; this is what keeps
// them bounded over a long run.
func (g *Gateway) sweep(now time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()

	for id, p := range g.pending {
		if now.After(p.deadline) {
			// A request that got its data but is only waiting for the
			// client's final SegmentACK is not an unanswered request;
			// counting it would make a slow client look like a dead
			// device.
			if !p.complete {
				g.metrics.RequestTimeouts.Inc()
			}
			g.dropPendingLocked(id)
			g.log.Debug("request timed out", zap.Uint8("device_invoke_id", id),
				zap.Stringer("client", p.client))
		}
	}
	for k, c := range g.done {
		if now.After(c.deadline) {
			delete(g.done, k)
		}
	}
	for id, ex := range g.fromDevice {
		if now.After(ex.deadline) {
			g.dropExchangeLocked(id)
		}
	}
	g.sweepSegWritesLocked(now)
	for obj, subs := range g.cov {
		for k, sub := range subs {
			if !sub.expires.IsZero() && now.After(sub.expires) {
				delete(subs, k)
				g.subCount--
				g.metrics.Subscriptions.Dec()
			}
		}
		if len(subs) == 0 {
			delete(g.cov, obj)
		}
	}
	for k, c := range g.clients {
		if now.Sub(c.last) > clientIdle {
			delete(g.clients, k)
		}
	}
}

func (g *Gateway) sendDevice(frame []byte) {
	if _, err := g.deviceConn.WriteToUDP(frame, g.deviceAddr); err != nil {
		g.log.Warn("device leg write", zap.Error(err), zap.Stringer("device", g.deviceAddr))
	}
}

func (g *Gateway) sendClientNPDU(npdu []byte, client peer) {
	if err := client.SendNPDU(npdu); err != nil {
		g.log.Debug("client leg write", zap.Error(err), zap.Stringer("client", client))
	}
}

// buildNPDU returns the network-layer bytes the proxy forwards: routing fields
// stripped, the APDU as given. The client leg wraps this in whatever link
// layer it speaks (BVLC for BACnet/IP, BVLL-SC for BACnet/SC), which is why the
// data plane and its replay cache hold NPDUs rather than link frames.
func buildNPDU(n bacnet.NPDU, apdu []byte) []byte {
	n = n.StripRouting()
	n.APDU = apdu
	return n.Marshal()
}

// buildFrame wraps an NPDU as a plain Original-Unicast BACnet/IP frame for the
// clear device leg. The gateway always speaks unicast to its device, even when a
// client sent a broadcast: this gateway has exactly one device, so a broadcast
// is a discovery request aimed at that device.
func buildFrame(n bacnet.NPDU, apdu []byte) []byte {
	return bacnet.BVLC{Function: bacnet.BVLCOriginalUnicastNPDU, Data: buildNPDU(n, apdu)}.Marshal()
}

// touchClient records a client for unsolicited notification delivery. It is
// called only after the ACL and rate checks, so an off-list source never enters
// the table. At the cap the oldest entry is evicted: a new legitimate client is
// more valuable than a stale one.
func (g *Gateway) touchClient(p peer, now time.Time) {
	key := p.Key()
	g.mu.Lock()
	defer g.mu.Unlock()
	if c, ok := g.clients[key]; ok {
		c.last = now
		c.peer = p
		return
	}
	if len(g.clients) >= maxClients {
		var oldestKey string
		var oldest time.Time
		for k, c := range g.clients {
			if oldestKey == "" || c.last.Before(oldest) {
				oldestKey, oldest = k, c.last
			}
		}
		delete(g.clients, oldestKey)
	}
	g.clients[key] = &clientState{peer: p, last: now}
}

// activeClients snapshots the clients that should receive a broadcast-shaped
// notification. The slice is a copy; the caller may send to it without the
// lock.
func (g *Gateway) activeClients() []peer {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := time.Now()
	out := make([]peer, 0, len(g.clients))
	for _, c := range g.clients {
		if now.Sub(c.last) <= clientIdle {
			out = append(out, c.peer)
		}
	}
	return out
}

type clientState struct {
	peer peer
	last time.Time
}
