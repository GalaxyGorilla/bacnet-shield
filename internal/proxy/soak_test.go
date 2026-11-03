// Soak test for the steady-state data plane: the property only minutes of
// continuous traffic can show.
//
// It is skipped unless BACNET_SHIELD_SOAK=1 (`make soak`), because a
// ten-minute test in `go test ./...` would be a ten-minute edit loop. The unit
// tests already pin correctness; this pins the operational shape: every
// request is answered, goroutines and live heap stay flat, and the pending
// gauge returns to zero — a leak does not need a crash to take down an
// appliance weeks later.
package proxy

import (
	"fmt"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/GalaxyGorilla/bacnet-shield/internal/bacnet"
	"github.com/GalaxyGorilla/bacnet-shield/internal/testkit"
)

const soakPollInterval = 5 * time.Millisecond

// startEchoDevice binds a real UDP socket that answers every confirmed
// ReadProperty with a ComplexACK. It is deliberately a plain protocol peer,
// not a mock: the proxy's production read, correlate and patch paths all run.
func startEchoDevice(t *testing.T, oid bacnet.ObjectID, prop bacnet.PropertyID) *net.UDPAddr {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("echo device bind: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	go func() {
		buf := make([]byte, 65535)
		for {
			n, src, err := conn.ReadFromUDP(buf)
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
			if a.Type != bacnet.PDUConfirmedRequest || a.Service != bacnet.ServiceReadProperty {
				continue
			}
			ack := readPropertyACK(a.InvokeID, oid, prop, []byte{0x44, 0x3F, 0x80, 0x00, 0x00})
			frame := bacnet.BVLC{
				Function: bacnet.BVLCOriginalUnicastNPDU,
				Data:     bacnet.NPDU{APDU: ack.Marshal()}.Marshal(),
			}.Marshal()
			_, _ = conn.WriteToUDP(frame, src)
		}
	}()

	return conn.LocalAddr().(*net.UDPAddr)
}

// soakRoundTrip sends one ReadProperty and waits for the answer with the same
// invoke ID. It never calls t.Fatalf, so a single lost datagram is counted
// rather than ending the run.
func soakRoundTrip(c *testClient, dst *net.UDPAddr, oid bacnet.ObjectID, prop bacnet.PropertyID, invoke byte) error {
	req := readProperty(invoke, oid, prop)
	frame := bacnet.BVLC{
		Function: bacnet.BVLCOriginalUnicastNPDU,
		Data:     bacnet.NPDU{APDU: req.Marshal()}.Marshal(),
	}.Marshal()
	if _, err := c.conn.WriteToUDP(frame, dst); err != nil {
		return err
	}
	a, _, _, err := c.recv(2 * time.Second)
	if err != nil {
		return err
	}
	if a.Type != bacnet.PDUComplexACK || a.InvokeID != invoke {
		return fmt.Errorf("answer %s invoke %d, want complex-ack invoke %d", a.Type, a.InvokeID, invoke)
	}
	return nil
}

// TestSoakSteadyState keeps one gateway busy for the budget and asserts it
// stays flat: zero unanswered requests, bounded goroutines, bounded live heap,
// and no pending requests left behind.
func TestSoakSteadyState(t *testing.T) {
	budget := testkit.SoakDuration(t)

	prop := bacnet.PropertyPresentValue
	dev := startEchoDevice(t, bacnet.ObjectID{Type: bacnet.ObjectAnalogValue, Instance: 1}, prop)
	f := startGateway(t, Config{DeviceAddr: dev.String()}, nil)
	c := newTestClient(t)
	dst := f.addr()

	// Warm up so the baseline includes the device loop and the sweeper.
	for i := 0; i < 5; i++ {
		oid := bacnet.ObjectID{Type: bacnet.ObjectAnalogValue, Instance: uint32(i)}
		if err := soakRoundTrip(c, dst, oid, prop, byte(i)); err != nil {
			t.Fatalf("warmup request %d: %v", i, err)
		}
	}

	runtime.GC()
	baseGoroutines := runtime.NumGoroutine()
	var baseHeap runtime.MemStats
	runtime.ReadMemStats(&baseHeap)

	var (
		ok, failed, maxGoroutines int
		worst                     time.Duration
		lastErr                   error
		sent                      int
	)
	sampleEvery := budget / 20
	if sampleEvery < time.Second {
		sampleEvery = time.Second
	}
	nextSample := time.Now().Add(sampleEvery)

	deadline := time.Now().Add(budget)
	for time.Now().Before(deadline) {
		// Vary the object instance so each request hashes differently: after
		// the one-octet invoke-ID space wraps, the same ID must be forwarded
		// as a new exchange, not answered from the completed-response cache.
		oid := bacnet.ObjectID{Type: bacnet.ObjectAnalogValue, Instance: uint32(sent % 4096)}
		start := time.Now()
		err := soakRoundTrip(c, dst, oid, prop, byte(sent))
		sent++
		if err != nil {
			failed++
			lastErr = err
		} else {
			ok++
			if elapsed := time.Since(start); elapsed > worst {
				worst = elapsed
			}
		}
		if time.Now().After(nextSample) {
			if g := runtime.NumGoroutine(); g > maxGoroutines {
				maxGoroutines = g
			}
			nextSample = time.Now().Add(sampleEvery)
		}
		time.Sleep(soakPollInterval)
	}

	if failed != 0 {
		t.Fatalf("%d of %d requests were unanswered over %s (last error: %v)", failed, ok+failed, budget, lastErr)
	}
	if maxGoroutines > baseGoroutines+8 {
		t.Fatalf("goroutines grew %d -> %d during the soak", baseGoroutines, maxGoroutines)
	}
	if pending := testutil.ToFloat64(f.metrics.Pending); pending != 0 {
		t.Fatalf("pending gauge = %v after the soak, want 0: state was left behind", pending)
	}

	runtime.GC()
	var endHeap runtime.MemStats
	runtime.ReadMemStats(&endHeap)
	if grew := int64(endHeap.HeapAlloc) - int64(baseHeap.HeapAlloc); grew > 24<<20 {
		t.Fatalf("live heap grew %.1fMiB over the soak (%.1fMiB -> %.1fMiB): something retains per-request state",
			float64(grew)/(1<<20), float64(baseHeap.HeapAlloc)/(1<<20), float64(endHeap.HeapAlloc)/(1<<20))
	}

	t.Logf("soak: %s, %d requests, worst round trip %s, goroutines %d (baseline %d, peak %d), live heap %.1fMiB -> %.1fMiB",
		budget, ok, worst.Round(time.Millisecond), runtime.NumGoroutine(), baseGoroutines, maxGoroutines,
		float64(baseHeap.HeapAlloc)/(1<<20), float64(endHeap.HeapAlloc)/(1<<20))
}

// TestSoakMultiDeviceSteadyState is the co-hosting variant: two independent
// listener↔device pairs in one process, each under continuous load. It
// asserts the same flatness as the single-device soak, plus that neither
// device's pending table is left behind.
func TestSoakMultiDeviceSteadyState(t *testing.T) {
	budget := testkit.SoakDuration(t)

	prop := bacnet.PropertyPresentValue
	oid := bacnet.ObjectID{Type: bacnet.ObjectAnalogValue, Instance: 1}
	devA := startEchoDevice(t, oid, prop)
	devB := startEchoDevice(t, oid, prop)
	fA := startGateway(t, Config{DeviceAddr: devA.String()}, nil)
	fB := startGateway(t, Config{DeviceAddr: devB.String()}, nil)
	cA := newTestClient(t)
	cB := newTestClient(t)
	dstA, dstB := fA.addr(), fB.addr()

	// Warm up so the baseline includes both device loops and both sweepers.
	for i := 0; i < 5; i++ {
		if err := soakRoundTrip(cA, dstA, oid, prop, byte(i)); err != nil {
			t.Fatalf("warmup a: %v", err)
		}
		if err := soakRoundTrip(cB, dstB, oid, prop, byte(i)); err != nil {
			t.Fatalf("warmup b: %v", err)
		}
	}

	runtime.GC()
	baseGoroutines := runtime.NumGoroutine()
	var baseHeap runtime.MemStats
	runtime.ReadMemStats(&baseHeap)

	var (
		ok, failed, maxGoroutines int
		worst                     time.Duration
		lastErr                   error
	)
	sampleEvery := budget / 20
	if sampleEvery < time.Second {
		sampleEvery = time.Second
	}
	nextSample := time.Now().Add(sampleEvery)
	deadline := time.Now().Add(budget)

	for time.Now().Before(deadline) {
		start := time.Now()
		errA := soakRoundTrip(cA, dstA, oid, prop, byte(ok))
		errB := soakRoundTrip(cB, dstB, oid, prop, byte(ok))
		if errA != nil || errB != nil {
			failed++
			if errA != nil {
				lastErr = errA
			} else {
				lastErr = errB
			}
		} else {
			ok++
			if elapsed := time.Since(start); elapsed > worst {
				worst = elapsed
			}
		}
		if time.Now().After(nextSample) {
			if g := runtime.NumGoroutine(); g > maxGoroutines {
				maxGoroutines = g
			}
			nextSample = time.Now().Add(sampleEvery)
		}
		time.Sleep(soakPollInterval)
	}

	if failed != 0 {
		t.Fatalf("%d of %d rounds were unanswered over %s (last error: %v)", failed, ok+failed, budget, lastErr)
	}
	if maxGoroutines > baseGoroutines+8 {
		t.Fatalf("goroutines grew %d -> %d during the soak", baseGoroutines, maxGoroutines)
	}
	for name, f := range map[string]*fixture{"a": fA, "b": fB} {
		if pending := testutil.ToFloat64(f.metrics.Pending); pending != 0 {
			t.Fatalf("device %s pending gauge = %v after the soak, want 0: state was left behind", name, pending)
		}
	}

	runtime.GC()
	var endHeap runtime.MemStats
	runtime.ReadMemStats(&endHeap)
	if grew := int64(endHeap.HeapAlloc) - int64(baseHeap.HeapAlloc); grew > 24<<20 {
		t.Fatalf("live heap grew %.1fMiB over the soak (%.1fMiB -> %.1fMiB): something retains per-request state",
			float64(grew)/(1<<20), float64(baseHeap.HeapAlloc)/(1<<20), float64(endHeap.HeapAlloc)/(1<<20))
	}

	t.Logf("multi-device soak: %s, %d rounds, worst round trip %s, goroutines %d (baseline %d, peak %d), live heap %.1fMiB -> %.1fMiB",
		budget, ok, worst.Round(time.Millisecond), runtime.NumGoroutine(), baseGoroutines, maxGoroutines,
		float64(baseHeap.HeapAlloc)/(1<<20), float64(endHeap.HeapAlloc)/(1<<20))
}

// TestSoakMultiClientSteadyState is the fan-in shape: one device and one
// gateway, several independent clients hammering it at once. It exercises the
// per-client invoke-ID space, the pending table under concurrent allocation,
// and the completed-response cache while the gateway is busy.
func TestSoakMultiClientSteadyState(t *testing.T) {
	budget := testkit.SoakDuration(t)

	prop := bacnet.PropertyPresentValue
	oid := bacnet.ObjectID{Type: bacnet.ObjectAnalogValue, Instance: 1}
	dev := startEchoDevice(t, oid, prop)
	f := startGateway(t, Config{DeviceAddr: dev.String()}, nil)
	dst := f.addr()

	const clients = 8
	cs := make([]*testClient, clients)
	for i := range cs {
		cs[i] = newTestClient(t)
		// Warm up so the baseline includes every client's socket and the
		// gateway's per-client state.
		for j := 0; j < 3; j++ {
			if err := soakRoundTrip(cs[i], dst, oid, prop, byte(j)); err != nil {
				t.Fatalf("warmup client %d: %v", i, err)
			}
		}
	}

	var (
		ok, failed atomic.Int64
		errMu      sync.Mutex
		lastErr    error
	)
	deadline := time.Now().Add(budget)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i, c := range cs {
		i, c := i, c
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			sent := 0
			for time.Now().Before(deadline) {
				// Vary the instance so the completed-response cache does not
				// answer a wrapped invoke ID from an earlier exchange.
				reqOID := bacnet.ObjectID{Type: bacnet.ObjectAnalogValue, Instance: uint32((sent + i) % 4096)}
				if err := soakRoundTrip(c, dst, reqOID, prop, byte(sent)); err != nil {
					failed.Add(1)
					errMu.Lock()
					lastErr = err
					errMu.Unlock()
				} else {
					ok.Add(1)
				}
				sent++
				time.Sleep(soakPollInterval)
			}
		}()
	}

	// The workers exist but are parked on start, so the baseline includes
	// their goroutines rather than counting them as growth.
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	runtime.GC()
	runtime.Gosched()
	time.Sleep(20 * time.Millisecond)
	baseGoroutines := runtime.NumGoroutine()
	var baseHeap runtime.MemStats
	runtime.ReadMemStats(&baseHeap)
	close(start)

	var maxGoroutines int
	sampleEvery := budget / 20
	if sampleEvery < time.Second {
		sampleEvery = time.Second
	}
	ticker := time.NewTicker(sampleEvery)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			if g := runtime.NumGoroutine(); g > maxGoroutines {
				maxGoroutines = g
			}
			goto finished
		case <-ticker.C:
			if g := runtime.NumGoroutine(); g > maxGoroutines {
				maxGoroutines = g
			}
		}
	}

finished:
	if n := failed.Load(); n != 0 {
		errMu.Lock()
		last := lastErr
		errMu.Unlock()
		t.Fatalf("%d of %d requests were unanswered over %s (last error: %v)", n, ok.Load()+n, budget, last)
	}
	if maxGoroutines > baseGoroutines+8 {
		t.Fatalf("goroutines grew %d -> %d during the soak", baseGoroutines, maxGoroutines)
	}
	if pending := testutil.ToFloat64(f.metrics.Pending); pending != 0 {
		t.Fatalf("pending gauge = %v after the soak, want 0: state was left behind", pending)
	}

	runtime.GC()
	var endHeap runtime.MemStats
	runtime.ReadMemStats(&endHeap)
	if grew := int64(endHeap.HeapAlloc) - int64(baseHeap.HeapAlloc); grew > 24<<20 {
		t.Fatalf("live heap grew %.1fMiB over the soak (%.1fMiB -> %.1fMiB): something retains per-request state",
			float64(grew)/(1<<20), float64(baseHeap.HeapAlloc)/(1<<20), float64(endHeap.HeapAlloc)/(1<<20))
	}

	t.Logf("multi-client soak: %s, %d clients, %d requests, goroutines %d (baseline %d, peak %d), live heap %.1fMiB -> %.1fMiB",
		budget, clients, ok.Load(), runtime.NumGoroutine(), baseGoroutines, maxGoroutines,
		float64(baseHeap.HeapAlloc)/(1<<20), float64(endHeap.HeapAlloc)/(1<<20))
}
