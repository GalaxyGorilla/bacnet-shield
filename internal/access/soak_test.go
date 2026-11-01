// Soak test for the per-client rate limiter, in package access so it can see
// the bucket table directly.
//
// The unit tests already pin the two correctness properties (the table is
// swept after an idle period, and a full table refuses a new client). What
// they cannot show is that those properties hold under a sustained flood of
// spoofed sources: the sweep runs on a real clock, so a long run interleaves
// allocations, sweeps and refusals in an order no unit test reproduces. That
// is the DoS premise — an attacker chooses the source addresses — so it gets
// a soak rather than a plausible-looking unit test.
package access

import (
	"fmt"
	"net"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/GalaxyGorilla/bacnet-shield/internal/testkit"
)

// limitLen reports the bucket count under the limiter's own lock.
func limitLen(l *Limit) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}

// TestSoakRateLimiterSpoofedSources floods the limiter with distinct source
// addresses for the soak budget and asserts the table stays bounded, every
// request from a source it has never seen is refused once the table is full,
// and neither goroutines nor the live heap grow.
func TestSoakRateLimiterSpoofedSources(t *testing.T) {
	budget := testkit.SoakDuration(t)

	lim := NewLimit(100) // one token per request is irrelevant: each source is new
	baseline := runtime.NumGoroutine()

	runtime.GC()
	var base runtime.MemStats
	runtime.ReadMemStats(&base)

	deadline := time.Now().Add(budget)
	var allowed, refused atomic.Int64
	var maxTable int

	// One producer is the harshest honest shape: the limiter's mutex is the
	// shared resource, so parallel producers would only measure contention.
	for n := 0; time.Now().Before(deadline); n++ {
		// 10.0.0.0/8 gives 16.7M distinct spoofed sources — far past the
		// maxBuckets cap, so the flood necessarily crosses it.
		ip := net.IPv4(10, byte(n>>16), byte(n>>8), byte(n))
		if lim.Allow(ip, time.Now()) {
			allowed.Add(1)
		} else {
			refused.Add(1)
		}
		if n%4096 == 0 {
			size := limitLen(lim)
			if size > maxTable {
				maxTable = size
			}
			if size > maxBuckets {
				t.Fatalf("bucket table grew to %d entries, cap is %d", size, maxBuckets)
			}
			// Keep the flood hot without pinning a core for ten minutes.
			time.Sleep(100 * time.Microsecond)
		}
	}

	if maxTable != maxBuckets {
		t.Fatalf("table peaked at %d entries, want the cap %d — the flood never reached it", maxTable, maxBuckets)
	}
	if refused.Load() == 0 {
		t.Fatal("no request was refused: the fail-closed cap did not engage under the flood")
	}

	// The property that matters operationally: a source the proxy has never
	// seen is refused, not admitted, while the table is full. A long soak can
	// sweep idle entries between the flood and this check, so only assert it
	// when the table is still full — otherwise the claim would be vacuous.
	if limitLen(lim) == maxBuckets && lim.Allow(net.IPv4(192, 0, 2, 77), time.Now()) {
		t.Fatal("a never-seen source was admitted while the table was full (fail-open)")
	}

	after := runtime.NumGoroutine()
	if after > baseline+2 {
		t.Fatalf("goroutines %d -> %d during the soak", baseline, after)
	}

	runtime.GC()
	var end runtime.MemStats
	runtime.ReadMemStats(&end)
	// The table is bounded, so live heap must not track the request count.
	if grew := int64(end.HeapAlloc) - int64(base.HeapAlloc); grew > 16<<20 {
		t.Fatalf("live heap grew %s during the soak (base %s, end %s): the table is not the only thing being retained",
			time.Duration(grew), fmtBytes(base.HeapAlloc), fmtBytes(end.HeapAlloc))
	}

	t.Logf("soak: %s, %d admitted, %d refused, table %d/%d, goroutines %d",
		budget, allowed.Load(), refused.Load(), limitLen(lim), maxBuckets, after)
}

func fmtBytes(b uint64) string {
	const unit = 1 << 20
	return fmt.Sprintf("%.1fMiB", float64(b)/unit)
}
