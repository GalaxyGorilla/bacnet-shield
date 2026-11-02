package proxy

import (
	"context"
	"sync"
)

// Runner owns every gateway in a single process (the multi-device co-hosting
// shape) and serves them together. Each Gateway already binds its own front-leg
// and device sockets in New, so a bind failure is a construction error, not a
// goroutine that dies quietly: by the time a Runner exists, every listener is
// bound and every device leg is open. The Runner is purely a lifecycle
// wrapper — it never routes one device's traffic to another.
type Runner struct {
	gws []*Gateway
}

// NewRunner wraps already-built gateways. The caller builds them in config
// order so a bind conflict fails startup before anything serves.
func NewRunner(gws []*Gateway) *Runner { return &Runner{gws: gws} }

// Gateways returns the running gateways in config order. The command uses it
// to apply a SIGHUP policy swap per device.
func (r *Runner) Gateways() []*Gateway { return r.gws }

// Serve runs every gateway until ctx is cancelled, then returns. Each
// gateway's Serve closes its own sockets on cancellation, so a multi-device
// process shuts down every leg, not just the first.
func (r *Runner) Serve(ctx context.Context) error {
	var wg sync.WaitGroup
	for _, g := range r.gws {
		g := g
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = g.Serve(ctx)
		}()
	}
	<-ctx.Done()
	wg.Wait()
	return nil
}
