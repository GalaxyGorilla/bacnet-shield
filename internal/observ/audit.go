package observ

import (
	"encoding/json"
	"io"
	"os"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// AuditEvent is one security-relevant decision, recorded as a single JSON
// object. The field names are a stable contract: an operator's SIEM or log
// pipeline may rely on them, so a record is added to, never silently renamed.
//
// Time is filled in by the writer, not the caller, so every record carries the
// instant it was flushed rather than the instant the datagram was parsed.
type AuditEvent struct {
	Time    string   `json:"time"`
	Event   string   `json:"event"`
	Device  string   `json:"device"`
	Leg     string   `json:"leg"`
	Client  string   `json:"client"`
	Service string   `json:"service,omitempty"`
	Targets []string `json:"targets,omitempty"`
	Reason  string   `json:"reason,omitempty"`
}

// auditQueue is the depth of the in-memory audit stream. It bounds the memory
// the audit can use; a burst larger than this drops records (and counts them)
// rather than blocking the data plane. A few hundred bytes per record means
// the whole queue is on the order of a few hundred kilobytes.
const auditQueue = 1024

// Audit is a bounded, non-blocking audit stream: a datagram handler enqueues a
// record and returns, and a single goroutine writes it. A full queue drops the
// record instead of blocking the handler, which matters because an on-list
// client can generate denials as fast as it can send and must not be able to
// stall the data plane or fill the disk through the log path.
//
// A nil *Audit records nothing, so call sites can record unconditionally.
type Audit struct {
	ch      chan AuditEvent
	closer  io.Closer
	dropped prometheus.Counter

	mu     sync.RWMutex
	closed bool
	once   sync.Once
	wg     sync.WaitGroup
}

// NewAuditWriter streams records to w. It is used for tests and for a lab
// where the operator forwards stdout; the appliance path is NewAuditFile.
func NewAuditWriter(w io.Writer, dropped prometheus.Counter) *Audit {
	a := &Audit{ch: make(chan AuditEvent, auditQueue), dropped: dropped}
	a.wg.Add(1)
	go a.run(w)
	return a
}

// NewAuditFile opens an append-only audit file. When maxBytes is positive the
// file is rotated at that size, keeping exactly one backup ("<path>.1"), so
// the disk use is bounded at roughly twice maxBytes with no external logrotate.
// The file is created 0600: an audit trail names who wrote what.
func NewAuditFile(path string, maxBytes int64, dropped prometheus.Counter) (*Audit, error) {
	rf, err := openRotatingFile(path, maxBytes)
	if err != nil {
		return nil, err
	}
	a := NewAuditWriter(rf, dropped)
	a.closer = rf
	return a, nil
}

// Record enqueues one event. It never blocks: a full queue drops the event and
// counts it. Safe to call on a nil *Audit.
func (a *Audit) Record(ev AuditEvent) {
	if a == nil {
		return
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.closed {
		return
	}
	select {
	case a.ch <- ev:
	default:
		if a.dropped != nil {
			a.dropped.Inc()
		}
	}
}

// Close stops the writer after draining queued records and closes the file.
// It is idempotent and safe to call on a nil *Audit.
func (a *Audit) Close() error {
	if a == nil {
		return nil
	}
	a.once.Do(func() {
		a.mu.Lock()
		a.closed = true
		close(a.ch)
		a.mu.Unlock()
		a.wg.Wait()
	})
	if a.closer != nil {
		return a.closer.Close()
	}
	return nil
}

// run drains the stream and writes one JSON object per line.
func (a *Audit) run(w io.Writer) {
	defer a.wg.Done()
	enc := json.NewEncoder(w)
	for ev := range a.ch {
		ev.Time = time.Now().UTC().Format(time.RFC3339Nano)
		_ = enc.Encode(ev)
	}
}

// rotatingFile is an append-only writer that rotates once at a size cap. The
// rotation keeps a single backup, so the on-disk footprint is bounded at about
// twice maxBytes without an external log-rotation agent. A write larger than
// maxBytes is still written whole (a record is never split), which is why the
// cap is a rotation trigger, not a hard ceiling.
type rotatingFile struct {
	mu   sync.Mutex
	path string
	max  int64
	f    *os.File
	size int64
}

func openRotatingFile(path string, max int64) (*rotatingFile, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return &rotatingFile{path: path, max: max, f: f, size: fi.Size()}, nil
}

func (r *rotatingFile) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.max > 0 && r.size > 0 && r.size+int64(len(p)) > r.max {
		if err := r.rotateLocked(); err != nil {
			return 0, err
		}
	}
	n, err := r.f.Write(p)
	r.size += int64(n)
	return n, err
}

func (r *rotatingFile) rotateLocked() error {
	if err := r.f.Close(); err != nil {
		return err
	}
	// Replace the single backup. A failed rename is not fatal: the new file
	// still opens and the audit continues, only the previous backup is lost.
	_ = os.Rename(r.path, r.path+".1")
	f, err := os.OpenFile(r.path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	r.f = f
	r.size = 0
	return nil
}

func (r *rotatingFile) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.f.Close()
}
