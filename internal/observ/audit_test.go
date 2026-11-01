package observ

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestAuditWriterEmitsJSONLines(t *testing.T) {
	var buf bytes.Buffer
	a := NewAuditWriter(&buf, nil)
	a.Record(AuditEvent{Event: "write_denied", Leg: "ip", Client: "10.0.0.5:1",
		Service: "write-property", Targets: []string{"analog-value,5:present-value"}, Reason: "read_only"})
	a.Record(AuditEvent{Event: "acl_denied", Leg: "sc", Client: "sc:02:00:00:00:00:0a"})
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("audit lines = %d, want 2: %q", len(lines), buf.String())
	}
	var ev AuditEvent
	if err := json.Unmarshal([]byte(lines[0]), &ev); err != nil {
		t.Fatal(err)
	}
	if ev.Event != "write_denied" || ev.Leg != "ip" || ev.Reason != "read_only" {
		t.Fatalf("event = %+v", ev)
	}
	if ev.Time == "" {
		t.Fatal("time was not stamped by the writer")
	}
	if len(ev.Targets) != 1 || ev.Targets[0] != "analog-value,5:present-value" {
		t.Fatalf("targets = %v", ev.Targets)
	}
	// An unset field must be omitted, not serialized as an empty value, so the
	// schema stays honest about what a record actually contains.
	if strings.Contains(lines[1], "targets") || strings.Contains(lines[1], "reason") {
		t.Fatalf("empty fields serialized: %s", lines[1])
	}
}

func TestNilAuditIsNoop(t *testing.T) {
	var a *Audit
	a.Record(AuditEvent{Event: "x"}) // must not panic
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
}

// TestAuditDropsWhenFull is the bounded-memory property: when the writer cannot
// keep up, records are dropped and counted rather than blocking the caller.
func TestAuditDropsWhenFull(t *testing.T) {
	counter := prometheus.NewCounter(prometheus.CounterOpts{Name: "test_audit_dropped", Help: "x"})
	bw := &blockWriter{release: make(chan struct{})}
	a := NewAuditWriter(bw, counter)

	// The writer goroutine blocks on the first record; fill the queue and push
	// several more so the overflow must drop.
	for i := 0; i < auditQueue+8; i++ {
		a.Record(AuditEvent{Event: "e"})
	}
	if got := testutil.ToFloat64(counter); got < 1 {
		t.Fatalf("dropped = %v, want >= 1", got)
	}
	close(bw.release)
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
}

type blockWriter struct{ release chan struct{} }

func (b *blockWriter) Write(p []byte) (int, error) {
	<-b.release
	return len(p), nil
}

// TestAuditFileRotation pins the bound: the file never grows past the cap, and
// one backup is kept.
func TestAuditFileRotation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	rf, err := openRotatingFile(path, 100)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 200; i++ {
		if _, err := rf.Write([]byte("0123456789\n")); err != nil {
			t.Fatal(err)
		}
	}
	if err := rf.Close(); err != nil {
		t.Fatal(err)
	}

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() > 100 {
		t.Fatalf("current file %d bytes exceeds the 100-byte cap", fi.Size())
	}
	if _, err := os.Stat(path + ".1"); err != nil {
		t.Fatalf("no backup kept: %v", err)
	}
}
