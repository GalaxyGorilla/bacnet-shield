package scnet

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestClientTLS(t *testing.T) {
	cert, _ := genCert(t)
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.pem")
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})
	if err := os.WriteFile(caPath, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := ClientTLS(caPath, "", "")
	if err != nil {
		t.Fatalf("ClientTLS: %v", err)
	}
	if cfg.MinVersion != tls.VersionTLS13 {
		t.Fatalf("MinVersion = %x, want TLS 1.3", cfg.MinVersion)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: cfg.RootCAs, DNSName: "localhost"}); err != nil {
		t.Fatalf("configured pool does not trust the test certificate: %v", err)
	}

	// The system roots are used when no CA file is given; that is a valid
	// configuration, not an error.
	cfg, err = ClientTLS("", "", "")
	if err != nil {
		t.Fatalf("default roots: %v", err)
	}
	if cfg.RootCAs != nil || cfg.MinVersion != tls.VersionTLS13 {
		t.Fatalf("default TLS config = %+v", cfg)
	}
}

func TestClientTLSErrors(t *testing.T) {
	dir := t.TempDir()
	if _, err := ClientTLS(filepath.Join(dir, "missing.pem"), "", ""); err == nil {
		t.Fatal("missing CA file accepted")
	}
	bad := filepath.Join(dir, "bad.pem")
	if err := os.WriteFile(bad, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ClientTLS(bad, "", ""); err == nil {
		t.Fatal("CA file with no certificates accepted")
	}
	if _, err := ClientTLS("", "cert.pem", ""); err == nil {
		t.Fatal("certificate without a key accepted")
	}
	if _, err := ClientTLS("", "", "key.pem"); err == nil {
		t.Fatal("key without a certificate accepted")
	}
}
