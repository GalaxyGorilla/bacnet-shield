package scnet

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

// ClientTLS builds the TLS client configuration for a BACnet/SC node. caFile
// optionally replaces the system roots (an appliance normally trusts one hub
// CA); certFile and keyFile optionally present a client certificate. TLS 1.3
// is forced: BACnet/SC does not define an older version, and allowing one here
// would quietly downgrade the secure leg.
func ClientTLS(caFile, certFile, keyFile string) (*tls.Config, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS13}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("sc: read ca file %q: %w", caFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("sc: ca file %q contains no certificates", caFile)
		}
		cfg.RootCAs = pool
	}
	if (certFile == "") != (keyFile == "") {
		return nil, fmt.Errorf("sc: cert_file and key_file must be set together")
	}
	if certFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("sc: client certificate: %w", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}
	return cfg, nil
}
