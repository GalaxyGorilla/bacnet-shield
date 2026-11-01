#!/bin/sh
# sc-certs.sh — generate the self-signed PKI the BACnet/SC interop needs.
#
#   sh scripts/sc-certs.sh <dir>
#
# Produces, all RSA (the widest TLS 1.3 compatibility for a C peer):
#
#   ca_cert.pem / ca_key.pem          the interop CA
#   server_cert.pem / server_key.pem  the hub's TLS certificate,
#                                     SAN 127.0.0.1 + localhost
#   client_cert.pem / client_key.pem  the proxy's (and bacnet-stack client's)
#                                     TLS certificate
#
# The example certificates shipped with bacnet-stack carry only a CN, no SAN.
# Go ignores a CN for hostname verification, so the proxy could not verify a
# hub that presented them; these certificates exist so the Go node's real
# TLS 1.3 verification is what the interop exercises.
set -eu

dir="${1:?usage: sc-certs.sh <dir>}"
mkdir -p "$dir"
cd "$dir"
OSSL="${OPENSSL:-openssl}"

umask 077

"$OSSL" genrsa -out ca_key.pem 2048 2>/dev/null
"$OSSL" req -x509 -new -key ca_key.pem -sha256 -days 3650 \
	-subj "/CN=bacnet-shield-interop-ca" -out ca_cert.pem

make_leaf() {
	# make_leaf <name> <cn> <eku>
	name="$1"
	cn="$2"
	eku="$3"
	"$OSSL" genrsa -out "${name}_key.pem" 2048 2>/dev/null
	"$OSSL" req -new -key "${name}_key.pem" -subj "/CN=${cn}" -out "${name}.csr"
	cat >"${name}.ext" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=${eku}
subjectAltName=IP:127.0.0.1,DNS:localhost
EOF
	"$OSSL" x509 -req -in "${name}.csr" -CA ca_cert.pem -CAkey ca_key.pem \
		-CAcreateserial -sha256 -days 3650 -extfile "${name}.ext" \
		-out "${name}_cert.pem"
	rm -f "${name}.csr" "${name}.ext"
}

make_leaf server 127.0.0.1 serverAuth
make_leaf client bacnet-shield-node clientAuth

rm -f ca_cert.srl
echo "certs written to $dir"
