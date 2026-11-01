# Independent BACnet/SC peer for the interop suite: bacnet-stack's hub
# (`bacschub`) plus the BSC client tools (`bacwi`, `bacrp`, ...). The proxy is
# a node of this hub, so a run against it proves the SC transport against a
# third-party implementation instead of our own in-process TLS fake.
#
# Build (cached by `make interop-sc`):
#   docker build -t bacnet-shield/sc-hub scripts/sc-hub
#
# Single stage on purpose: libwebsockets is built from source (the distro
# package lacks libuv, which the SC datalink needs), and keeping its build tree
# in the image is simpler and less fragile than replicating the exact runtime
# soname set. This is an interop tool, not a shipped artifact.
#
# The image deliberately carries the client tools too: the hub relays between
# two nodes, and a bacnet-stack client is the most independent way to drive a
# request through the proxy.
#
# Pinned: bacnet-stack 1.6.1 (a line whose sc-hub relays only: no write
# services) and libwebsockets v4.3-stable (the ref bacnet-stack's own CI uses).
FROM ubuntu:24.04

ARG BACNET_STACK_REF=bacnet-stack-1.6.1
ARG LIBWEBSOCKETS_REF=v4.3-stable

SHELL ["/bin/bash", "-c"]
RUN set -eux; \
    apt-get update; \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        build-essential ca-certificates cmake curl git \
        libconfig-dev libcap-dev libssl-dev libuv1-dev; \
    rm -rf /var/lib/apt/lists/*

# libwebsockets from source: the distro package is not built with libuv, which
# bacnet-stack's SC datalink needs.
RUN set -eux; \
    git clone --depth 1 --branch "${LIBWEBSOCKETS_REF}" \
        --recurse-submodules --shallow-submodules \
        https://github.com/warmcat/libwebsockets.git /src/libwebsockets; \
    cmake -S /src/libwebsockets -B /src/libwebsockets/build \
        -DLWS_WITH_LIBUV=ON -DLWS_WITH_MINIMAL_EXAMPLES=0 \
        -DLWS_MAX_SMP=32 -DCMAKE_POLICY_VERSION_MINIMUM=3.5 \
        -DCMAKE_BUILD_TYPE=Release; \
    cmake --build /src/libwebsockets/build -j"$(nproc)"; \
    cmake --install /src/libwebsockets/build; \
    ldconfig

# bacnet-stack: every BSC client tool plus the hub.
RUN set -eux; \
    git clone --depth 1 --branch "${BACNET_STACK_REF}" \
        https://github.com/bacnet-stack/bacnet-stack.git /src/bacnet-stack; \
    cd /src/bacnet-stack; \
    make -s BACDL=bsc -C apps all; \
    make -s sc-hub; \
    mkdir -p /opt/bacnet/bin; \
    cp -v bin/bacwi bin/bacrp bin/bacepics bin/bacschub bin/bacserv \
          bin/bacscov bin/bacwhohas /opt/bacnet/bin/ 2>/dev/null || \
        cp -v bin/bac* /opt/bacnet/bin/

# Self-signed example certificates from the same bacnet-stack tree; the
# interop script overrides them with certificates that carry a 127.0.0.1 SAN
# so the Go node's hostname verification passes.
RUN cp -r /src/bacnet-stack/bin/certs /opt/bacnet/certs

WORKDIR /opt/bacnet
ENTRYPOINT ["/opt/bacnet/bin/bacschub"]
CMD ["1", "InteropHub"]
