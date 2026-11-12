FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends iproute2 nftables procps \
    && rm -rf /var/lib/apt/lists/*

COPY target/debug/vpn-relay /usr/local/bin/vpn-relay
COPY scripts/vpn-relay-podman-container-test.sh /usr/local/bin/vpn-relay-podman-container-test

ENTRYPOINT ["/usr/bin/bash", "/usr/local/bin/vpn-relay-podman-container-test"]
