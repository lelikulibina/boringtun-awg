# Changelog

Изменения проекта vpn-relay.

## [0.1.0] - 2026-11-12

### Добавлено

- AWG-параметры конфигурации задаются непосредственно в `[interfaces.<имя>]`, без вложенной секции `[interfaces.<имя>.awg]`.

- Linux daemon для маршрутизации между несколькими WireGuard/AmneziaWG TUN.
- IPv4 routing rules с приоритетами, source/destination CIDR selectors и multi-uplink.
- nftables INPUT/OUTPUT/FORWARD isolation с fail-closed поведением и защитой от подмены managed-интерфейсов.
- NAT без трансляции, masquerade и статический SNAT.
- Conntrack decision tracking, policy routing и отдельные socket fwmarks для внешнего WG/AWG UDP.
- Runtime reload firewall, routing, NAT и peer configuration без перезапуска daemon.
- Peer lifecycle, AllowedIPs ownership и packet-level acceptance tests для peer removal, restoration и handoff.
- Durable forwarding journal, graceful rollback и SIGKILL recovery.
- Per-interface IPv4 forwarding через rtnetlink с ifindex identity checks.
- Rootful Podman deployment в private network namespace и соответствующий CI smoke test.

### Безопасность и ограничения

- Поддерживается только IPv4. IPv6 transport, адреса, маршруты, NAT, forwarding и sysctl не настраиваются.
- IPv6-пакеты блокируются на managed TUN через nftables.
- Каталог boringtun/ не модифицируется этим проектом.
- Требуется Linux, права root или эквивалентные CAP_NET_ADMIN, /dev/net/tun, nftables и iproute2.
- Поддержка Windows, rootless Podman и host-network deployment не заявляется.
