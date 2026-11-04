# Настройка AmneziaWG 3.1 в BoringTun

Этот документ — практическая памятка по AWG 3.1 в BoringTun: UAPI, безопасные значения и ограничения реализации. Полная история версий, семантика каждого параметра, межверсионная совместимость, upstream edge cases и ссылки на исходники вынесены в [AMNEZIAWG_PROTOCOL_COMPATIBILITY.md](AMNEZIAWG_PROTOCOL_COMPATIBILITY.md).

## Область действия UAPI

В daemon UAPI AWG-настройки являются interface-wide: один профиль S/H, J, CPS, HP, CPA, RT, DisableCookies и timer ranges применяется ко всем peer интерфейса. В библиотечном API отдельный `Tunn` может иметь собственный профиль. `persistent_keepalive_interval` задаётся отдельно для каждого peer.

## 1. Совместимость

У AWG нет отдельного version negotiation. Версия в конфигурации не согласуется по сети; обе стороны должны заранее иметь совместимые настройки.

**Должны совпадать на обеих сторонах:**

- `S1-S4` — точные длины префиксов для Init, Response, Cookie Reply и Transport.
- `H1-H4` — одинаковые непересекающиеся диапазоны message type tags.
- `HeaderProtectionKey` — один и тот же 32-байтовый ключ, если Header Protection включён.
- `RandomTrailers` — обе стороны должны разрешать variable-length handshake/cookie envelopes, если отправитель добавляет trailers.

**Не требуют зеркального значения:**

- `Jc/Jmin/Jmax` и `I1-I5` — параметры исходящих pre-handshake datagrams.
- `ContentPaddingAddition` и таймеры — локальная политика отправителя/peer.
- `DisableCookies` — локальная under-load политика принимающей стороны.

Профиль AWG 3.1 с выключенными `RandomTrailers` и `DisableCookies`, без Header Protection и с одинаковыми S/H может сохранять совместимость с более ранними поколениями при условии, что старый config parser принимает остальные ключи.

## 2. UAPI-параметры AWG 3.1

| Параметр | Формат | Default / смысл |
|---|---|---|
| `header_protection_key` | 64 hex-символа (32 байта) | Нулевой ключ отключает HP. Один ключ на обоих концах. При HP все S1-S4 должны быть ≥12 байт. |
| `content_padding_addition` | `N` или `MIN-MAX`, uint32 | Включительный диапазон нулевого padding внутри transport plaintext до AEAD. `0-0` выключает. |
| `random_trailers` | boolean | `false`. Внешний случайный trailer для handshake/cookie; нулевой padding внутри transport AEAD. |
| `disable_cookies` | boolean | `false`. Пропускает under-load MAC2/cookie gate, но MAC1 остаётся обязательным. Входящие Cookie Reply продолжают приниматься. |
| `rekey_after_time` | секунды, uint32 range | 120 с по умолчанию. |
| `rekey_timeout` | секунды, uint32 range | 5 с по умолчанию. |
| `reject_after_time` | секунды, uint32 range | 180 с по умолчанию. |
| `keepalive_timeout` | секунды, uint32 range | 10 с по умолчанию. |
| `max_handshake_attempts` | uint32 range | 18 по умолчанию; бюджет выбирается на handshake cycle. |
| `persistent_keepalive_interval` | per-peer, секунды, uint32 range | `0-0` выключает; интервал выбирается заново после authenticated traversal. |

Таймерные диапазоны включают обе границы. `0-0` означает «не задано, использовать WireGuard default», а не нулевую длительность. Диапазон `0-1` — уже заданная конфигурация, которая может выбрать 0. Подробные формулы таймеров см. в основном исследовании.

## 3. S/H и пределы пакетов

| Поле | Тип сообщения | Базовый размер |
|---|---|---:|
| `S1` | Handshake Initiation | 148 байт |
| `S2` | Handshake Response | 92 байта |
| `S3` | Cookie Reply | 64 байта |
| `S4` | Transport Data | 32 байта overhead + payload |

S — фиксированная длина префикса перед WG-сообщением. UAPI upstream хранит S как uint16, но BoringTun также проверяет, что базовая UDP payload-датаграмма помещается в 65 507 байт.

H1-H4 — включительные диапазоны 32-битных little-endian message type tags. Диапазоны не должны пересекаться. Стандартные значения 1, 2, 3, 4 соответствуют обычным WireGuard type tags.

### RandomTrailers и одинаковые S

BoringTun требует `S1=S2=S3=S4`, когда `random_trailers=true`. Upstream принимает разные значения, но его first-match classifier может ошибочно принять transport packet за handshake при проверке разных offsets; это описано в [upstream issue #186](https://github.com/amnezia-vpn/amneziawg-go/issues/186). Равные S вместе с непересекающимися H устраняют неоднозначность.

При включённом Header Protection каждый S-префикс должен быть не короче 12 байт: первые 12 байт — nonce ChaCha20. Эти байты должны быть случайными. Поэтому BoringTun не использует protocol-shaped S-prefix при включённом HP, даже если включена локальная имитация протокола.

## 4. J-пакеты и CPS

- `Jc=0` выключает junk train.
- При `Jc>0` BoringTun ограничивает количество 128 пакетами, `Jmax` — 1280 байтами. Это safety cap, а не гарантия отсутствия фрагментации на маршрутах с MTU ниже 1280.
- В upstream фактическая формула размера — `Jmin + fastrandn(Jmax-Jmin)`, то есть Jmax не включается.
- BoringTun отвергает `Jmin>Jmax` и некорректные значения до отправки. При `Jc>0` и `Jmin=Jmax=0` используются безопасные defaults 50…1000.
- `I1-I5` задают CPS-пакеты. Поддерживаются upstream-теги `b`, `t`, `r`, `rc`, `rd`, `d`, `ds`, `dz`. Отрицательные длины отклоняются; итоговая датаграмма ограничена UDP payload limit.

Upstream issue [#189](https://github.com/amnezia-vpn/amneziawg-go/issues/189) документирует опасные конфигурации `Jmin>Jmax` и отрицательные CPS tag lengths, способные привести к panic/OOM в upstream. BoringTun проверяет эти случаи при конфигурации.

## 5. Padding и UDP window

- `ContentPaddingAddition` добавляет нули к внутреннему IP-пакету до AEAD; приёмник удаляет их по IPv4/IPv6 length field.
- `RandomTrailers` добавляет внешний trailer к Init/Response/Cookie Reply и нули внутрь transport AEAD.
- Для transport CPA имеет приоритет над RT, если диапазон CPA задан. Для handshake/cookie RT работает независимо.
- Пустой handshake-confirmation keepalive также проходит transport padding path.
- UDP window — high-water mark базовых исходящих transport datagrams до добавления padding/trailer. BoringTun обновляет его по исходящим пакетам, как upstream; входящий padded datagram не должен обучать локальное окно.

CPA не ограничивает внешние handshake/cookie trailers — см. [upstream issue #185](https://github.com/amnezia-vpn/amneziawg-go/issues/185).

## 6. DisableCookies: безопасность

`disable_cookies=true` не просто запрещает отправку Cookie Reply. Параметр пропускает under-load gate, включая MAC2 challenge и связанный handshake rate limiting; MAC1 всё ещё проверяется. Входящие Cookie Reply продолжают приниматься. Это снижает DoS-защиту от потока handshake-пакетов и требует осознанного применения на публичном endpoint.

BoringTun следует исправленному upstream поведению из `v3.1.20260828`. В `v3.1.20260812` under-load gate ещё вызывался независимо от DisableCookies.

## 7. BoringTun-only настройки

`Jd` (задержка между junk-пакетами), `Ip/Id/Ib` (локальная имитация протокола/domain/browser), responder-mode/suppress-pre-handshake и protocol probe replies — локальные расширения BoringTun, а не параметры version negotiation AWG. Их нельзя считать обязательными для совместимости с официальным AmneziaWG.

## Известное отличие от upstream: обычный 16-byte padding

Когда CPA не задан и RandomTrailers выключен, upstream дополняет transport plaintext до кратного 16 байтам размера с ограничением по TUN MTU. Текущий BoringTun `Session::format_packet_data` это padding намеренно не добавляет; standalone `Tunn` также не хранит MTU. Wire compatibility сохраняется, но размеры обычных transport-пакетов отличаются от upstream. Для полного parity нужен отдельный MTU plumbing в `Tunn` и fallback `calculatePaddingSize`; это отличие подробно описано в основном исследовании.

## 8. Проверка

Любое изменение framing должно проверяться в обеих ролях: BoringTun server ↔ amneziawg-go client и amneziawg-go server ↔ BoringTun client. Для RandomTrailers нужны равные S на обеих сторонах; для HP — общий ключ и S≥12. Quick interop матрица в PR #13 включает vanilla WG, AWG 2.x baseline, accelerated rekey, packet-loss recovery, combined AWG 3.1 и CPS I1-I5. Полная матрица запускается отдельно через workflow_dispatch.

Полное исследование параметров, версий, лимитов и известных upstream defects: [AMNEZIAWG_PROTOCOL_COMPATIBILITY.md](AMNEZIAWG_PROTOCOL_COMPATIBILITY.md).
