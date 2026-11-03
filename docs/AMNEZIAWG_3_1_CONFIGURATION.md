# Настройка AmneziaWG 3.1 в BoringTun

> **Состояние на 2026-11-03:** функциональная матрица AWG 3.1 прошла **44/44 сценария** на исходном кодовом HEAD `115a6c35d59a626e4c1f0f074b652618ff2f7092`; затем в PR #8 интегрированы UAPI и AllowedIPs исправления из follow-up ветки. Финальный Linux CI после этих изменений повторно запускается. Текущие ограничения: нет полного byte-for-byte сравнения всех wire datagrams; Windows job отключён, macOS не входит в merge gate.

> **Предупреждение о безопасности:** `disable_cookies=true` — не просто запрет отправки Cookie Reply. Как и в upstream, при этом обходится весь under-load gate: MAC1 остаётся обязательным, но проверка MAC2 и handshake rate limiting не выполняются. Это снижает защиту от CPU-exhaustion/DoS при потоке handshake-пакетов. Включайте параметр только осознанно и учитывайте риск на публично доступном endpoint.

## Совместимость и безопасные значения

Все новые параметры выключены или имеют WireGuard-совместимые значения по умолчанию. Если AWG-параметры не заданы, обычный WireGuard-путь сохраняется. Параметры, влияющие на wire format, должны быть согласованы на обеих сторонах туннеля.

| UAPI-параметр | Формат | Значение по умолчанию / смысл |
|---|---|---|
| `disable_cookies` | `true` / `false` | `false`. При `true` MAC1 по-прежнему проверяется, но under-load MAC2/cookie challenge и связанный handshake rate-limit gate обходятся. Входящие Cookie Reply продолжают приниматься. |
| `header_protection_key` | 64 hex-символа (32 байта) | Нулевой ключ выключает защиту. Один и тот же ключ и S-настройки нужны на обоих концах. |
| `content_padding_addition` | `uint32`: `N` или `MIN-MAX` | Inclusive диапазон нулевого дополнения transport plaintext перед AEAD. `0`/не задано — выключено. |
| `random_trailers` | `true` / `false` | `false`. Случайный внешний trailer для handshake/cookie и нулевое дополнение transport внутри AEAD. |
| `rekey_after_time` | секунды, `uint32`: `N` или `MIN-MAX` | `120` секунд, если не задано. |
| `rekey_timeout` | секунды, `uint32`: `N` или `MIN-MAX` | `5` секунд, если не задано. |
| `reject_after_time` | секунды, `uint32`: `N` или `MIN-MAX` | `180` секунд, если не задано. |
| `keepalive_timeout` | секунды, `uint32`: `N` или `MIN-MAX` | `10` секунд, если не задано. |
| `max_handshake_attempts` | `uint32`: `N` или `MIN-MAX` | `18`, если не задано. |

Диапазоны включают обе границы. Обратный диапазон отклоняется. Частичный UAPI `set=1` объединяется с текущей конфигурацией и не должен сбрасывать неуказанные AWG-поля.

Существующие `Jc/Jmin/Jmax`, `S1-S4`, `H1-H4` и `I1-I5` сохраняются. Формат имитационных пакетов и DNS/SIP/STUN/QUIC imitation не заменяется новыми параметрами.

## UAPI: set/get и совместимость

UAPI сверяется с `device/uapi.go` закреплённой версии `amneziawg-go`.

- Диапазоны `H1-H4`, `content_padding_addition`, таймеров и `persistent_keepalive_interval` читаются как unsigned `uint32`; обе границы включены. `H1-H4` допускают явный ноль при `set=1`; пересекающиеся диапазоны отклоняются, чтобы классификация пакетов оставалась однозначной.
- Boolean-поля принимают варианты Go `strconv.ParseBool`: `1/0`, `t/f`, `T/F`, `true/false`, `True/False`, `TRUE/FALSE`.
- Ключи private/public/PSK принимаются в hex и base64; разбор разделяет строку только по первому `=`, поэтому завершающий base64 padding не теряется.
- `endpoint` принимает числовой SocketAddr и hostname с портом; hostname разрешается через системный resolver.
- `allowed_ip=PREFIX` добавляет префикс, `allowed_ip=-PREFIX` удаляет точный префикс только у текущего владельца, `replace_allowed_ips=true` удаляет все префиксы peer. Операции применяются в исходном порядке, а не группируются по типу.
- Поддерживаются `remove=true`, `update_only=true`, `replace_peers=true` и `protocol_version=1`. Неизвестные поля и некорректные значения возвращают UAPI error.
- `persistent_keepalive_interval` поддерживает `N` и inclusive `MIN-MAX`. При включении таймер ставит немедленный keepalive; после аутентифицированного traversal следующий интервал выбирается заново из диапазона.
- `get=1` возвращает `private_key` (не `own_public_key`), peer `preshared_key`, `protocol_version`, endpoint, AllowedIPs, диапазон persistent keepalive, counters и `last_handshake_time_sec/nsec` как абсолютное Unix-время. Для default H1-H4 возвращаются стандартные ненулевые message-type tags; нулевые optional fields опускаются, boolean flags сериализуются в обоих состояниях.
- `set=1` корректно завершает последнюю строку по EOF, не требует дополнительного пустого terminator для фиксации последнего peer и сохраняет base64-значения с `=` внутри. AWG-параметры валидируются как единый набор; частичный update сохраняет неуказанные параметры.
- AllowedIPs хранятся в одном авторитетном routing trie. Проверка исходного адреса peer, выдача конфигурации и удаление префикса используют один источник истины. Это устраняет рассинхронизацию старой per-peer копии и риск source spoofing после переноса префикса другому peer.

**Ограничения UAPI-паритета:** интерфейсные поля следует располагать до первого `public_key`, как это делает штатный `awg setconf`; после начала peer-секций parser ожидает только peer-поля. Создание нового peer требует уже заданного private key интерфейса. Пересекающиеся H1-H4 и неодинаковые S1-S4 при `random_trailers=true` намеренно отклоняются, хотя upstream может принять часть таких конфигураций без проверки. Для `Jc/Jmin/Jmax` дополнительно действуют безопасные лимиты размера и количества junk-пакетов.

## Header Protection

- Ключ — 32 байта, UAPI принимает 64 шестнадцатеричных символа.
- Первые 12 байт соответствующего S-prefix используются как ChaCha20 nonce.
- При включённой защите каждый из S1-S4 должен быть не меньше 12 байт.
- Для handshake и Cookie Reply шифруется всё фиксированное WG-сообщение; для transport — только 16-байтовый заголовок (type, receiver index, counter). AEAD ciphertext и tag не меняются.
- При включённом ключе неудачная расшифровка не должна приводить к plaintext fallback.

## ContentPaddingAddition и RandomTrailers

- ContentPaddingAddition добавляет нулевые байты к IP plaintext до AEAD. Получатель обрезает их по IPv4 Total Length или IPv6 Payload Length.
- RandomTrailers добавляет случайный хвост после фиксированных handshake/cookie сообщений; для transport добавляет нули внутрь AEAD plaintext.
- Длина внешнего RandomTrailers выбирается по upstream-правилу `fastrandn(udpWindow - packetSize)`: диапазон верхней границы не включает свободное место целиком (`0..available`), в отличие от inclusive ContentPaddingAddition. Дополнительно учитывается размер исходного cookie-triggering запроса.
- Для transport ContentPaddingAddition имеет приоритет над RandomTrailers; handshake/cookie trailers остаются независимыми от ContentPaddingAddition, как в upstream.
- Пустой keepalive не получает ContentPaddingAddition. При включённом RandomTrailers transport padding обрабатывается отдельно по upstream-семантике.
- Peer UDP window начинается с 500 байт, увеличивается только после аутентифицированной входящей transport-датаграммы и сбрасывается при смене endpoint. Исходящий пакет сам по себе не расширяет окно.
- Cookie Reply ограничивается размером вызвавшей его датаграммы, чтобы trailer не создавал amplification.
- При включённом RandomTrailers требуется `S1 = S2 = S3 = S4`. Это не косметическая рекомендация: разные смещения могут заставить ранний handshake-классификатор прочитать байты транспортного пакета в неправильной позиции и отбросить его до проверки AEAD. При одинаковых S все классификаторы читают одно поле типа; непересекающиеся H1-H4 устраняют такую неоднозначность.

В upstream зафиксированы edge cases:
- [Issue #185](https://github.com/amnezia-vpn/amneziawg-go/issues/185): ContentPaddingAddition имеет приоритет над RandomTrailers только для transport; handshake/cookie по-прежнему получают RandomTrailers.
- [Issue #186](https://github.com/amnezia-vpn/amneziawg-go/issues/186): при RandomTrailers разные S1-S4 могут приводить к ложной классификации и потере transport-пакетов даже при включённом Header Protection. В этой реализации неодинаковые S1-S4 отклоняются при применении; одинаковые S и непересекающиеся H1-H4 обеспечивают единое смещение классификации.

## Проверка с официальным amneziawg-go

Для воспроизводимой проверки AWG 3.1 добавлена отдельная матрица:

```bash
sudo python3 scripts/awg31-go-interop.py ./target/release/boringtun-cli ./amneziawg-go
```

Скрипт требует Linux, root, `iproute2`, `ping`, `tcpdump`, Python-пакет `cryptography`, BoringTun с feature `device` и официальный бинарник `amneziawg-go` из модуля `/v3`. CI собирает эталон из upstream commit `b5928efb6ca19f0153958460c3d141f04abc5c2e`. Каждый профиль запускается в двух ролях: BoringTun-сервер ↔ amneziawg-go-клиент и amneziawg-go-сервер ↔ BoringTun-клиент. Для каждого прогона создаются отдельные сетевые namespace с уникальными именами; хостовые маршруты и интерфейсы не перенастраиваются.

### Историческая базовая проверка (до UAPI follow-up)

На исходном кодовом HEAD `115a6c35d59a626e4c1f0f074b652618ff2f7092` завершились успешно:

- [PR Status Checks, run 41629784730](https://github.com/lelikulibina/boringtun-awg/actions/runs/41629784730): `rustfmt`, `clippy`, `check_features`, `tests`, `integration-tests`, `awg31-interoperability` и `all-systems-go` — success.
- Основной тестовый запуск: **277 passed, 0 failed, 9 ignored**; матрица `cargo hack test --each-feature` прошла.
- AWG 3.1 interoperability: **44/44 passed, 0 failed** (22 профиля × обе роли сервера). Для профилей проверяются handshake, двусторонние ICMP/UDP и нормализованный PCAP.
- Сценарий packet-loss recovery: `tc` подтвердил потерю одного совпавшего с фильтром H1 rekey datagram в каждой роли; после retransmit handshake и двусторонний UDP-трафик восстановились.
- Long peer lifecycle soak: **120/120 rekey cycles в каждой роли сервера**; после каждого цикла harness проверил UDP roundtrip.
- [Semgrep, run 41629784731](https://github.com/lelikulibina/boringtun-awg/actions/runs/41629784731) — success.
- [PCAP artifacts](https://github.com/lelikulibina/boringtun-awg/actions/runs/41629784730) сохранены в GitHub Actions.

Матрица включает vanilla WireGuard, AWG 2.0, AWG 3.0, AWG 3.1, отдельные расширения, совместный профиль, CPS I1–I5, accelerated rekey, packet-loss recovery и длительный ускоренный lifecycle soak. В AWG 3.0-профилях проверяются HeaderProtectionKey, ContentPaddingAddition и таймеры; AWG 3.1 добавляет RandomTrailers и DisableCookies.

**Граница доказательства:** текущий PCAP verifier декодирует типы сообщений и проверяет направление, framing, длины, наличие ожидаемых datagrams и порядок CPS signatures. Он не сравнивает каждый байт независимых PCAP с эталонным Go-процессом. Поэтому 44/44 — это успешные функциональные interoperability-сценарии, а не заявление о полном byte-for-byte wire equivalence.

### Дополнительная проверка UAPI follow-up

UAPI-исправления перенесены из draft PR #9 в PR #8: `private_key` вместо `own_public_key` в `get=1`, абсолютное Unix-время handshake, `protocol_version=1`, uint32 ranges, Go-compatible bool parsing, DNS endpoints, base64 keys, persistent keepalive ranges, EOF/framing, ordered AllowedIP add/remove/replace/update_only и owner-checked routing trie. На исходной follow-up ветке CI run [41670671377](https://github.com/lelikulibina/boringtun-awg/actions/runs/41670671377) прошли `check_features`, `tests`, `clippy` и AWG interoperability 44/44; rustfmt замечания устранены при переносе в PR #8.

### Финальная проверка PR #8

Итоговый HEAD `25dcf432296f8f3cc52d76c889b60e8d5087d0b9` проверен полным Linux PR CI: [run 41684331967](https://github.com/lelikulibina/boringtun-awg/actions/runs/41684331967) — success. Успешны `rustfmt`, `clippy`, `check_features`, `tests`, `integration-tests` (9/9), `awg31-interoperability` (**44/44**) и `all-systems-go`. В матрице 22 профиля проверяются в обеих ролях сервера; она включает vanilla WireGuard, AWG 2.x, AWG 3.0/3.1, одиночные и комбинированные расширения, CPS I1-I5, ускоренный rekey, восстановление после потери пакета и lifecycle soak. [Semgrep run 41684332036](https://github.com/lelikulibina/boringtun-awg/actions/runs/41684332036) также завершился успешно.

Это подтверждает функциональную совместимость на проверенных Linux-сценариях. Это не полная сертификация всех конфигураций и платформ: PCAP verifier не сравнивает каждый байт с Go, Windows job пропущен, macOS не входит в обязательный merge gate, а 120 rekey cycles не заменяют многочасовой production soak.

### Оставшиеся ограничения

1. Нет полного byte-for-byte differential corpus для всех типов пакетов, вариантов Header Protection, RandomTrailers, Cookie Reply и H1–H4. Имеются отдельные фиксированные known-answer vectors для ChaCha20, MAC1/MAC2 и XChaCha20-Poly1305 Cookie Reply, но это не заменяет полную побайтовую матрицу.
2. В текущем workflow Windows job явно отключён, а macOS job не входит в merge gate. Следовательно, текущий зелёный CI подтверждает Linux, а не все поддерживаемые платформы.
3. 120 ускоренных циклов rekey на каждую роль — это длительный автоматизированный lifecycle regression, но не многочасовой production soak под реальной нагрузкой.

До закрытия этих ограничений корректно заявлять функциональную совместимость на проверенных профилях Linux, но не полную сертифицированную совместимость со всеми вариантами AmneziaWG 3.1.
