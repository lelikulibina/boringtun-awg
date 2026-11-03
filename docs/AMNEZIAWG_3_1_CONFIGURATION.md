# Настройка AmneziaWG 3.1 в BoringTun

> **Статус:** экспериментальная реализация в PR [#8](https://github.com/lelikulibina/boringtun-awg/pull/8). Это не заявление о полной совместимости с AmneziaWG 3.1: до неё ещё нужны дифференциальные тесты с официальным `amneziawg-go`, двусторонний handshake и матрица WireGuard/AWG 2.x/AWG 3.1.

## Совместимость и безопасные значения

Все новые параметры выключены или имеют WireGuard-совместимые значения по умолчанию. Если AWG-параметры не заданы, обычный WireGuard-путь сохраняется. Параметры, влияющие на wire format, должны быть согласованы на обеих сторонах туннеля.

| UAPI-параметр | Формат | Значение по умолчанию / смысл |
|---|---|---|
| `disable_cookies` | `true` / `false` | `false`. При `true` MAC1 по-прежнему проверяется, но under-load MAC2/cookie challenge обходится. Входящие Cookie Reply продолжают приниматься. |
| `header_protection_key` | 64 hex-символа (32 байта) | Нулевой ключ выключает защиту. Один и тот же ключ и S-настройки нужны на обоих концах. |
| `content_padding_addition` | `uint16`: `N` или `MIN-MAX` | Inclusive диапазон нулевого дополнения transport plaintext перед AEAD. `0`/не задано — выключено. |
| `random_trailers` | `true` / `false` | `false`. Случайный внешний trailer для handshake/cookie и нулевое дополнение transport внутри AEAD. |
| `rekey_after_time` | секунды, `uint16`: `N` или `MIN-MAX` | `120` секунд, если не задано. |
| `rekey_timeout` | секунды, `uint16`: `N` или `MIN-MAX` | `5` секунд, если не задано. |
| `reject_after_time` | секунды, `uint16`: `N` или `MIN-MAX` | `180` секунд, если не задано. |
| `keepalive_timeout` | секунды, `uint16`: `N` или `MIN-MAX` | `10` секунд, если не задано. |
| `max_handshake_attempts` | `N` или `MIN-MAX` | `18`, если не задано. |

Диапазоны включают обе границы. Обратный диапазон отклоняется. Частичный UAPI `set=1` объединяется с текущей конфигурацией и не должен сбрасывать неуказанные AWG-поля.

Существующие `Jc/Jmin/Jmax`, `S1-S4`, `H1-H4` и `I1-I5` сохраняются. Формат имитационных пакетов и DNS/SIP/STUN/QUIC imitation не заменяется новыми параметрами.

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

Скрипт требует Linux, root, `iproute2`, `ping`, Python-пакет `cryptography`, BoringTun с feature `device` и официальный бинарник `amneziawg-go` из модуля `/v3`; CI собирает эталон из upstream commit `b5928efb6ca19f0153958460c3d141f04abc5c2e`, чтобы результаты матрицы были воспроизводимыми. Каждый профиль запускается в двух ролях: BoringTun-сервер ↔ amneziawg-go-клиент и amneziawg-go-сервер ↔ BoringTun-клиент. Для каждого прогона создаются отдельные сетевые namespace с уникальными именами; хостовые маршруты и интерфейсы не перенастраиваются. Успех означает не только принятие UAPI-конфигурации, но и handshake с последующим двусторонним ICMP-трафиком.

Матрица отдельно проверяет 1 MiB двусторонней передачи для vanilla WireGuard, AWG 2.0, AWG 3.0 и AWG 3.1. Профиль AWG 3.0 включает HeaderProtectionKey, ContentPaddingAddition и диапазоны таймеров; AWG 3.1 добавляет RandomTrailers и DisableCookies поверх профиля 3.0. CPS I1–I5 проверяются отдельными сценариями, поскольку цепочки сигнатур не являются заменой транспортных расширений AWG 3.0. В CI run [41496077388](https://github.com/lelikulibina/boringtun-awg/actions/runs/41496077388) матрица завершилась успешно на кодовом HEAD `e11c15e3340b5e73305207f95e7d727d40f7877c`: все 8 профилей прошли в обеих ролях (16/16), включая vanilla WireGuard и AWG 2.x. Для каждого профиля подтверждены UAPI-настройка, handshake и двусторонний ICMP-трафик. Это не заменяет отдельные тесты под искусственной under-load нагрузкой для DisableCookies и длительный differential-тест rekey/retry/expiry.

## Что ещё не подтверждено

1. Differential wire-vector tests с официальным Go peer для Header Protection, RandomTrailers, cookie replies и H1-H4.
2. Реальный двусторонний handshake BoringTun ↔ amneziawg-go с HP и RandomTrailers.
3. Регрессии vanilla WireGuard и AWG 2.x, а также комбинации всех новых параметров.
4. Полная проверка жизненного цикла таймеров и количества handshake retries против upstream.

Пока эти проверки не завершены, не следует маркировать эту ветку как полностью совместимую с AmneziaWG 3.1.
