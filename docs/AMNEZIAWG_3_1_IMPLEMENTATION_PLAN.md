# План реализации AmneziaWG 3.1 в BoringTun

Документ предназначен для сопровождения работ между сессиями и агентами. Перед продолжением необходимо сверить фактическое состояние ветки и PR: отметки ниже описывают состояние на момент последнего обновления документа.

## Цель и правила совместимости

Реализовать совместимость с AmneziaWG 3.1 поверх существующего BoringTun, не заменяя и не ломая:
- стандартный WireGuard при отключённых AWG-параметрах;
- существующую реализацию AmneziaWG 1.x/2.x (Jc/Jmin/Jmax, S1-S4, H1-H4);
- существующие протокольные имитации DNS/SIP/STUN/QUIC и текущие API.

Новые механизмы должны быть opt-in и иметь безопасные значения по умолчанию. Криптографическое ядро Noise/WireGuard не менять. Совместимость на проводе проверять против официального `amnezia-vpn/amneziawg-go`, а не только собственными тестами.

## Этапы

### Этап 0. Инвентаризация и фиксация базовой линии
- [x] Проверить структуру репозитория, default branch и существующие AWG-расширения.
- [x] Сверить ключевые требования с официальной документацией AWG 3.1.
- [x] Зафиксировать полный результат Linux CI для актуальной ветки/PR.
- [x] Составить матрицу текущей реализации и оставшихся interoperability-проверок по каждому параметру.

**Готово, когда:** есть список реализованных/отсутствующих возможностей, известны точки ingress/egress и базовые тесты.

### Этап 1. DisableCookies
- [x] Добавить `disable_cookies` в конфигурацию с default=false.
- [x] Сверить и реализовать upstream-семантику: при включённом флаге сохранять MAC1-проверку, но обходить under-load MAC2/cookie challenge целиком.
- [x] Сохранить приём входящих Cookie Reply и старый публичный API rate limiter.
- [x] Добавить UAPI set/get и unit-тесты.
- [x] Проверить under-load сценарии на уровне rate limiter: валидный MAC2 принимается, DisableCookies пропускает невалидный MAC2 как с source IP, так и без него, при этом MAC1 остаётся обязательным и счётчик нагрузки не увеличивается.
- [x] Получить полный зелёный Linux CI на PR (для базовой реализации и первой полной interop-матрицы; новые тесты ожидают отдельного CI запуска).

**Готово, когда:** обычное поведение без флага не меняется; с флагом MAC1 продолжает проверяться, но under-load MAC2/cookie challenge отключён (handshake без MAC2 допускается), как в upstream; входящие Cookie Reply продолжают обрабатываться.

### Этап 2. HeaderProtectionKey (AWG 3.0+, требуется для полного профиля 3.1)
- [x] Сверить upstream receive/send path: первые 12 байт S-prefix — nonce; ChaCha20 XOR начинается с байта 0 WG-сообщения; на приёме тип восстанавливается до выбора H-range; transport защищает только 16-байтовый заголовок, handshake/cookie — всё фиксированное сообщение.
- [ ] Подтвердить точное совпадение Rust wire bytes с upstream Go известными тест-векторами/дифференциальным тестом. Добавлен детерминированный ChaCha20 reference-vector test для handshake и transport; тест проходит Linux CI, но не является differential test с Go peer.
- [x] Добавить 32-байтовый ключ в `AmneziaConfig` и UAPI `header_protection_key` (64 hex-символа); all-zero key отключает защиту.
- [x] Валидировать требование S1-S4 >= 12 при включённой защите и отклонять некорректную конфигурацию.
- [x] Добавить ChaCha20 protection на egress/ingress: handshake/cookie защищаются целиком; transport — только type/receiver/counter (16 байт), AEAD ciphertext не меняется.
- [ ] Полностью согласовать H1-H4 detection и legacy-режим с upstream, включая все допустимые ranges.
- [x] Добавить unit round-trip и config validation coverage.
- [x] Проверить реальный двусторонний interop с amneziawg-go для HeaderProtectionKey: обе серверные роли прошли handshake и bidirectional ICMP в CI (профиль HeaderProtectionKey, 2/2).
- [ ] Добавить точные upstream Go differential vectors. Текущий Rust test проверяет фиксированный IETF ChaCha20 keystream и протокольное правило: handshake полностью, transport только первые 16 байт.
- [x] Проверить базовые vanilla WG/AWG 2.x регрессии handshake + bidirectional ICMP в CI (профили vanilla WireGuard и AWG 2.x, 4/4).
- [ ] Добавить отдельное побайтовое сравнение wire bytes при выключенной защите.

**Статус:** реализация ingress/egress и UAPI находится в PR #8. Добавлен фиксированный ChaCha20 reference-vector test (key `0x42` × 32, nonce `00..0b`) для handshake и transport; он проверяет IETF ChaCha20 keystream и wire layout, но не является differential test с официальным Go peer. В device UDP ingress запрещён plaintext fallback, если HeaderProtectionKey включён; добавлен deterministic negative test на отклонение plaintext initiation. Полный Linux CI для SHA `5248ff1c53afc4f8649d42235615a5e84097badf` прошёл: rustfmt, check_features, tests, clippy, integration-tests и all-systems-go — success; Semgrep также success. Этап не завершён: нужны upstream Go differential test, реальный двусторонний handshake и проверка vanilla WG/AWG 2.x.

**Готово, когда:** BoringTun и официальный AWG взаимно устанавливают туннель с одинаковым ключом, неверный ключ/недостаточный S-prefix корректно отклоняется, а vanilla WG и AWG 2.x не меняют поведение.

### Этап 3. ContentPaddingAddition
- [x] Добавить inclusive range (одно значение или min-max) в `AmneziaConfig` и UAPI set/get.
- [x] Добавлять случайное число нулевых байтов к transport plaintext до AEAD encryption.
- [x] Ограничивать ContentPaddingAddition остатком peer UDP window (по умолчанию 500 байт); пустые keepalive не дополнять.
- [x] Приёмная сторона обрезает расшифрованный пакет по IPv4 Total Length / IPv6 Payload Length через существующий validator.
- [x] Добавить IPv4/IPv6 boundary и receive-trimming tests, включая clamp по доступному peer UDP window. На актуальном HEAD `34343e78f1cd5250d636cdf322c2b7026c9bbf1a` прошли Linux tests, integration-tests, clippy, check_features, rustfmt и Semgrep.

**Готово, когда:** пакеты не превышают MTU/буферные лимиты, payload восстанавливается без изменений, значения диапазона соблюдаются.

**Реализация в работе:** range/config/UAPI и обработка до AEAD добавлены в рабочую ветку. После повторной сверки `device/send.go` upstream граница ContentPaddingAddition исправлена: добавление ограничивается остатком peer UDP window, а не локальным TUN MTU. IPv4/IPv6 тесты формируют датаграммы, оставляющие ровно пять байт в стандартном окне 500 байт, и проверяют восстановление исходного IP-пакета. При отсутствии параметра прежнее поведение BoringTun сохраняется.

### Этап 4. Рандомизация протокольных таймеров
- [x] Сопоставить RekeyAfterTime, RekeyTimeout, RejectAfterTime, KeepaliveTimeout и MaxHandshakeAttempts с polling state machine BoringTun; документировать архитектурные отличия.
- [x] Добавить диапазоны и UAPI set/get parsing с merge semantics и проверкой обратных диапазонов.
- [x] Добавить случайный inclusive range picker, выбор порогов по событиям data sent/received и handshake lifecycle, jitter 0..333 ms и счётчик handshake retries.
- [x] Добавить тесты parsing/merge, fixed-range selection и WireGuard defaults.
- [x] Согласовать inactivity timers с upstream lifecycle: первый data-send запускает new-handshake timer, первый data-receive запускает keepalive timer; последующие пакеты не сдвигают активный deadline, повторные receive запрашивают дополнительный keepalive.
- [x] Добавить mock-instant регрессии для idle-before-first-send, повторных receive, сохранения первого deadline и дополнительного keepalive.
- [ ] Differentially verify точные точки выбора диапазонов и retry/expiry semantics против upstream peer; покрыть сценарии rekey/inactivity/handshake exhaustion.

**Готово, когда:** интервалы и поведение соответствуют upstream и не меняют дефолты WireGuard.

**Текущий статус:** диапазоны, UAPI, случайный выбор порогов, retry budget и jitter реализованы. Inactivity deadlines теперь моделируют upstream timer lifecycle: повторная отправка данных не перезапускает уже активный new-handshake timer; повторное получение данных не сдвигает активный keepalive timer и запрашивает ещё один keepalive после первого. Добавлены mock-instant regressions. Этап остаётся незавершённым до differential-проверки выбора значений и retry/expiry против upstream.

### Этап 5. RandomTrailers
- [x] Сверить upstream алгоритм: handshake/cookie получают случайный незашифрованный хвост; transport получает нулевое дополнение внутри AEAD; предел — peer UDP window (по умолчанию 500 байт).
- [x] Реализовать опциональный флаг `random_trailers` (по умолчанию выключен), handshake/cookie trailer и transport padding с ограничением по peer UDP window и максимальному размеру UDP-датаграммы.
- [x] Реализовать inbound распознавание переменной длины с удалением handshake/cookie trailer до MAC/Noise parsing; для transport лишние нули удаляются по IPv4 Total Length / IPv6 Payload Length после AEAD.
- [x] Сохранить upstream precedence: ContentPaddingAddition заменяет RandomTrailers только для transport; handshake/cookie trailers остаются независимыми.
- [x] Ограничить cookie trailer остатком размера исходного запроса, чтобы RandomTrailers не создавал amplification.
- [x] Добавить unit/tunnel тесты на handshake/cookie framing, совместную работу HP + trailer, transport AEAD padding, UDP-window bounds и CPA precedence.
- [x] Исправить локальное увеличение UDP window исходящим размером пакета: окно теперь растёт только по аутентифицированной входящей датаграмме, как в upstream. Добавлен regression test: пакет больше начального окна 500 байт не получает случайное дополнение.
- [ ] Differentially verify wire lengths, random range boundaries, H1-H4 classification and cookie reply behaviour against upstream Go peer; отдельно закрыть regressions из upstream issues #185/#186.

**Готово, когда:** обе стороны принимают пакеты с trailer, корректно выделяют исходное сообщение и не возникает потерь на допустимых комбинациях диапазонов. Этап не считается завершённым до differential interop.

### Этап 6. UAPI, конфигурация и документация
- [x] Поддержать новые параметры в UAPI set/get, включая сериализацию обоих состояний boolean-флагов; проверить parse/merge и round-trip значений.
- [x] Добавить fallible `Tunn::try_set_obfuscation`: runtime update сначала проверяет все ограничения, а при ошибке сохраняет прежнюю конфигурацию. Старый `set_obfuscation` API оставлен совместимым и логирует отказ.
- [x] Документировать формат ключей/диапазонов, согласование настроек сторон, UDP-window/MTU ограничения и обратную совместимость в `docs/AMNEZIAWG_3_1_CONFIGURATION.md`.
- [x] Добавить ссылку на документацию и оговорку о неполной interop-валидации в README.
- [x] Проверить merge semantics: частичный `set` не сбрасывает неуказанные параметры и существующие imitation-настройки.

**Статус:** UAPI и конфигурационная документация обновлены. Полная release-готовность не достигнута до выполнения этапа 7.

**Готово, когда:** конфигурацию можно безопасно применить, прочитать обратно и перенести без потери значений.

### Этап 7. Межоперабельность и выпуск
- [ ] Поднять тестовую матрицу BoringTun client ↔ amneziawg-go server и наоборот.
- [ ] Прогнать vanilla WireGuard ↔ BoringTun в обоих направлениях.
- [ ] Прогнать AWG 2.x без новых параметров.
- [ ] Прогнать AWG 3.1 с каждым механизмом отдельно и со всеми вместе.
- [x] Выполнить cargo fmt, cargo hack check/test/clippy --each-feature и Linux CI.
- [x] Добавить Windows `cargo check -p boringtun --no-default-features` как обязательную проверку `all-systems-go`; macOS `cargo check -p boringtun --all-features` и `cargo check -p boringtun-cli` вынесены в отдельную дополнительную job, не блокирующую основной merge gate.
- [x] Прогнать существующие probe/imitation unit tests и Linux integration tests; полный upstream interop остаётся отдельным незавершённым пунктом.
- [ ] После review и зелёного CI обновить PR и только затем обсуждать merge.

**Готово, когда:** вся матрица совместимости пройдена, а документация отражает фактический уровень поддержки.

## Матрица параметров

| Возможность | Состояние на старте плана | Целевой этап |
|---|---|---|
| Jc/Jmin/Jmax | Реализовано | Сохранить, регресс-тесты |
| S1-S4 | Реализовано | Расширить требованиями HPK/MTU |
| H1-H4 ranges | Реализовано | Проверить режим HPK и RandomTrailers |
| I1-I5 CPS | UAPI принимает, но фактическая отправка не подтверждена; аудит обязателен | Отдельная проверка в этапе 0/6 |
| DNS/SIP/STUN/QUIC imitation | Реализовано как существующее расширение | Сохранить |
| DisableCookies | Реализовано в PR #8, Linux CI зелёный | Этап 1 |
| HeaderProtectionKey | Реализовано в Rust/UAPI; Go differential и полноценный двусторонний interop не выполнены | Этап 2 |
| ContentPaddingAddition | Реализовано в текущем PR: config/UAPI, peer-UDP-window-bounded transport padding и receive trimming; IPv4/IPv6 boundary/receive-trimming tests; IPv4 keepalive test | Этап 3 |
| Randomized timers | Реализованы диапазоны UAPI/config, случайный выбор порогов, jitter и retry budget; differential interop ещё не выполнен | Этап 4 |
| RandomTrailers | Реализованы handshake/cookie trailers и transport AEAD padding, UAPI flag off by default; differential interop ещё не выполнен | Этап 5 |

## Точки входа в код

Ориентиры для следующего агента (проверяйте актуальные имена и строки перед изменениями):
- `boringtun/src/noise/amnezia.rs` — конфигурация AWG, S-prefix, H ranges и подготовка пакетов.
- `boringtun/src/noise/mod.rs` — обработка пакетов туннеля и rate limiter.
- `boringtun/src/noise/handshake.rs` — формирование/разбор Noise handshake.
- `boringtun/src/device/mod.rs` — UDP ingress/egress и маршрутизация пакетов.
- `boringtun/src/device/api.rs` — UAPI parsing, merge и get.
- `boringtun/src/noise/rate_limiter.rs` — MAC/cookie/rate-limit поведение.

### ContentPaddingAddition: upstream wire semantics

- Upstream `device/send.go` выбирает случайное добавление по inclusive range для непустого transport payload, ограничивает его свободным местом до tunnel MTU, добавляет нулевые байты к plaintext IP-пакету и затем шифрует расширенный payload через AEAD. Это отличается от S4 — незашифрованного префикса перед WireGuard message.
- Upstream `device/receive.go` сначала расшифровывает, затем проверяет внутреннюю длину IPv4 Total Length или IPv6 Payload Length и обрезает plaintext перед записью в TUN. BoringTun уже выполняет это в `Tunn::validate_decapsulated_packet`, поэтому дополнительное поле framing не требуется.
- Пустые keepalive не дополняются. Если параметр не задан, эта реализация сохраняет существующие размеры пакетов BoringTun, не меняя legacy wire lengths побочным эффектом.
- Текущая реализация добавляет inclusive `u16` range в `AmneziaConfig` и UAPI `content_padding_addition`, добавляет нулевые байты до AEAD и ограничивает их доступным peer UDP window. Пустой payload не получает CPA. В сочетании с RandomTrailers ContentPaddingAddition имеет приоритет для transport, как в upstream; handshake/cookie trailers остаются независимыми.
- Upstream sources: `device/send.go` (`randomPaddingAddition`, `RoutineEncryption`) и `device/receive.go` (`RoutineDecryption` и IPv4/IPv6 length validation). В upstream есть отдельные edge-case reports по сочетанию ContentPaddingAddition/RandomTrailers; RandomTrailers остаётся выключенным до отдельного аудита.

## Последний handoff (2026-11-02)

- Рабочая ветка: `feat/amneziawg-3.1-disable-cookies`, draft PR #8.
- Актуальный полностью зелёный HEAD: `34343e78f1cd5250d636cdf322c2b7026c9bbf1a`. Linux jobs `tests`, `integration-tests`, `clippy`, `check_features`, `rustfmt`, `all-systems-go` и Semgrep завершились успешно. macOS/Windows не запускались по требованию.
- Header Protection: raw ChaCha20, nonce из первых 12 байт S-prefix; handshake/cookie защищаются целиком, transport — только первые 16 байт. Plaintext fallback при включённом ключе запрещён. Rust reference-vector и negative tests проходят, но Go differential и реальный двусторонний peer handshake ещё не выполнены.
- ContentPaddingAddition: transport plaintext padding ограничен peer UDP window; IPv4/IPv6 receive trimming и boundary tests проходят. Пустой keepalive не получает CPA.
- RandomTrailers: UAPI и framing реализованы, флаг выключен по умолчанию. Handshake/cookie получают внешний случайный trailer, transport — нулевое дополнение внутри AEAD. Для transport CPA имеет приоритет; cookie reply ограничен размером вызвавшей датаграммы.
- Исправлен важный UDP-window дефект: окно растёт только по аутентифицированной входящей transport-датаграмме, а не от исходящего пакета. Есть regression test для пакета больше начального окна 500 байт.
- Добавлен fallible `Tunn::try_set_obfuscation`, который валидирует настройки до изменения живого туннеля; старый setter сохранён для API-совместимости.
- UAPI get сериализует оба состояния `disable_cookies` и `random_trailers`; интеграционные ожидания обновлены. Добавлена пользовательская документация `docs/AMNEZIAWG_3_1_CONFIGURATION.md` и ссылка из README.
- Открытые критерии: Go differential tests для HP/RandomTrailers/cookie/H ranges; полный rekey/inactivity/retry differential audit; vanilla WG и AWG 2.x регрессии; BoringTun ↔ amneziawg-go в обоих направлениях. Полную поддержку AmneziaWG 3.1 не заявлять до завершения этих проверок.

## Протокол продолжения работы для нового агента

1. Прочитать этот документ и `README.md`, затем проверить PR #8 и актуальный head SHA.
2. Проверить состояние CI именно для актуального head SHA; не полагаться на старые результаты из переписки.
3. Сравнить реализацию с текущим upstream `amnezia-vpn/amneziawg-go` (зафиксировать commit/tag и ссылки на конкретные файлы).
4. Перед изменением пакетов описать wire format и порядок преобразований для send/receive; не делать предположений только по документации.
5. Реализовывать один этап за раз, добавляя unit, integration и differential tests.
6. Все изменения вести в feature-ветке и PR, не коммитить напрямую в `main`.
7. Не объявлять AWG 3.1 полной поддержкой до прохождения этапов 2-7 и всей матрицы совместимости.
8. В конце каждого этапа обновлять чекбоксы, матрицу параметров, проверенные SHA/CI и краткий handoff в этом документе.

## Источники

- Официальная документация AmneziaWG: https://docs.amnezia.org/ru/documentation/amnezia-wg/
- Официальный upstream: https://github.com/amnezia-vpn/amneziawg-go
- Upstream receive path: https://github.com/amnezia-vpn/amneziawg-go/blob/master/device/receive.go
- Upstream send path: https://github.com/amnezia-vpn/amneziawg-go/blob/master/device/send.go


## Технические заметки по аудиту upstream (2026-11-02)

Проверен актуальный upstream `amnezia-vpn/amneziawg-go` (ветка `master`); для воспроизводимого аудита перед реализацией каждого этапа нужно зафиксировать конкретный commit SHA upstream.

### Header Protection: подтверждённый порядок обработки

- Upstream хранит ключ как 32-байтовый `HeaderCipherKey`; UAPI принимает hex (`header_protection_key`), то есть 64 hex-символа. В пользовательском конфиге может быть base64-представление, но это отдельный слой сериализации.
- Проверенный upstream HEAD на момент аудита: `b5928efb6ca19f0153958460c3d141f04abc5c2e` (2026-08-28). Этот commit уточняет семантику `DisableCookies`: при флаге отключается весь under-load cookie challenge, а не только отправка Cookie Reply. MAC1 остаётся обязательным; MAC2/rate-limit challenge в under-load обходится. Это отражено в текущей реализации и тесте.
- Upstream создаёт raw ChaCha20 stream cipher: `chacha20.NewUnauthenticatedCipher(key, salt)`. `salt` — первые 12 байт S-prefix конкретного датаграмма; это не AEAD и не отдельная аутентификация.
- На отправке сначала формируется полный WireGuard message и его MAC-поля, затем тот же ChaCha20 stream XOR-ится с байтами сообщения от offset 0 до конца защищаемой части. Префикс S остаётся открытым и служит nonce.
- На приёме cipher создаётся из первых 12 байт префикса. Сначала нулевой 4-байтовый буфер XOR-ится с первыми 4 байтами keystream, чтобы восстановить тип сообщения и сопоставить H1-H4. Затем тем же экземпляром cipher (с уже сдвинутой позицией потока) расшифровываются байты сообщения начиная с offset 4. Для transport дополнительно расшифровывается заголовок до receiver index/counter lookup; для handshake/cookie расшифровывается остальное фиксированное сообщение.
- Поэтому текущий `strip_inbound`, который проверяет H-tag в открытом виде, нельзя просто оставить перед парсером. Нужен отдельный этап классификации с расшифровкой типа до выбора H-range, а затем полная расшифровка до проверки MAC1/MAC2 и разбора WireGuard-пакета.
- Все четыре S-prefix должны быть не короче 12 байт при включённом ключе. Проверка должна происходить атомарно при merge UAPI, чтобы частичная конфигурация не оставляла устройство в невалидном состоянии.
- Когда ключ не задан, байты и текущая legacy-проверка H1-H4 должны оставаться абсолютно неизменными.

Upstream точки сверки:
- `device/receive.go`: `RoutineReceiveIncoming`, `DeterminePacketTypeAndPadding`, `applyHash`.
- `device/send.go`: `SendHandshakeInitiation`, `SendHandshakeResponse`, `SendHandshakeCookie`, `RoutineEncryption`.
- `device/noise-protocol.go`: `HeaderProtectionCipher`.
- `device/noise-types.go`: размеры ключа и nonce.

### Текущая проверка CI для PR #8

Последний проверенный кодовый HEAD: `e11c15e3340b5e73305207f95e7d727d40f7877c`.

- PR Status Checks run [41496077388](https://github.com/lelikulibina/boringtun-awg/actions/runs/41496077388): Linux `rustfmt`, `clippy`, `check_features`, `tests`, `integration-tests`, `awg31-interoperability` и `all-systems-go` — **success**.
- Отдельный Semgrep OSS scan run [41496077499](https://github.com/lelikulibina/boringtun-awg/actions/runs/41496077499): **success**.
- Job `awg31-interoperability` собрал BoringTun и официальный `amneziawg-go` из закреплённого upstream SHA и успешно выполнил все 16 прогонов: 8 профилей × 2 серверные роли. Сюда входят vanilla WireGuard, AWG 2.x, HeaderProtectionKey, ContentPaddingAddition, RandomTrailers, DisableCookies, randomized timers и их совместная конфигурация.
- macOS/Windows не запускались.
- Результат подтверждает успешный handshake и двусторонний ICMP-трафик для перечисленных конфигураций. Он не является проверкой under-load cookie challenge, длительного rekey/retry/expiry или полной эквивалентности всех wire bytes.
- Следующие проверки должны быть направлены на differential vectors, искусственную нагрузку DisableCookies и таймерный lifecycle, а не на повторение уже зелёных CI suites.

Важное исправление после аудита: прежнее поведение `DisableCookies` (отклонять MAC2-invalid handshake без Cookie Reply) не совпадало с upstream. Исправлено на bypass under-load challenge целиком; MAC1 остаётся обязательным, входящие Cookie Reply поддерживаются.

### Этап 4: уточнённая upstream-семантика таймеров (аудит 2026-11-02)

Официальные источники: device/timers.go, device/send.go, device/receive.go, device/peer.go, device/constants.go.

- rekey_after_time: выбирается из диапазона при проверке свежести исходящего keypair; порог применяется только к keypair, инициированному локальной стороной.
- reject_after_time: при проверке входящих аутентифицированных данных выбирается порог обновления ключа; upstream вычитает минимальные keepalive_timeout и rekey_timeout. Для уничтожения key material использует верхнюю границу reject_after_time, умноженную на 3.
- rekey_timeout: случайное значение используется для retransmit handshake и для inactivity timeout; при расчёте последнего upstream использует максимум keepalive timeout и случайный rekey timeout. При старте peer минимальная граница участвует в начальном handshake pacing.
- keepalive_timeout: случайное значение для keepalive; нижняя граница участвует в receive-side rekey threshold, верхняя — в inactivity threshold.
- max_handshake_attempts: значение выбирается при старте peer и после успешного handshake, хранится до следующего handshake; не эквивалентно простому 90-секундному deadline.
- Повтор handshake в upstream использует rekey_timeout + random(0..333ms). Отдельный RekeyAttemptTime=90s — верхняя граница цикла попыток, но в AmneziaWG число повторов дополнительно ограничивается max_handshake_attempts.
- Default constants: rekey-after 120s, rekey-timeout 5s, reject-after 180s, keepalive-timeout 10s, max-handshake-attempts 18, jitter 0..333ms.

Архитектурное отличие BoringTun: Tunn::update_timers — polling state machine, тогда как upstream использует независимые peer timers и хранит отдельные счётчики попыток. Простая замена четырёх констант диапазонами даст неправильную точку повторного выбора и неверную семантику max attempts. До реализации необходимо добавить в Timers явное состояние выбранных порогов/счётчика handshake attempts и привязать выбор к событиям (session established, authenticated data sent/received, handshake initiation/retry), сохранив mock-instant поведение. Не менять криптографический state machine и не считать 90s deadline заменой max_handshake_attempts.

Текущий статус этапа 4: range state в AmneziaConfig/UAPI и Timers реализован; polling-модель BoringTun использует явные deadlines, чтобы сохранить семантику запуска и отмены upstream timers. Повторные события не должны случайно продлевать активные deadlines. Следующий шаг — differential peer tests для rekey, inactivity, retry exhaustion и expiry. Реализация должна оставаться opt-in и сохранять vanilla WG defaults.

Дополнительное покрытие timer state (последующие коммиты в feature-ветке):
- Добавлены regressions для fallback только при диапазоне `(0, 0)`, fixed min=max endpoints для всех пяти параметров, нулевой нижней границы и полного диапазона `u32` без переполнения.
- Добавлена проверка отклонения reversed bounds для каждого из пяти timer-параметров.
- Добавлены проверки замены диапазонов в уже созданном `Timers` и обновления/отключения persistent keepalive.
- Эти тесты покрывают выбор диапазонов и конфигурационное состояние, но не моделируют течение времени и реальные повторные handshake. Они должны пройти полный CI на актуальном HEAD; differential peer lifecycle tests остаются отдельной задачей.

### Этап 4: проверки границ reject и повторного handshake (2026-11-02)

Сверка с `device/timers.go` официального `amneziawg-go` на закреплённом SHA `b5928efb6ca19f0153958460c3d141f04abc5c2e` подтверждает следующие правила:

- `keychainExpireTime()` использует верхнюю границу `reject_after_time`; удаление key material происходит через `3 × upper_bound`.
- Сессионные ключи удаляются после истечения верхней границы `reject_after_time`; в BoringTun polling-проверка выполняется при `time_now - session_time > upper_bound`.
- `max_handshake_attempts` хранится в peer-состоянии, сбрасывается после успешного handshake и выбирается заново при его завершении.
- Retry budget проверяется при срабатывании retransmit timeout, а не при каждом вызове polling API.

Добавлены mock-clock regressions: раздельное истечение session keys и handshake key material; строгая граница `> upper_bound` для сессии; срок key material ровно `3 × upper_bound`; использование верхней границы настроенного диапазона reject; сброс счётчика попыток и повторная установка фиксированного max-handshake-attempts после успешного handshake.

Дополнительные peer-level regressions после этого аудита:
- Под искусственной нагрузкой (rate-limit = 0) полный handshake с `DisableCookies` проходит без cookie exchange; повреждённый MAC1 при этом отклоняется. Это проверяет не только rate limiter helper, но и реальный `Tunn::decapsulate` путь.
- Аутентифицированный входящий data packet отменяет ожидающий inactivity-handshake deadline.
- Аутентифицированный исходящий data packet отменяет ожидающий keepalive deadline.
- При проверке отменённых deadlines тесты оставляют запас по keepalive timeout, чтобы отдельно не запускать штатную keepalive отправку.
- Исправлен тест границы reject: перед проверкой срока жизни session keys он теперь действительно устанавливает handshake и создаёт session. Ранее он проверял пустой набор sessions и давал ложный результат.
- `handshake_attempts` открыт для родительского тестового модуля через `pub(super)`; внешний API не расширен.

Последний полностью завершённый CI до этих новых тестов: run `41499066051` — `rustfmt`, `check_features`, `integration-tests`, `tests`, `clippy`, `awg31-interoperability` и `all-systems-go` завершились успешно; Semgrep `41499065998` также успешен. Новые regressions добавлены в последующих коммитах и требуют отдельного зелёного CI.


Проверка на HEAD `eb5eadbcb7d509eba5e60c97bd17e6d51eacb0fe` завершена: Linux `rustfmt`, `clippy`, `check_features`, `tests`, `integration-tests`, `awg31-interoperability` и `all-systems-go` — success; Semgrep OSS scan — success. Peer-level DisableCookies и timer cancellation regressions вошли в зелёный прогон. Interop harness подтвердил 16/16 профилей на том же upstream SHA; macOS/Windows в этом цикле не запускались.


### Этап 5: дополнительные wire-level regressions (2026-11-02)

- Расширены фиксированные HeaderProtection vectors для всех фиксированных сообщений: initiation, response и cookie reply. Добавлены независимые ожидаемые ciphertext-префиксы для response/cookie на одном ключе и nonce; декодирование сверяется с исходным сообщением.
- Для transport закреплён отдельный 16-байтовый вектор заголовка: тип, receiver index и counter зашифрованы ChaCha20, AEAD payload остаётся неизменным.
- Для ContentPaddingAddition добавлены границы inclusive `[min, max]`, проверка включённого верхнего endpoint, clamp к свободному месту UDP window, нулевого остатка окна и отсутствия padding для keepalive.
- CI на кодовом HEAD `a6237d7638ef17a50489a55c6e311b8c133b6392`: rustfmt, clippy, check_features, tests, integration-tests, awg31-interoperability (16/16), all-systems-go и Semgrep — success.
- Эти фиксированные векторы проверяют ChaCha20/защищённые поля и не заменяют полную дифференциальную запись всех wire datagrams с upstream; отдельные randomized trailer lengths и MAC поля всё ещё требуют точечных differential fixtures.


### Этап 5: cookie/MAC flow при совместной обфускации

- Добавлен peer-level тест полного under-load cookie exchange при одновременно включённых HeaderProtectionKey и RandomTrailers: responder выдаёт защищённый Cookie Reply с S3/trailer, initiator принимает его и принудительно повторяет handshake с MAC2, responder принимает MAC2 и обе стороны устанавливают session.
- Тест явно задаёт source IP responder-у: без адреса rate limiter корректно возвращает `UnderLoad`, а не Cookie Reply, поскольку cookie криптографически привязан к IP.
- После получения cookie повторный `format_handshake_initiation` выполняется с `force_resend = true`, что соответствует повторной отправке уже начатого handshake после cookie challenge.
- CI на кодовом HEAD `4e9f8be619e78e8d1fa5c4199263cf5e73f6bc43`: rustfmt, clippy, check_features, tests, integration-tests, awg31-interoperability (16/16), all-systems-go и Semgrep — success.


### Этап 5: границы RandomTrailers и collision guard (2026-11-02)

- Добавлен regression test, сверяющий распределённую границу RandomTrailers с upstream `fastrandn(udpWindow - packetSize)`: верхняя граница exclusive, а размер дополнительно ограничивается лимитом исходного запроса/датаграммы и peer UDP window; отсутствие свободного места и выключенный флаг дают нулевой trailer.
- Добавлен boundary test для совокупной inclusive ширины H1-H3: конфигурация ровно на лимите collision guard принимается, превышение на одно значение отклоняется. В расчёте учитываются singleton H2/H3, а не только диапазон H1.
- На HEAD `3660a39e974c74efd70c6efb9ba9a8c5b6b06bc9` прошли `tests`, `integration-tests`, `clippy`, `check_features`, `rustfmt`, `awg31-interoperability` (16/16) и Semgrep. Windows core build прошёл на предыдущем HEAD `981ee08becc6b0fda5349812a49297623525445a`; macOS job ожидал runner. Для нового runner закреплён `macos-15-intel`; CI HEAD `e85c16400fc554ee8a6cf333eb3ed19823df7cfe` выполняется.
- Эти тесты подтверждают арифметику размеров и защиту от H1-H3 false-positive роста, но не заменяют полное дифференциальное сравнение pcap/wire datagrams с Go для всех вариантов RandomTrailers.


### Этап 6: атомарное применение UAPI и платформенный gate (2026-11-02)

- Добавлен combined UAPI regression: одна транзакция применяет H1-H4, DisableCookies, RandomTrailers, HeaderProtectionKey, ContentPaddingAddition и все пять timer ranges; затем partial update меняет только keepalive_timeout и сохраняет все остальные параметры.
- Обязательная Windows-сборка protocol core (`cargo check -p boringtun --no-default-features`) прошла.
- Linux rustfmt, clippy, check_features, tests, integration-tests, 16/16 upstream interop и all-systems-go прошли на кодовом HEAD `396c5f9dd696c6ebc1d2ae03b2fce8d811573c21`; Semgrep прошёл на HEAD `ee6722106002ed4b649cba3a958843c1eecda18d`.
- Дополнительная macOS device/CLI job сохранена, но runner assignment остаётся в очереди и не блокирует обязательный gate. macOS build пока не считается проверенным.


### Этап 6: семантика повторного handshake и таймеров активности (2026-11-02)

- Retry budget теперь выбирается при создании peer и после успешного handshake; начало новой попытки и retransmit не пересэмплируют `MaxHandshakeAttempts`. Изменение UAPI timer range влияет на следующий успешный handshake, а не на уже активный цикл повторов.
- Добавлены проверки send-side `RekeyAfterTime` на точной границе и receive-side порога `RejectAfterTime - KeepaliveTimeout.Lo - RekeyTimeout.Lo` с диапазонами и детерминированным clock boundary.
- Проверено, что inactivity handshake deadline не сбрасывается неаутентифицированным transport-пакетом и сбрасывается только после успешной AEAD-аутентификации входящего data.
- CI на кодовом HEAD `488407da2f2e1a9e3da9a666a9d5dbb02b311d07`: `rustfmt`, `clippy`, `check_features`, `tests` (261 passed, 9 ignored), `integration-tests`, Windows core check, `awg31-interoperability` (16/16) и `all-systems-go` — success; Semgrep — success. Дополнительная macOS job не входила в merge gate и ожидала runner.
- Эти проверки закрывают timer state transitions и контроль AEAD-гейта для inactivity deadline. Они не заменяют wire-level differential vectors для MAC/H1-H4 и pcap-сравнение внешних датаграмм.


### Этап 7: outbound wire-векторы HeaderProtection и H1-H4 (2026-11-02)

- Добавлен тест outbound HeaderProtection, который для handshake initiation, response, cookie reply и transport строит эталонный ChaCha20-результат с nonce из S-prefix и сравнивает каждый защищаемый байт. Для transport отдельно проверяется, что payload/AEAD ciphertext после первых 16 байт не изменён.
- Добавлен тест классификации нестандартных singleton H1-H4 tags с HeaderProtection для всех четырёх типов пакетов.
- Существующие inbound known-answer vectors продолжают проверять стандартный ChaCha20 поток для полного handshake/cookie сообщения и 16-байтового transport header.
- CI на кодовом HEAD `d3ac38be1e394a4fc32d7f07a4fb4e534c377c3d`: `rustfmt`, `clippy`, `check_features`, tests (263 passed, 9 ignored), integration-tests, Windows core check, interop (16/16), `all-systems-go` и Semgrep — success. Дополнительная macOS job остаётся вне merge gate и ожидает runner.
- Следующая задача — фиксированные differential fixtures для MAC1/MAC2 и побайтовая проверка внешних S-prefix/trailer datagrams; текущие tests подтверждают ChaCha20-обработку и сохранность AEAD payload, но не являются полным pcap comparison.


### Этап 8: MAC1/MAC2 BLAKE2s known-answer vectors (2026-11-02)

- Добавлен детерминированный known-answer test для ключа MAC1 (`BLAKE2s-256("mac1----" || peer_public)`), MAC1 (`BLAKE2s-128` keyed), cookie-encryption key (`BLAKE2s-256("cookie--" || peer_public)`), source-bound cookie и MAC2 над `message || MAC1`.
- Векторы вычислены независимой реализацией Python `hashlib.blake2s` с фиксированными ключами/входами и соответствуют upstream Go `blake2s.New256/New128` semantics; тест ловит изменения labels, key derivation, truncation и coverage MAC2.
- На кодовом HEAD `172446911971da2106d267c920b6fa90fd039997`: tests (264 passed, 9 ignored), `rustfmt`, `clippy`, `check_features`, integration-tests, Windows core check, interop (16/16), `all-systems-go` и Semgrep — success. Дополнительная macOS job ещё выполнялась и не блокирует merge gate.
- Следующая проверка — deterministic XChaCha20-Poly1305 cookie-reply fixture и внешние wire datagrams с trailer bytes; текущие MAC vectors проверяют ключи/теги, но не AEAD cookie envelope.


### Этап 9: композиция DisableCookies с преобразованиями AWG 3.1 (2026-11-02)

- Добавлен peer-level regression под принудительной нагрузкой (RateLimiter limit = 0): DisableCookies проходит полный handshake без Cookie Reply при одновременном включении HeaderProtectionKey, ContentPaddingAddition и RandomTrailers.
- Тест использует минимально допустимый для HeaderProtection 12-байтовый S-prefix; это проверяет не только bypass cookie challenge, но и ограничение формата заголовка. MAC1 остаётся обязательным в отдельном peer-level тесте.
- На кодовом HEAD 43dbbda4bbba05b005290a855c66bbc2b2336def: tests (266 passed, 9 ignored), rustfmt, clippy, check_features, integration-tests, Windows core build, awg31-interoperability (16/16), all-systems-go и Semgrep — success.
- Дополнительная macOS job выполняется отдельно и не блокирует обязательный gate.
- Первый вариант regression выявил некорректную тестовую конфигурацию: 8-байтовый S-prefix несовместим с HeaderProtection, которому требуется не менее 12 байт для nonce. Тест исправлен на валидные 12 байт; итоговый CI прошёл.


### Этап 10: аутентичность Cookie Reply при HeaderProtection (2026-11-02)

- В сквозном cookie-challenge тесте с HeaderProtectionKey и RandomTrailers добавлена порча байта AEAD-тега внутри защищённого 64-байтового Cookie Reply. Получатель обязан вернуть InvalidAeadTag; затем исходный корректный Cookie Reply принимается, и MAC2 handshake завершается. Это подтверждает, что случайный внешний trailer не сдвигает границы фиксированного сообщения и отвергнутый пакет не мешает последующей корректной cookie-авторизации.
- На HEAD 642ff21410a366159a75dd0cd81838f2c2d84d37: tests (266 passed, 9 ignored), rustfmt, clippy, check_features, integration-tests, Windows и macOS core/device builds, awg31-interoperability (16/16), all-systems-go и Semgrep — success.


### Этап 11: DisableCookies для обеих сторон handshake (2026-11-02)

- Добавлен peer-level тест входящего Handshake Response под принудительной нагрузкой на RateLimiter. При DisableCookies корректный ответ принимается без Cookie Reply; испорченный MAC1 отклоняется как InvalidMac. После этого исходный ответ принимается, и сессия успешно завершается.
- Это дополняет проверку инициирующего Handshake Init и подтверждает одинаковую политику bypass для обоих типов handshake-сообщений при обязательной проверке MAC1.
- На HEAD 62953032edf0b1e6d89db601d6f33c4141d3c991: tests (267 passed, 9 ignored), rustfmt, clippy, check_features, integration-tests, Windows и macOS builds, awg31-interoperability (16/16), all-systems-go и Semgrep — success.


### Этап 12: детерминированные границы ContentPaddingAddition (2026-11-02)

- Вынесено отображение случайного u32 в inclusive CPA range в отдельный mapper. Rejection sampling сохраняет отсутствие modulo bias и явно отбрасывает хвост распределения.
- Добавлены детерминированные проверки: первый/последний допустимый sample, первый sample rejection tail, полный диапазон u16 без переполнения, singleton и reversed bounds.
- На HEAD b3304c0b0ec570f9976c58c3a62f6abb9ecb61b2: tests (268 passed, 9 ignored), rustfmt, clippy, check_features, integration-tests, Windows и macOS builds, awg31-interoperability (16/16), all-systems-go и Semgrep — success.


### Этап 13: аутентифицированный сброс inactivity deadline и роли rekey (2026-11-02)

- Добавлен regression: первый исходящий data packet запускает inactivity-handshake deadline; последующий аутентифицированный входящий data packet отменяет его; следующий исходящий data packet начинает новый deadline. Отдельный существующий тест подтверждает, что повреждённый AEAD packet не отменяет deadline.
- Добавлен regression роли responder: исходный responder не инициирует send-side rekey только по достижении RekeyAfterTime; этот порог относится к исходному initiator. Параллельно сохраняется точная проверка send-side rekey для initiator и receive-side порога RejectAfterTime - KeepaliveTimeout.Lo - RekeyTimeout.Lo.
- Peer-level DisableCookies coverage подтверждает полный handshake при искусственном under-load, обязательность MAC1 и bypass MAC2/cookie challenge для Init и Response.
- На HEAD `9387c3bdb0f4c5b029bdbe4636f22cd939e3a758` обязательные проверки прошли: rustfmt, clippy, check_features, tests (включая mock-instant timer regressions), integration-tests, Windows core check, macOS build, AWG interop (16/16) и all-systems-go; Semgrep — success.
- Следующий этап: расширить differential wire fixtures для CPA и RandomTrailers, включая сравнение точных внешних datagram lengths и authenticated plaintext boundaries с закреплённым upstream.

### Этап 14: детерминированная защита классификации RandomTrailers (2026-11-02)

- Заменено вероятностное ограничение суммарной ширины H1-H3 на детерминированную проверку: при включённом RandomTrailers BoringTun требует S1 = S2 = S3 = S4. При одинаковом смещении все четыре классификатора читают одно поле типа; непересекающиеся H1-H4 исключают описанную в upstream #186 ложную классификацию transport как handshake.
- Добавлены regressions на диапазонах из upstream issue #186: конфигурация с разными S отклоняется, одинаковые S проходят; синтетический transport frame с ложным H2-кандидатом на старом S2-offset корректно распознаётся как transport при общем offset.
- Interop harness переведён на S1-S4 = 120 для профилей RandomTrailers и совместного AWG 3.1, сохраняя AWG 2.x baseline и все двусторонние роли.
- Публичный Tunn::new_with_obfuscation теперь вызывает полную AmneziaConfig::validate, а не только timer validation, чтобы прямой constructor не обходил ограничения размеров, CPA и cookie amplification.
- Это осознанно более строгое поведение, чем upstream Go: официальная документация рекомендует одинаковые S при RandomTrailers, но Go не отклоняет неравные значения. BoringTun теперь сообщает ошибку при конфигурации, которая может приводить к тихой потере transport-пакетов.
- CI на HEAD bbf43d0f3fa6fbb3254895424d617df6eb460272 запущен; результаты ещё не получены. До завершения CI изменения не считаются проверенными.

## Продолжение работ — 2026-11-03

- На HEAD `53d4b10aac55b4c000644d6947ab7f4791f89bde` подтверждены Linux tests, integration tests, clippy, check_features, rustfmt, AWG 3.1 interoperability (16/16) и Semgrep — все успешно.
- Добавлен отдельный rate-limiter regression для `DisableCookies` на Handshake Response: корректный MAC1 принимается под искусственной нагрузкой без MAC2, cookie challenge и увеличения under-load счётчика. Это дополняет существующие initiation-тесты.
- Кроссплатформенные jobs macOS/Windows временно исключены из PR workflow на время протокольной валидации AWG 3.1; Linux checks и Go interoperability остаются обязательными. После завершения wire-level/differential этапа платформенные jobs следует вернуть.
- Новый тест и изменение workflow требуют отдельного CI на обновлённом HEAD; до его завершения их прохождение не заявляется.

### Этап 15: завершённый send-side rekey (2026-11-03)

- Добавлен mock-clock regression, который не ограничивается проверкой факта отправки нового Handshake Initiation: после достижения `RekeyAfterTime` инициатор и peer проходят полный повторный Noise handshake, handshake timestamp обновляется, а новый transport session подтверждается реальным зашифрованным IPv4-пакетом.
- Проверка кроссует timer trigger → initiation → response → keepalive/session installation → authenticated data; до этого предыдущий тест подтверждал только отправку initiation в момент deadline.
- Требуется подтверждение Linux CI на новом HEAD. Это локальный peer-level state-machine regression, а не замена длительного differential-теста с amneziawg-go.


### Этап 16: восстановление handshake после потери ответа (2026-11-03)

- Добавлен mock-clock regression: responder принимает первое Handshake Initiation и отправляет корректный Response, который моделируется потерянным в сети.
- После истечения настроенного RekeyTimeout плюс верхней границы jitter инициатор повторно отправляет новое Initiation; responder принимает повтор, handshake завершается, retry budget сбрасывается, обе стороны устанавливают новые сессии.
- Проверяется реальная передача IPv4-пакета через восстановленную сессию. Это дополняет проверку исчерпания retry budget: покрываются как успешное восстановление после потери Response, так и окончательный отказ при превышении числа попыток.
- Требуется подтверждение Linux CI на коммите этапа 16; до завершения CI тест не считается пройденным.


### Этап 17: двусторонний UDP payload в Go interop matrix (2026-11-03)

- Interop harness расширен: каждый из 8 профилей в обеих серверных ролях теперь проверяет не только handshake и двусторонний ICMP, но и реальный UDP request/reply через зашифрованный туннель.
- UDP server/client запускаются внутри изолированных network namespaces; проверяется точное содержимое ответа, а не только наличие маршрута или handshake timestamp.
- Требуется подтверждение полного CI и 16/16 interop прогонов на новом HEAD.


### Этап 18: XChaCha20-Poly1305 Cookie Reply known-answer vector (2026-11-03)

- Добавлен фиксированный 64-байтовый Cookie Reply fixture с детерминированными nonce key/counter, AEAD key, cookie, MAC1 и H3 tag.
- Эталон независимо рассчитан через keyed BLAKE2s-192 и XChaCha20-Poly1305 (HChaCha20 + ChaCha20-Poly1305); сравнивается весь wire envelope: type, receiver index, nonce, ciphertext и Poly1305 tag.
- Это закрывает ранее отмеченный пробел между MAC1/MAC2 known-answer vectors и end-to-end проверкой Cookie Reply authentication. Требуется CI на новом HEAD.


### Этап 19: реальный send-side rekey между BoringTun и Go (2026-11-03)

- В interop matrix добавлен профиль accelerated rekey с короткими UAPI ranges: RekeyAfterTime=2s, RekeyTimeout=2s, RejectAfterTime=30s, KeepaliveTimeout=2s и MaxHandshakeAttempts=3.
- В обеих ролях сервера harness запоминает timestamp первого handshake, создаёт исходящий трафик и ожидает его изменения после повторного handshake; затем повторно проверяет UDP request/reply через новую сессию.
- Это внешний differential state-machine test между BoringTun и закреплённым amneziawg-go, дополняющий локальный mock-clock coverage. Требуется CI на новом HEAD.


### Финальный этап A: нормализованная wire/pcap differential-проверка (2026-11-03)

- Interop harness захватывает реальные UDP datagrams на серверном veth через tcpdump для каждого из 9 профилей в обеих ролях (18 независимых сценариев).
- Pcap verifier декодирует Ethernet/IPv4/UDP, восстанавливает защищённое поле типа AWG 3.1 через ChaCha20 (для HPK-профилей), затем классифицирует H1-H4 и проверяет направление, фиксированные размеры Initiation/Response/Cookie Reply и framing Transport.
- Для RandomTrailers проверяются границы handshake/cookie envelope; для accelerated rekey в pcap требуются минимум два Initiation и два Response, а UDP roundtrip повторно проходит после смены handshake.
- Сравнение выполняется по нормализованной семантике пакетов, а не по полным байтам: ephemeral Noise keys, nonce и случайные trailers закономерно различаются между независимыми запусками. Побайтовое равенство двух независимых pcap не является корректным критерием.
- Требуется CI на новом HEAD; этап не считается завершённым до проверки.


### Финальный этап B: повторные rekey и непрерывная передача данных (2026-11-03)

- В обоих направлениях interop добавлены три последовательных send-side rekey с коротким интервалом 2 секунды.
- После каждого повторного handshake harness проверяет новый UAPI handshake timestamp и выполняет двусторонний UDP request/reply с точным payload.
- Pcap verifier требует не менее четырёх Handshake Initiation и четырёх Handshake Response на accelerated-rekey сценарий: исходный handshake плюс три rekey; transport traffic проверяется между переходами.
- Это короткий multi-rekey soak, а не длительный многочасовой тест и не симуляция packet loss. Проверка истечения старых ключей и потерь handshake-пакетов остаётся отдельным критерием до объявления полной поддержки.
- Требуется CI на новом HEAD.
