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
- [ ] Зафиксировать полный результат CI для исходной ветки/PR.
- [ ] Составить матрицу текущей совместимости и точек интеграции по каждому параметру.

**Готово, когда:** есть список реализованных/отсутствующих возможностей, известны точки ingress/egress и базовые тесты.

### Этап 1. DisableCookies
- [x] Добавить `disable_cookies` в конфигурацию с default=false.
- [x] Сверить и реализовать upstream-семантику: при включённом флаге сохранять MAC1-проверку, но обходить under-load MAC2/cookie challenge целиком.
- [x] Сохранить приём входящих Cookie Reply и старый публичный API rate limiter.
- [x] Добавить UAPI set/get и unit-тесты.
- [ ] Получить полный зелёный CI на PR.

**Готово, когда:** обычное поведение без флага не меняется; с флагом MAC1 продолжает проверяться, но under-load MAC2/cookie challenge отключён (handshake без MAC2 допускается), как в upstream; входящие Cookie Reply продолжают обрабатываться.

### Этап 2. HeaderProtectionKey (AWG 3.0+, требуется для полного профиля 3.1)
- [x] Сверить upstream receive/send path: первые 12 байт S-prefix — nonce; ChaCha20 XOR начинается с байта 0 WG-сообщения; на приёме тип восстанавливается до выбора H-range; transport защищает только 16-байтовый заголовок, handshake/cookie — всё фиксированное сообщение.
- [ ] Подтвердить точное совпадение Rust wire bytes с upstream Go известными тест-векторами/дифференциальным тестом. Добавлен детерминированный ChaCha20 reference-vector test для handshake и transport; результат ожидает Linux CI.
- [x] Добавить 32-байтовый ключ в `AmneziaConfig` и UAPI `header_protection_key` (64 hex-символа); all-zero key отключает защиту.
- [x] Валидировать требование S1-S4 >= 12 при включённой защите и отклонять некорректную конфигурацию.
- [x] Добавить ChaCha20 protection на egress/ingress: handshake/cookie защищаются целиком; transport — только type/receiver/counter (16 байт), AEAD ciphertext не меняется.
- [ ] Полностью согласовать H1-H4 detection и legacy-режим с upstream, включая все допустимые ranges.
- [x] Добавить unit round-trip и config validation coverage.
- [ ] Добавить upstream differential vectors и проверить interop на реальном amneziawg-go peer. Текущий Rust test проверяет фиксированный IETF ChaCha20 keystream и протокольное правило: handshake полностью, transport только первые 16 байт.
- [ ] Проверить отсутствие изменения wire bytes при выключенной защите и полную vanilla WG/AWG 2.x регрессию.

**Статус:** реализация ingress/egress и UAPI находится в PR #8. Добавлен детерминированный reference-vector test (key `0x42` × 32, nonce `00..0b`) с проверкой зашифрованного handshake-заголовка и неизменности transport payload; CI для коммита `d536be5f7f685554490f02b7068752179b4524a3` ожидает завершения. Этап не завершён: нужны внешний differential test с официальным Go peer, реальный двусторонний handshake и проверка vanilla WG/AWG 2.x.

**Готово, когда:** BoringTun и официальный AWG взаимно устанавливают туннель с одинаковым ключом, неверный ключ/недостаточный S-prefix корректно отклоняется, а vanilla WG и AWG 2.x не меняют поведение.

### Этап 3. ContentPaddingAddition
- [ ] Добавить диапазон (одиночное значение или inclusive min-max) в конфиг/UAPI.
- [ ] Случайно выбирать добавочный padding transport payload по правилам upstream.
- [ ] Учитывать MTU и максимально допустимый размер UDP-датаграммы без фрагментации/переполнения буфера.
- [ ] Проверить обработку входящего transport payload: padding должен сниматься корректно после расшифрования.
- [ ] Добавить тесты границ, keepalive, IPv4/IPv6, больших пакетов и межоперабельности.

**Готово, когда:** пакеты не превышают MTU/буферные лимиты, payload восстанавливается без изменений, значения диапазона соблюдаются.

### Этап 4. Рандомизация протокольных таймеров
- [ ] Определить соответствие RekeyAfterTime, RekeyTimeout, RejectAfterTime, KeepaliveTimeout и MaxHandshakeAttempts внутренним таймерам BoringTun.
- [ ] Добавить диапазоны и UAPI/config parsing с безопасной валидацией.
- [ ] Выбирать значения в тех же точках жизненного цикла, что и upstream (не каждый тик, если upstream выбирает один раз на сессию/пир).
- [ ] Добавить тесты min/max, повторного выбора, нулевых/обратных диапазонов и отсутствующих параметров.

**Готово, когда:** интервалы и поведение соответствуют upstream и не меняют дефолты WireGuard.

### Этап 5. RandomTrailers
- [ ] Сверить upstream алгоритм, особенно условия включения и поведение с H1-H4 ranges.
- [ ] Реализовать добавление случайных хвостовых байтов к нужным пакетам с учётом MTU.
- [ ] Реализовать совместное распознавание пакетов и корректное отбрасывание лишнего хвоста.
- [ ] Добавить регрессионные тесты на переменные H-диапазоны, все S1-S4, транспорт и handshake.
- [ ] Отдельно проверить известные upstream edge cases и не включать флаг по умолчанию.

**Готово, когда:** обе стороны принимают пакеты с trailer, корректно выделяют исходное сообщение и не возникает потерь на допустимых комбинациях диапазонов.

### Этап 6. UAPI, конфигурация и документация
- [ ] Поддержать все новые параметры в set/get, конфигурационном парсинге и round-trip сериализации.
- [ ] Документировать формат ключей/диапазонов, какие настройки должны совпадать на обеих сторонах, ограничения MTU и обратную совместимость.
- [ ] Обновить README/CHANGELOG и примеры конфигурации.
- [ ] Проверить merge semantics: частичный `set` не должен сбрасывать неуказанные параметры и существующие imitation-настройки.

**Готово, когда:** конфигурацию можно безопасно применить, прочитать обратно и перенести без потери значений.

### Этап 7. Межоперабельность и выпуск
- [ ] Поднять тестовую матрицу BoringTun client ↔ amneziawg-go server и наоборот.
- [ ] Прогнать vanilla WireGuard ↔ BoringTun в обоих направлениях.
- [ ] Прогнать AWG 2.x без новых параметров.
- [ ] Прогнать AWG 3.1 с каждым механизмом отдельно и со всеми вместе.
- [ ] Выполнить cargo fmt, cargo hack check/test/clippy --each-feature и CI на Linux/macOS/Windows.
- [ ] Проверить отсутствие регрессий существующих probe/imitation и интеграционных тестов.
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
| DisableCookies | Реализуется в PR #8 | Этап 1 |
| HeaderProtectionKey | Не реализовано | Этап 2 |
| ContentPaddingAddition | Не реализовано | Этап 3 |
| Randomized timers | Не реализовано | Этап 4 |
| RandomTrailers | Не реализовано | Этап 5 |

## Точки входа в код

Ориентиры для следующего агента (проверяйте актуальные имена и строки перед изменениями):
- `boringtun/src/noise/amnezia.rs` — конфигурация AWG, S-prefix, H ranges и подготовка пакетов.
- `boringtun/src/noise/mod.rs` — обработка пакетов туннеля и rate limiter.
- `boringtun/src/noise/handshake.rs` — формирование/разбор Noise handshake.
- `boringtun/src/device/mod.rs` — UDP ingress/egress и маршрутизация пакетов.
- `boringtun/src/device/api.rs` — UAPI parsing, merge и get.
- `boringtun/src/noise/rate_limiter.rs` — MAC/cookie/rate-limit поведение.

## Последний handoff (2026-11-02)

- Рабочая ветка: `feat/amneziawg-3.1-disable-cookies`, PR #8.
- Последний CI HEAD: `d536be5f7f685554490f02b7068752179b4524a3` (CI run `41457924674` и Semgrep `41457924557`; на момент обновления queued). Не переносить старые результаты на новый SHA.
- Header Protection сейчас частично реализован в `noise/amnezia.rs`, `noise/mod.rs`, `device/api.rs`; зависимость raw ChaCha20 добавлена в `boringtun/Cargo.toml` и lockfile.
- Upstream receive path: `device/receive.go`. Он сначала строит cipher по `packet[:12]`, восстанавливает type из ChaCha20 keystream, определяет packet kind/padding по H-ranges, затем XOR-ит оставшуюся часть handshake/cookie или только `packet[4:MessageTransportHeaderSize]` для transport. Send path шифрует handshake/cookie целиком, transport header отдельно. Не шифровать transport AEAD payload.
- Важное исправление уже внесено: transport egress ограничен первыми 16 байтами; payload/tag AEAD остаются нетронутыми.
- В CI workflow оставлены только Ubuntu/Linux jobs; macOS/Windows отключены, Semgrep остаётся отдельным workflow.
- Не считать этап Header Protection завершённым до differential test vectors и двустороннего теста с upstream. Сверить текущий код по актуальному upstream commit перед продолжением.

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

Последний документальный commit на момент заметки: `02c269f57579cb951785032d5e8a9f9b0e553c00`.

- Semgrep OSS scan: success.
- Linux: rustfmt, clippy, check_features, tests и integration-tests завершились success на предыдущем SHA `0a00757110660a40fe0a9684cb7fbafafb7f4dfa`.
- Для SHA документа `02c269f57579cb951785032d5e8a9f9b0e553c00` Semgrep прошёл, но PR workflow ещё выполнялся. После последующих исправлений запущен новый CI; не считать CI полностью зелёным, пока все jobs последнего SHA не завершатся.
- Важное исправление после аудита: прежнее поведение `DisableCookies` (отклонять MAC2-invalid handshake без Cookie Reply) не совпадало с upstream. Исправлено на bypass under-load challenge целиком; тест обновлён.
