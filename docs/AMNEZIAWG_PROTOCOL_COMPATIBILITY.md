# AmneziaWG: версии протокола, параметры, лимиты и совместимость

> Срез исследования: 2026-11-04. Основной эталон реализации — `amneziawg-go` tag `v3.1.20260828` (upstream commit `b5928efb6ca19f0153958460c3d141f04abc5c2e`). Для исторического сравнения использованы `v0.2.19`, `v3.0.0`, `v3.1.20260812` и `v3.1.20260828`. Ниже описано фактическое поведение исходников, а не только краткая таблица параметров на сайте.

## 1. Главный принцип совместимости

AmneziaWG не выполняет отдельное согласование версии протокола во время handshake. В пакетах нет поля «AWG 1.5/2.0/3.0/3.1», а стороны не договариваются о параметрах автоматически. В основе остаются сообщения WireGuard Noise IK; AmneziaWG меняет их внешнее представление, обрамление, часть заголовка, размеры, последовательность служебных пакетов и тайминги.

Параметры делятся на три класса:

1. **Общие параметры wire format** — должны совпадать на обеих сторонах: `S1-S4`, `H1-H4`, `HeaderProtectionKey`. `RandomTrailers` должен быть включён на каждом endpoint, который принимает внешние handshake/cookie trailers. Для обычного двустороннего туннеля его включают на обоих концах.
2. **Локальные параметры отправителя** — не требуют одинаковых значений у получателя: `Jc/Jmin/Jmax`, `I1-I5`, `ContentPaddingAddition`, таймеры.
3. **Локальная политика получателя** — `DisableCookies`. Она меняет реакцию конкретного endpoint под нагрузкой, а не формат обычных пакетов.

«Клиентские» и «серверные» настройки не следует путать с обязательной ролью инициатора. Любая сторона, которая инициирует handshake, может отправить I/J-пакеты. Рекомендация задавать их только на клиенте — операционная практика, а не ограничение Noise.

### Область действия: интерфейс или peer

В upstream Go UAPI почти все AWG-поля (`S/H`, `Jc/Jmin/Jmax`, `I1-I5`, HP key, CPA, RT, DisableCookies и timer ranges) — **поля Device**, то есть одна конфигурация интерфейса применяется ко всем peer на этом интерфейсе. В BoringTun это отражено в `DeviceConfig.obf` и `DeviceConfig.amnezia`. Самостоятельный library API `Tunn::new_with_amnezia` позволяет задать профиль отдельному Tunn, но daemon UAPI остаётся interface-wide. `persistent_keepalive_interval` — отдельная per-peer настройка.

## 2. История версий

Ниже — история возможностей по публичной документации Amnezia и историческим исходникам. Это **не** поле version negotiation и не гарантия, что любой бинарник с таким номером версии принимает все поздние ключи UAPI.

| Поколение | Существенные механизмы | Практический смысл |
|---|---|---|
| AWG 1.0 | `Jc`, `Jmin`, `Jmax`; `S1/S2`; `H1-H4` с фиксированными значениями | Junk-пакеты перед handshake, префиксы Init/Response и изменение type tags |
| AWG 1.5 | Имитация распространённых UDP-протоколов (QUIC/DNS), изменение заголовков и размеров handshake | Протокол-маскировка выходит за пределы одного фиксированного WireGuard packet shape |
| AWG 2.0 | `S3/S4`; диапазоны `H1-H4`; CPS/signature chain `I1-I5` и расширенная последовательность pre-handshake datagrams | Обфускация Cookie Reply и transport data; type tags выбираются из диапазонов; до handshake можно отправлять до пяти самостоятельных CPS-пакетов |
| AWG 3.0 | `HeaderProtectionKey`, `ContentPaddingAddition`, диапазоны таймеров | ChaCha20 скрывает незашифрованные поля WireGuard; внутри AEAD добавляется padding; таймеры рандомизируются |
| AWG 3.1 | `RandomTrailers`, `DisableCookies` | Вариативность внешней длины handshake/cookie, padding transport и изменение under-load cookie policy |

### Проверяемые поколения UAPI по исходникам

Ниже не рекламные названия релизов, а набор ключей, реально присутствующих в upstream UAPI на закреплённых ревизиях:

| Upstream source | Ключи, которые уже присутствуют в UAPI | Вывод |
|---|---|---|
| `v0.2.19` (до 3.x) | `jc/jmin/jmax`, `s1-s4`, `h1-h4`, `i1-i5` | Базовая обфускация и CPS |
| `v3.0.0` | Всё из предыдущего + `header_protection_key`, `content_padding_addition`, `rekey_after_time`, `rekey_timeout`, `reject_after_time`, `keepalive_timeout`, `max_handshake_attempts` | HP, CPA и timer ranges |
| `v3.1.20260812` | Всё из 3.0 + `random_trailers`, `disable_cookies` | Появились оба 3.1 ключа; ранняя DisableCookies реализация ещё не обходила under-load gate |
| `v3.1.20260828` | Тот же набор ключей, исправлен DisableCookies under-load gate | Текущий эталон 3.1 для этой ветки |

Это позволяет точно определить, когда UAPI parser вообще знает ключ. Наличие ключа не всегда доказывает корректность реализации: пример — `disable_cookies` в `v3.1.20260812`. Аналогично, старый бинарник может отвергнуть неизвестный ключ целиком при применении конфигурации, даже если сами сетевые пакеты без нового расширения были бы совместимы.

Исторические исходники:

- [amneziawg-go v0.2.19](https://github.com/amnezia-vpn/amneziawg-go/tree/v0.2.19) — поколение до 3.x с S3/S4, H-диапазонами и CPS.
- [AWG 3.0.0](https://github.com/amnezia-vpn/amneziawg-go/tree/v3.0.0) — Header Protection, Content Padding и custom timers.
- [AWG 3.1.20260812](https://github.com/amnezia-vpn/amneziawg-go/tree/v3.1.20260812) — ранняя реализация 3.1.
- [AWG 3.1.20260828](https://github.com/amnezia-vpn/amneziawg-go/tree/v3.1.20260828), commit `b5928ef` — исправлен DisableCookies under-load gate.

Важная деталь: уже в `v3.0.0` исходники задают `HeaderCipherNonceSize = 12` и отклоняют S-префиксы короче 12 байт при включённом Header Protection. В том же исходнике текст ошибки говорит «more than 8», но фактическое условие сравнивает длину с константой 12. Реализация должна ориентироваться на константу и проверку, а не на устаревшую строку ошибки: **каждый S-префикс не короче 12 байт**.

## 3. Wire format и размеры сообщений

Базовые размеры WireGuard-сообщений до Amnezia-префиксов:

| Сообщение | WG type | Базовый размер |
|---|---:|---:|
| Handshake Initiation | 1 | 148 байт |
| Handshake Response | 2 | 92 байта |
| Cookie Reply | 3 | 64 байта |
| Transport Data | 4 | 32 байта overhead плюс внутренний payload |

С учётом S-префиксов:

- Init: `S1 + 148`
- Response: `S2 + 92`
- Cookie Reply: `S3 + 64`
- Transport: `S4 + 32 + encrypted_payload_length`

У transport 32 байта — 16-байтовый заголовок (type, receiver index, counter) и 16-байтовый AEAD tag. Для пустого keepalive внутренний payload пуст, поэтому без padding wire length равен `S4 + 32`.

**Эффективные пределы S в BoringTun:** UAPI S — uint16, но валидатор дополнительно ограничивает каждую базовую UDP-датаграмму 65 507 байтами (IPv4 UDP payload limit). Поэтому максимумы без внутреннего transport payload: `S1 ≤ 65 359`, `S2 ≤ 65 415`, `S3 ≤ 65 443`, `S4 ≤ 65 475`. При HP нижняя граница каждого S — 12 байт. При `RandomTrailers=true` все четыре S должны быть равны, поэтому для такого профиля действует самый строгий максимум S=65 359. Это safety validation BoringTun; не следует считать, что любая uint16 длина безопасна для отправки.

`S1-S4` — длины фиксированных префиксов, а не диапазоны. UAPI upstream разбирает их как `uint16` (0…65 535). Фактическая отправка ограничена максимальной UDP payload-датаграммой: 65 507 байт для IPv4. BoringTun заранее проверяет, что базовый пакет с соответствующим S-префиксом помещается в этот предел.

## 4. Параметры и их ограничения

### 4.0 Значения по умолчанию в upstream 3.1

Здесь приведены именно defaults исходников amneziawg-go v3.1.20260828, а не рекомендации для развёртывания.

| Параметр | Default | Комментарий |
|---|---:|---|
| Jc | 0 | Junk train выключен |
| Jmin/Jmax | 0/0 | Сами по себе не создают junk; BoringTun подставляет безопасный диапазон 50–1000, если Jc включён и обе границы нулевые |
| S1-S4 | 0 | Нет дополнительных префиксов |
| H1-H4 | 1 / 2 / 3 / 4 | Стандартные WireGuard type tags |
| I1-I5 | пусто | CPS datagrams не отправляются |
| HeaderProtectionKey | нулевой ключ | Header Protection выключен |
| ContentPaddingAddition | 0–0 | CPA выключен; применяется обычное WG MTU padding, если RT тоже выключен |
| RandomTrailers | false | Внешние handshake/cookie trailers и transport RT выключены |
| DisableCookies | false | Under-load cookie challenge остаётся включён |
| RekeyAfterTime | 120 с | Порог инициирования rekey по отправке |
| RekeyTimeout | 5 с | Интервал handshake retry |
| RejectAfterTime | 180 с | Базовый срок жизни ключевого материала |
| KeepaliveTimeout | 10 с | Таймер keepalive |
| MaxTimerHandshakes | 18 | 90 / 5; лимит handshake попыток |
| DefaultUdpWindow | 500 байт | Начальный размер окна для device-level Cookie Reply |
| PersistentKeepalive | 0 | По умолчанию выключен; задаётся отдельно для каждого peer |

Важная разница defaults: upstream атомики Jmin/Jmax изначально равны нулю, а BoringTun при включённом Jc и 0-0 применяет 50–1000 байт, чтобы не генерировать пустые junk datagrams. Это защитное поведение BoringTun, а не upstream default.


### 4.1 Junk train: `Jc`, `Jmin`, `Jmax`

| Поле | Значение |
|---|---|
| `Jc` | Количество junk datagrams перед handshake |
| `Jmin` | Нижняя граница размера junk datagram, байты |
| `Jmax` | Верхняя граница размера; в фактическом Go-коде **не включается** |
| Направление | Отправитель handshake; получателю не требуется знать J-параметры |
| Default | `Jc=0` — выключено |

Upstream 3.1 вычисляет размер как `Jmin + fastrandn(Jmax - Jmin)`. Поэтому при `Jmin < Jmax` возможны размеры `Jmin … Jmax-1`. При равных границах получается фиксированный размер. Это отличается от `UintRange` для H/CPA/timers, где обе границы включены.

В публичной таблице параметров Amnezia сейчас указаны uint16 для `Jc/Jmin/Jmax`, но pinned Go UAPI parser принимает 32-битные значения. Это расхождение документации и конкретной реализации; при межклиентской совместимости нельзя полагаться только на тип из веб-таблицы. В upstream 3.1 также отсутствуют необходимые проверки взаимного порядка и безопасного верхнего предела. При `Jmin > Jmax` беззнаковое вычитание может превратиться в огромный диапазон и привести к гигантским аллокациям/OOM. См. [upstream issue #189](https://github.com/amnezia-vpn/amneziawg-go/issues/189).

**Ограничения BoringTun (намеренно строже upstream):**

- `Jc` не более 128 пакетов за один handshake.
- `Jmin/Jmax` не более 1280 байт.
- `Jmin > Jmax` отклоняется при конфигурации, а не во время следующего handshake.
- `Jmin=0, Jmax=0` при `Jc>0` означает безопасные defaults 50…1000, а не нулевые пакеты.
- Для пользовательского диапазона `Jmin` должен быть положительным.
- Равные `Jmin=Jmax` поддерживаются как фиксированный размер.
- Размеры ограничены для снижения риска фрагментации и ограничения расхода памяти; 1280 байт всё ещё может фрагментироваться на маршрутах с малым MTU.

### 4.2 Префиксы: `S1-S4`

| Поле | Применение | База |
|---|---|---:|
| `S1` | Handshake Initiation | 148 |
| `S2` | Handshake Response | 92 |
| `S3` | Cookie Reply | 64 |
| `S4` | Transport Data | 32 + payload |

- Префикс добавляется **перед** WG-сообщением; приёмник удаляет ровно настроенное число байт.
- Значения S должны совпадать на обеих сторонах; несовпадение сдвигает type tag и остальные поля.
- При Header Protection каждый S должен быть не меньше 12 байт: первые 12 байт префикса служат nonce ChaCha20.
- Значение 0 отключает соответствующий префикс.
- BoringTun ограничивает не только `uint16`, но и полный базовый размер UDP-датаграммы.

### 4.3 Type ranges: `H1-H4`

| Поле | Тип пакета |
|---|---|
| `H1` | Init |
| `H2` | Response |
| `H3` | Cookie Reply |
| `H4` | Transport Data |

- Формат: одиночное значение или диапазон `MIN-MAX`.
- Type tag — 32-битное little-endian число.
- Диапазон включительный с обеих сторон.
- Отправитель выбирает значение из своего диапазона; получатель принимает любое значение из настроенного диапазона.
- Все четыре диапазона должны быть попарно непересекающимися. BoringTun проверяет пересечения.
- Стандартные значения WireGuard: `H1=1`, `H2=2`, `H3=3`, `H4=4`.
- Значения и диапазоны должны совпадать на обоих концах. Совпадение конкретного случайного выбора не требуется — требуется одинаковый допустимый диапазон.

При включённом Header Protection официальная документация рекомендует оставить стандартные H1-H4: type field будет скрыт ChaCha20. Однако pinned Go source всё равно выбирает type tag из соответствующего H-range, записывает его в заголовок и затем шифрует ChaCha20; receive path расшифровывает его и классифицирует по тому же H-range. Следовательно, H1-H4 не становятся игнорируемыми при HP: диапазоны должны оставаться совместимыми на обоих концах. Стандартные singleton-значения 1/2/3/4 просто отключают дополнительную рандомизацию type tag, сохраняя HP. BoringTun повторяет source behavior.

### 4.4 CPS / `I1-I5`

Каждый `I1…I5` — самостоятельная UDP-датаграмма, описанная последовательностью тегов. Настройка нужна отправителю; получатель не обязан иметь зеркальную конфигурацию. При отправке handshake цепочка передаётся по порядку I1…I5, затем junk train, затем Init. Публичная документация описывает типичную отправку примерно раз в 120 секунд; в Go-коде цепочка отправляется при каждом вызове отправки Handshake Initiation, поэтому фактическая частота зависит от rekey/retry событий и timer ranges, а не от отдельного CPS-таймера.

| Тег | Формат | Действие при отправке |
|---|---|---|
| `<b HEX>` | Статические байты, hex | Копирует указанные байты |
| `<t>` | Без аргумента | 32-битный Unix timestamp, big-endian |
| `<r N>` | N | N случайных байт |
| `<rc N>` | N | N случайных ASCII-букв `[A-Za-z]` |
| `<rd N>` | N | N случайных цифр `[0-9]` |
| `<d>` | Без аргумента | Копирует source buffer |
| `<ds>` | Без аргумента | Base64 Raw StdEncoding source buffer |
| `<dz N>` | N | Записывает длину source buffer в N big-endian байт |

В I1-I5 upstream вызывает `Obfuscate(buf, nil)`, то есть source buffer пустой. Поэтому `<d>` и `<ds>` добавляют 0 байт, а `<dz N>` записывает N байт нулевой длины.

Публичная таблица описывает `<t>` как уникальный timestamp внутри sequence, но Go builder просто записывает `time.Now().Unix()` в 32-bit поле для каждого пакета. При отправке I-пакетов в пределах одной секунды значения могут совпасть; монотонного sequence counter в этом теге нет. BoringTun повторяет source semantics.

**Лимиты и различия:**

- Публичная документация указывает N ≤ 1000 для `r/rc/rd`, однако upstream Go tag builders в `v3.1.20260828` не обеспечивают этот предел и не отклоняют отрицательные значения. Отрицательные N могут привести к panic при следующей отправке handshake; см. [issue #189](https://github.com/amnezia-vpn/amneziawg-go/issues/189).
- BoringTun отвергает отрицательные длины, применяет документированный предел 1000 байт отдельно к `r/rc/rd`, проверяет суммарную длину цепочки и ограничивает итоговую UDP-датаграмму 65 507 байтами. Это сознательно строже Go tag builder, но соответствует публичному контракту CPS.
- BoringTun поддерживает upstream-теги `d/ds/dz`.
- Пустое I-поле или значение без тегов очищает соответствующий слот.
- CPS-датаграммы не участвуют в Noise handshake и не аутентифицируют peer.

### 4.5 Header Protection: `HeaderProtectionKey`

- Ключ — ровно 32 байта, обычно 64 hex-символа; нулевой ключ отключает защиту.
- Ключ должен совпадать на обеих сторонах.
- Nonce ChaCha20 — первые 12 байт соответствующего S-префикса.
- Для Init/Response/Cookie Reply шифруется всё фиксированное WG-сообщение после S-префикса.
- Для Transport Data шифруются только первые 16 байт после S4: type, receiver index и counter. AEAD ciphertext и tag не меняются.
- Header Protection — keyed obfuscation заголовка, а не дополнительная аутентификация. Handshake по-прежнему защищён MAC1/MAC2, transport — ChaCha20-Poly1305.

**Nonce invariant:** первые 12 байт S-префикса должны быть свежими случайными байтами для каждого исходящего пакета. Нельзя заменять их фиксированным protocol-shaped шаблоном: первые байты SIP method line или STUN magic cookie повторяются, а повтор nonce при одном ключе повторно использует ChaCha20 keystream. В BoringTun при включённом HP S-префикс заполняется случайными байтами даже если локально включена имитация DNS/QUIC/SIP/STUN. Отдельные pre-handshake imitation datagrams остаются независимыми.

### 4.6 Content Padding: `ContentPaddingAddition`

- Формат UAPI: одиночное значение или включительный диапазон `MIN-MAX`.
- Публичная таблица Amnezia указывает `range<uint16>`, но pinned Go UAPI parser использует 32-битный `UintRange`. Для BoringTun и совместимости с другими реализациями ориентироваться нужно на фактические ограничения конкретного parser, а не только на тип в веб-документации.
- Padding — нулевые байты, добавляемые к внутреннему IP-пакету **до** AEAD encryption.
- Получатель расшифровывает payload и обрезает его по IPv4 Total Length или IPv6 Payload Length.
- Значение выбирается включительно и ограничивается доступным местом в текущем UDP window.
- **Поведение менялось между поколениями:** в AWG 3.0 (`v3.0.0`) CPA ограничивался внутренним TUN MTU и рассчитывался от длины IP payload; в AWG 3.1 используется per-peer UDP window и размер полного базового transport datagram (`S4 + 32 + payload`). BoringTun по умолчанию реализует 3.1 semantics; для точного legacy-поведения 3.0 доступны `content_padding_mode=mtu` в UAPI и `with_legacy_content_padding(true)` в библиотечном API.
- Публичная документация описывает CPA как padding до внутреннего MTU, что соответствует 3.0; pinned 3.1 Go implementation использует peer UDP window. Это high-water heuristic, а не измеренный path MTU.
- При обмене AWG 3.0 ↔ 3.1 CPA остаётся wire-compatible: padding находится внутри AEAD и удаляется по IP length field, но размерный профиль/предел padding может отличаться. Legacy mode локален и не согласуется по сети; его нужно включать явно согласно целевой реализации.
- `0-0` означает выключено; любой другой диапазон может включать 0 как допустимый результат.
- Настройка локальна для отправителя; значения не обязаны совпадать на peer.
- Padding применяется к transport data, включая пустой handshake-confirmation keepalive.

Если CPA включён, он имеет приоритет над RandomTrailers **для transport**. Если места в UDP window недостаточно, добавляется 0 байт; fallback к RT не выполняется. CPA не ограничивает внешние trailers handshake/cookie — это поведение upstream, обсуждаемое в [issue #185](https://github.com/amnezia-vpn/amneziawg-go/issues/185).

### 4.7 Таймеры

Значения — секунды, одиночное значение или включительный диапазон `MIN-MAX`. Публичная таблица Amnezia указывает `range<uint16>`, тогда как pinned Go UAPI parser разбирает их как 32-битные `UintRange`; это ещё одно расхождение веб-документации и исходников.

**Граничный случай полного uint32 диапазона:** upstream `UintRange.PickOne()` вычисляет ширину как `hi-lo+1` в `uint32`. Для диапазона `0-4294967295` это выражение переполняется в 0; Go `runtime.fastrandn(0)` возвращает 0, поэтому выбирается только нижняя граница. Это касается H, CPA и timer ranges, которые используют общий `UintRange`. BoringTun считает ширину в `u64` и корректно выбирает по всему диапазону. Это намеренное улучшение арифметики, но не побитовая parity с upstream на единственном полном диапазоне; для предсказуемой межреализационной конфигурации не задавайте весь диапазон uint32 целиком.

| Поле | WireGuard default | Роль |
|---|---:|---|
| `RekeyAfterTime` | 120 с | Возраст ключа до нового handshake |
| `RekeyTimeout` | 5 с | Минимальный интервал повторной отправки handshake и retry timeout |
| `RejectAfterTime` | 180 с | Срок жизни ключей/граница отказа от старого keypair |
| `KeepaliveTimeout` | 10 с | Таймер keepalive после активности data |
| `MaxHandshakeAttempts` | 18 | Число попыток в цикле повторного handshake |

`MaxHandshakeAttempts=18` выбирается один раз на новый handshake cycle и после успешного handshake. Retry не должен каждый раз выбирать новый бюджет.

Upstream формулы:

- `newHandshakeTimeout = KeepaliveTimeout.Hi + RekeyTimeout.PickOne()`.
- Receive-side key refresh: `max(0, RejectAfterTime.PickOne() - KeepaliveTimeout.Lo - RekeyTimeout.Lo)`.
- `keychainExpireTime = RejectAfterTime.Hi`.
- `rekeyMinTimeout = RekeyTimeout.Lo`.
- Для handshake retransmit и нового handshake добавляется jitter 0…333 мс.
- Диапазоны выбираются в соответствующих точках жизненного цикла; нельзя заменить их одной общей случайной задержкой.
- `0-0` означает «параметр не задан, использовать WireGuard default», а не таймер нулевой длины. Диапазон `0-1` уже задан и может выбрать 0.
- `persistent_keepalive_interval` — отдельный per-peer диапазон секунд (uint32); `0-0` отключает PersistentKeepalive. При переходе из disabled в enabled первый keepalive планируется немедленно, затем интервал заново выбирается после authenticated traversal.

Таймерные ranges задаются на интерфейсе и применяются к его peer; фактические timer states независимы для каждого peer. Значения не согласуются с другой стороной. Ошибочная комбинация может вызвать слишком ранний rekey, преждевременное удаление ключей или частые retry.

### 4.8 RandomTrailers

- Выключено по умолчанию.
- Для Init/Response/Cookie Reply добавляет случайные байты **после** фиксированного WG-сообщения.
- Для Transport Data добавляет нулевые байты внутрь AEAD plaintext.
- Длина внешнего trailer выбирается по `fastrandn(udpWindow - packetSize)`; верхняя граница свободного места не включается. Если свободного места нет, trailer равен 0.
- Upstream UDP window для peer начинается с 500 байт и увеличивается до high-water mark базовых исходящих transport datagrams до padding/trailer. BoringTun обновляет его по исходящему пакету и сбрасывает при смене endpoint. Окно нельзя обучать по входящему padded datagram или уже добавленному trailer.
- Это high-water heuristic, а не Path MTU Discovery: если крупный базовый datagram ранее прошёл, padding меньших пакетов до такого размера всё ещё может фрагментироваться на маршруте с меньшим MTU.
- Cookie Reply использует device-level `DefaultUdpWindow=500`, а не per-peer high-water mark.
- Для transport CPA имеет приоритет, если задан; для handshake/cookie RT остаётся независим.

**Критичная неоднозначность классификации (upstream issue #186):** при `RandomTrailers=true` upstream сначала пробует Init, Response и Cookie branches, разрешая пакеты длиннее соответствующего фиксированного размера, и только затем пробует Transport. Для каждого handshake branch читается type tag на своём offset `S1/S2/S3`. Если эти offsets не совпадают с `S4`, в transport packet там оказываются случайные байты S4-prefix или ciphertext. Они могут случайно попасть в широкий диапазон `H1/H2/H3`; пакет ошибочно уходит в handshake path и затем теряется на проверке MAC1. Для независимых равномерных 32-битных значений вероятность ложной классификации на один transport packet приблизительно:
`1 - (1 - W1/2^32) * (1 - W2/2^32) * (1 - W3/2^32)`,
где `Wi = Hi_max - Hi_min + 1`. Поэтому широкие H1-H3 усугубляют риск, а ширина H4 в этой конкретной ошибке не участвует.

Официальная документация рекомендует одинаковые S1-S4. BoringTun превращает рекомендацию в проверяемое ограничение: при `RandomTrailers=true` конфигурация с разными S1-S4 отклоняется. При равных S и непересекающихся H-диапазонах все четыре ветви смотрят на один type offset: реальный H4 не попадает в H1-H3. Это закрывает описанный false-positive path для корректной конфигурации; upstream UAPI пока принимает разные S и широкие H1-H3 без такой защиты.

### 4.9 DisableCookies

- Выключено по умолчанию.
- При `true` receiver по-прежнему проверяет MAC1, но полностью пропускает under-load cookie gate: MAC2 challenge и связанный handshake rate limiting.
- Входящие Cookie Reply продолжают приниматься; это не «игнорировать cookie packets».
- Параметр локален: endpoints могут иметь разные значения.
- Это компромисс между поведением при active probing и DoS-защитой. На публичном endpoint включение повышает риск CPU-exhaustion от потока handshake.

**Историческая оговорка:** в `v3.1.20260812` under-load gate ещё вызывался независимо от DisableCookies; исправление появилось к `v3.1.20260828` (commit `b5928ef`). BoringTun ориентируется на исправленное поведение.

## 5. Матрица совместимости поколений

Это матрица возможностей, а не гарантия для любого конфигурационного файла.

| Клиент ↔ сервер | Условия |
|---|---|
| WireGuard ↔ AWG | Совместимы при стандартном wire format: S1-S4=0, H1-H4=1/2/3/4, HP/RT выключены. I/J cover packets сами по себе не требуют поддержки, но старый config parser может отвергнуть неизвестные ключи. |
| AWG 1.0 ↔ AWG 1.5 | Базовые S/H/J механизмы совместимы при одинаковых значениях. Протокол-маскировка 1.5 не меняет Noise handshake, но конфигурационный parser старого клиента может отвергнуть новые ключи. |
| AWG 1.x/1.5 ↔ AWG 2.x | Нужны общие S/H значения; S3/S4 должны оставаться нулевыми, если старый peer не поддерживает Cookie/Data prefixes. I1-I5/CPS — sender-side cover datagrams; старый receiver обычно их игнорирует, но parser старого клиента может отвергнуть новые ключи. |
| AWG 2.x ↔ AWG 3.0 | Совместимы при выключенном HP и одинаковых S/H. CPA и таймеры локальны. При включённом HP обе стороны должны использовать один ключ и S1-S4≥12. |
| AWG 3.0 ↔ AWG 3.1 | Базовый wire format совместим при одинаковых S/H и выключенном RT. CPA остаётся совместимым по расшифровке, но в 3.0 он ограничен TUN MTU, а в 3.1 — UDP window, поэтому packet-size profile различается. Для внешних RT принимающая сторона должна разрешать trailers; BoringTun требует одинаковые S1-S4. DisableCookies — локальная политика. |
| AWG 3.1 ↔ старые поколения | Если включены HP/RT или изменены S3/S4/H ranges, старый peer не сможет корректно разобрать пакеты. Возврат к общим S/H и отключение новых расширений может вернуть базовую совместимость. |

### Что должно совпадать

| Настройка | Совпадение | Причина |
|---|---|---|
| S1-S4 | Да | Точные offsets WG-сообщений |
| H1-H4 | Да | Допустимые type tags |
| HeaderProtectionKey | Да | Ключ ChaCha20 |
| RandomTrailers | Receiver каждого направления должен разрешать trailers; для двустороннего туннеля включают на обоих концах | Иначе handshake/cookie datagrams с ненулевым trailer будут отвергнуты |

### Что не требует зеркального значения

| Настройка | Где действует |
|---|---|
| Jc/Jmin/Jmax | На интерфейсе-отправителе; burst отправляет peer, который инициирует handshake |
| I1-I5 | На интерфейсе-отправителе; CPS packets отправляет peer, который инициирует handshake |
| ContentPaddingAddition | На интерфейсе-отправителе; применяется к исходящему transport каждого peer |
| Таймеры | Локальная interface-wide timer policy; состояния отдельных peer независимы |
| DisableCookies | Локальная interface-wide under-load policy принимающей стороны |
| PersistentKeepalive | Локальная настройка peer |

## 6. Пример согласованного профиля AWG 3.1

Ниже — иллюстративный профиль, который включает HP, CPA и RT, но сохраняет простые H tags. Один и тот же набор S/H/HP key и RT должен быть установлен на обоих интерфейсах.

```ini
# Common wire framing — одинаково на обеих сторонах
s1=64
s2=64
s3=64
s4=64
h1=1
h2=2
h3=3
h4=4
header_protection_key=<64 hex characters, same key on both ends>
random_trailers=true

# Sender-side obfuscation — локально на каждом интерфейсе
jc=4
jmin=50
jmax=1000
content_padding_addition=16-64

# Local DoS policy — оценить риск перед включением
disable_cookies=false

# Timer ranges — локальные defaults, не negotiation
rekey_after_time=120
rekey_timeout=5
reject_after_time=180
keepalive_timeout=10
max_handshake_attempts=18
```

Это не универсальный «лучший» профиль: J/CPS и padding меняют трафик, расход CPU/сети и риск фрагментации. Для диагностики сначала следует проверить обычный WG/AWG профиль без HP/RT, затем включать механизмы по одному. Если `RandomTrailers=true`, BoringTun требует одинаковые S1-S4. Значение `jmax=1000` даёт размер до 999 байт, поскольку верхняя граница исключительная. `persistent_keepalive_interval` задаётся отдельно для каждого peer, а не в общем device profile.

## 7. Риски и upstream edge cases

1. **RandomTrailers + разные S + широкие H1-H3 — issue #186.** Ложная handshake classification может молча терять transport packets; риск растёт с суммарной шириной H1-H3. BoringTun требует одинаковые S1-S4 и проверяет непересечение H ranges.
2. **ContentPaddingAddition не ограничивает handshake trailers — issue #185.** CPA влияет только на transport. Даже при CPA handshake Response и Cookie Reply по-прежнему могут получить внешний RandomTrailers, ограниченный UDP window, а не CPA range и не TUN MTU. Оператор не должен считать CPA гарантией MTU-safe для handshake.
3. **Небезопасные J/CPS размеры — issue #189.** Upstream 3.1 не проверяет все cross-field combinations Jmin/Jmax и отрицательные длины CPS тегов. BoringTun валидирует их до отправки.
4. **Cookie Reply amplification.** Upstream не ограничивает размер Cookie Reply относительно вызвавшей handshake datagram. S3 и RT могут увеличить ответ; BoringTun сохраняет это wire behavior. На публичном endpoint требуется сетевой контроль и оценка reflection amplification risk.
5. **Header Protection — не AEAD.** Он скрывает служебные поля, но не заменяет Noise MAC и transport AEAD. Повтор nonce при одном HP key недопустим.

## 8. BoringTun-specific возможности и safety policy

| Поле/функция | Статус |
|---|---|
| `Jd` | Локальная задержка между pre-handshake junk datagrams; максимум 200 мс |
| `Ip`, `Id`, `Ib` | Локальная имитация DNS/QUIC/SIP/STUN, домена и browser profile; не часть AWG version negotiation. При включённом imitation protocol генератор размеров использует protocol-specific шаблон вместо обычного случайного диапазона Jmin/Jmax. |
| `suppress_pre_handshake` / responder mode | Локальное подавление исходящего I/J/imitation burst |
| Protocol probe replies | Локальный ответчик на распознанные probe datagrams; не стандарт AWG |
| Jc≤128, Jmax≤1280 | Ограничения памяти/фрагментации BoringTun |
| RT требует S1=S2=S3=S4 | Safety validation для известной неоднозначности upstream classifier |
| HP + protocol imitation | S-prefix принудительно случайный для сохранения уникальности nonce |

Имитация в S-prefix не должна подменять nonce Header Protection. При включённом HP BoringTun заполняет S-prefix случайными байтами; самостоятельные pre-handshake imitation datagrams остаются отдельным механизмом.

## 9. Стандартный WireGuard padding: parity в текущей ветке

В upstream AWG 3.0/3.1, когда ContentPaddingAddition не задан и RandomTrailers выключен, transport encryption fallback вызывает calculatePaddingSize(packetSize, tun.mtu): plaintext IP-пакет дополняется нулевыми байтами до кратного 16 байтам размера с ограничением по MTU. При включённом CPA используется CPA; при RT — RandomTrailers.

В текущей ветке BoringTun это поведение реализовано в AmneziaConfig::calculate_wg_padding_size и вызывается из transport_padding_size. Tunn хранит MTU: standalone API использует 1420 байт по умолчанию, Device передаёт фактический MTU через set_mtu. Алгоритм повторяет upstream special case для MTU=0, modulo для пакетов больше MTU и ограничение результата MTU. Тест wireguard_padding_matches_upstream_mtu_algorithm фиксирует граничные случаи.

Это изменение касается распределения размеров, а не wire compatibility: padding находится внутри AEAD plaintext и удаляется по длине IP-пакета. Важно прогнать обычный WG/AWG baseline и interop для IPv4/IPv6, а также убедиться, что выходной буфер рассчитан на добавляемый padding.

## 10. Соответствие исходникам BoringTun

| Область | Файл |
|---|---|
| S/H, Header Protection, RandomTrailers, CPA и limits | `boringtun/src/noise/amnezia.rs` |
| I1-I5/CPS grammar and emission | `boringtun/src/noise/signature.rs` |
| Noise parsing and HP flow | `boringtun/src/noise/handshake.rs`, `boringtun/src/noise/mod.rs` |
| Timer formulas, ranges, jitter, retry budgets | `boringtun/src/noise/timers.rs` |
| MAC1/MAC2, cookie generation, DisableCookies | `boringtun/src/noise/rate_limiter.rs` |
| Device ingress/demux and UAPI | `boringtun/src/device/mod.rs` |

### Инварианты, которые должны оставаться покрыты тестами

1. S1-S4 удаляются до обычного WG parsing; offsets MAC/AEAD не сдвигаются.
2. При HP каждый S≥12; nonce — первые 12 случайных байт S-prefix.
3. При HP plaintext fallback запрещён.
4. H1-H4 не пересекаются и читаются как little-endian u32.
5. При RT одинаковые S1-S4 обязательны в BoringTun; fixed handshake envelopes принимают trailer только в RT режиме.
6. UDP window обновляется по максимальному **исходящему базовому** transport datagram до padding/trailer, а не по входящему padded datagram.
7. CPA/RT применяются к transport plaintext до AEAD; handshake-confirmation keepalive проходит тот же transport path.
8. CPA имеет приоритет над RT для transport; handshake/cookie RT независим.
9. Jmax — exclusive upper bound; Jmin>Jmax отклоняется; Jc/J sizes ограничены.
10. CPS отрицательные длины отклоняются, итоговая датаграмма не превышает UDP payload limit.
11. Cookie Reply не сбрасывает обычные authenticated traversal timers; DisableCookies оставляет MAC1, но пропускает under-load MAC2/rate-limit gate.
12. Timer ranges inclusive; 0-0 означает default; retry budget выбирается один раз на handshake cycle.

## 11. Проверенные источники

### Реальные interop-проверки

CI использует два независимых официальных Go-эталона: `amneziawg-go` commit `b5928efb6ca19f0153958460c3d141f04abc5c2e` (v3.1.20260828) и tag `v3.0.0`. Быстрый набор проверяет 16 направленных сценариев с v3.1 и дополнительно 14 направленных сценариев с v3.0.0; последний набор исключает UAPI-поля, появившиеся только в 3.1. Полная матрица `--full` добавляет к v3.1-набору 44 сценария и длинные lifecycle/rekey проверки. CPA для профиля AWG 3.0 выбирается только на BoringTun через локальный `content_padding_mode=mtu`; официальный Go 3.0.0 использует собственную реализацию MTU-bounded CPA без неизвестного ему UAPI ключа.

- [Официальная документация AmneziaWG](https://docs.amnezia.org/documentation/amnezia-wg/)
- [amneziawg-go v0.2.19](https://github.com/amnezia-vpn/amneziawg-go/tree/v0.2.19)
- [amneziawg-go v3.0.0](https://github.com/amnezia-vpn/amneziawg-go/tree/v3.0.0)
- [amneziawg-go v3.1.20260812](https://github.com/amnezia-vpn/amneziawg-go/tree/v3.1.20260812)
- [amneziawg-go v3.1.20260828](https://github.com/amnezia-vpn/amneziawg-go/tree/v3.1.20260828)
- [noise-types.go](https://github.com/amnezia-vpn/amneziawg-go/blob/v3.1.20260828/device/noise-types.go) — размеры ключей, UintRange, HeaderCipherNonceSize.
- [uapi.go](https://github.com/amnezia-vpn/amneziawg-go/blob/v3.1.20260828/device/uapi.go) — реальные типы и проверки UAPI.
- [send.go AWG 3.0.0](https://github.com/amnezia-vpn/amneziawg-go/blob/v3.0.0/device/send.go) — MTU-bounded CPA and legacy transport padding.
- [send.go AWG 3.1](https://github.com/amnezia-vpn/amneziawg-go/blob/v3.1.20260828/device/send.go) — S-prefix, HP, RT, peer UDP window, CPA, handshake keepalive.
- [receive.go](https://github.com/amnezia-vpn/amneziawg-go/blob/v3.1.20260828/device/receive.go) — receive classifier, cookie policy, handshake lifecycle.
- [timers.go](https://github.com/amnezia-vpn/amneziawg-go/blob/v3.1.20260828/device/timers.go) — timer defaults and formulas.
- [obf.go](https://github.com/amnezia-vpn/amneziawg-go/blob/v3.1.20260828/device/obf.go) и `obf_*.go` — CPS grammar.
- [Issue #185](https://github.com/amnezia-vpn/amneziawg-go/issues/185), [Issue #186](https://github.com/amnezia-vpn/amneziawg-go/issues/186), [Issue #189](https://github.com/amnezia-vpn/amneziawg-go/issues/189).

> Совместимость оценивается по точному набору параметров и конкретному upstream revision, а не только по надписи «AWG 3.1». Любое изменение wire framing должно сопровождаться двусторонним interop-тестом BoringTun ↔ официальный amneziawg-go в обеих ролях.
