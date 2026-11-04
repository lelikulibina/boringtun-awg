# AmneziaWG: версии протокола, параметры, лимиты и совместимость

> Срез исследования: 2026-11-04. Основной эталон реализации — `amneziawg-go` tag `v3.1.20260828` (upstream commit `b5928efb6ca19f0153958460c3d141f04abc5c2e`). Для исторического сравнения использованы `v0.2.19`, `v3.0.0`, `v3.1.20260812` и `v3.1.20260828`. Ниже описано фактическое поведение исходников, а не только краткая таблица параметров на сайте.

## 1. Главный принцип совместимости

AmneziaWG не выполняет отдельное согласование версии протокола во время handshake. В пакетах нет поля «AWG 1.5/2.0/3.0/3.1», а стороны не договариваются о параметрах автоматически. В основе остаются сообщения WireGuard Noise IK; AmneziaWG меняет их внешнее представление, обрамление, часть заголовка, размеры, последовательность служебных пакетов и тайминги.

Параметры делятся на три класса:

1. **Общие параметры wire format** — должны совпадать на обеих сторонах: `S1-S4`, `H1-H4`, `HeaderProtectionKey`. `RandomTrailers` также должен быть включён на обоих концах, если отправитель добавляет внешние handshake/cookie trailers.
2. **Локальные параметры отправителя** — не требуют одинаковых значений у получателя: `Jc/Jmin/Jmax`, `I1-I5`, `ContentPaddingAddition`, таймеры.
3. **Локальная политика получателя** — `DisableCookies`. Она меняет реакцию конкретного endpoint под нагрузкой, а не формат обычных пакетов.

«Клиентские» и «серверные» настройки не следует путать с обязательной ролью инициатора. Любая сторона, которая инициирует handshake, может отправить I/J-пакеты. Рекомендация задавать их только на клиенте — операционная практика, а не ограничение Noise.

## 2. История версий

Ниже — история возможностей по публичной документации Amnezia и историческим исходникам. Это **не** поле version negotiation и не гарантия, что любой бинарник с таким номером версии принимает все поздние ключи UAPI.

| Поколение | Существенные механизмы | Практический смысл |
|---|---|---|
| AWG 1.0 | `Jc`, `Jmin`, `Jmax`; `S1/S2`; `H1-H4` с фиксированными значениями | Junk-пакеты перед handshake, префиксы Init/Response и изменение type tags |
| AWG 1.5 | CPS / signature chain `I1-I5`, развитая имитация UDP-протоколов | Несколько самостоятельных датаграмм перед handshake, похожих на DNS/QUIC/другие протоколы |
| AWG 2.0 | `S3/S4`; диапазоны `H1-H4`; расширенное изменение заголовков и размеров | Обфускация Cookie Reply и transport data; type tags выбираются из диапазонов |
| AWG 3.0 | `HeaderProtectionKey`, `ContentPaddingAddition`, диапазоны таймеров | ChaCha20 скрывает незашифрованные поля WireGuard; внутри AEAD добавляется padding; таймеры рандомизируются |
| AWG 3.1 | `RandomTrailers`, `DisableCookies` | Вариативность внешней длины handshake/cookie, padding transport и изменение under-load cookie policy |

Исторические исходники:

- [amneziawg-go v0.2.19](https://github.com/amnezia-vpn/amneziawg-go/tree/v0.2.19) — поколение до 3.x с S3/S4, H-диапазонами и CPS.
- [AWG 3.0.0](https://github.com/amnezia-vpn/amneziawg-go/tree/v3.0.0) — Header Protection, Content Padding и custom timers.
- [AWG 3.1.20260812](https://github.com/amnezia-vpn/amneziawg-go/tree/v3.1.20260812) — ранняя реализация 3.1.
- [AWG 3.1.20260828](https://github.com/amnezia-vpn/amneziawg-go/tree/v3.1.20260828), commit `b5928ef` — исправлен DisableCookies under-load gate.

Важная деталь: уже в `v3.0.0` исходники задают `HeaderCipherNonceSize = 12` и отклоняют S-префиксы короче 12 байт при включённом Header Protection. Встречающееся в старых описаниях требование «более 8 байт» не соответствует проверке в исходниках Go. Реализация должна использовать подтверждённое кодом условие: **каждый S-префикс не короче 12 байт**.

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

`S1-S4` — длины фиксированных префиксов, а не диапазоны. UAPI upstream разбирает их как `uint16` (0…65 535). Фактическая отправка ограничена максимальной UDP payload-датаграммой: 65 507 байт для IPv4. BoringTun заранее проверяет, что базовый пакет с соответствующим S-префиксом помещается в этот предел.

## 4. Параметры и их ограничения

### 4.1 Junk train: `Jc`, `Jmin`, `Jmax`

| Поле | Значение |
|---|---|
| `Jc` | Количество junk datagrams перед handshake |
| `Jmin` | Нижняя граница размера junk datagram, байты |
| `Jmax` | Верхняя граница размера; в фактическом Go-коде **не включается** |
| Направление | Отправитель handshake; получателю не требуется знать J-параметры |
| Default | `Jc=0` — выключено |

Upstream 3.1 вычисляет размер как `Jmin + fastrandn(Jmax - Jmin)`. Поэтому при `Jmin < Jmax` возможны размеры `Jmin … Jmax-1`. При равных границах получается фиксированный размер. Это отличается от `UintRange` для H/CPA/timers, где обе границы включены.

Upstream UAPI хранит `Jc/Jmin/Jmax` как 32-битные значения, но в upstream 3.1 отсутствуют необходимые проверки взаимного порядка и безопасного верхнего предела. При `Jmin > Jmax` беззнаковое вычитание может превратиться в огромный диапазон и привести к гигантским аллокациям/OOM. См. [upstream issue #189](https://github.com/amnezia-vpn/amneziawg-go/issues/189).

**Ограничения BoringTun (намеренно строже upstream):**

- `Jc` не более 128 пакетов за один handshake.
- `Jmin/Jmax` не более 1280 байт.
- `Jmin > Jmax` отклоняется при конфигурации, а не во время следующего handshake.
- `Jmin=0, Jmax=0` при `Jc>0` означает безопасные defaults 50…1000, а не нулевые пакеты.
- Для пользовательского диапазона `Jmin` должен быть положительным.
- Равные `Jmin=Jmax` поддерживаются как фиксированный размер.
- Размеры ограничены, чтобы не провоцировать фрагментацию и неконтролируемый расход памяти.

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

При включённом Header Protection официальная документация рекомендует оставить стандартные H1-H4: type field будет скрыт ChaCha20.

### 4.4 CPS / `I1-I5`

Каждый `I1…I5` — самостоятельная UDP-датаграмма, описанная последовательностью тегов. Настройка нужна отправителю; получатель не обязан иметь зеркальную конфигурацию. При отправке handshake цепочка передаётся по порядку I1…I5, затем junk train, затем Init.

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

**Лимиты и различия:**

- Публичная документация указывает N ≤ 1000 для `r/rc/rd`, однако upstream Go tag builders в `v3.1.20260828` не обеспечивают этот предел и не отклоняют отрицательные значения. Отрицательные N могут привести к panic при следующей отправке handshake; см. [issue #189](https://github.com/amnezia-vpn/amneziawg-go/issues/189).
- BoringTun отвергает отрицательные длины, проверяет суммарную длину цепочки и ограничивает итоговую UDP-датаграмму 65 507 байтами.
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
- Фактический upstream UAPI использует 32-битный `UintRange`; это расходится с некоторыми краткими таблицами на сайте, где указан uint16.
- Padding — нулевые байты, добавляемые к внутреннему IP-пакету **до** AEAD encryption.
- Получатель расшифровывает payload и обрезает его по IPv4 Total Length или IPv6 Payload Length.
- Значение выбирается включительно и ограничивается доступным местом в текущем UDP window.
- `0-0` означает выключено; любой другой диапазон может включать 0 как допустимый результат.
- Настройка локальна для отправителя; значения не обязаны совпадать на peer.
- Padding применяется к transport data, включая пустой handshake-confirmation keepalive.

Если CPA включён, он имеет приоритет над RandomTrailers **для transport**. Если места в UDP window недостаточно, добавляется 0 байт; fallback к RT не выполняется. CPA не ограничивает внешние trailers handshake/cookie — это поведение upstream, обсуждаемое в [issue #185](https://github.com/amnezia-vpn/amneziawg-go/issues/185).

### 4.7 Таймеры

Значения — секунды, одиночное значение или включительный диапазон `MIN-MAX`. Upstream UAPI разбирает их как 32-битные `UintRange`.

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

Таймеры локальны: значения не согласуются с другой стороной. Ошибочная комбинация может вызвать слишком ранний rekey, преждевременное удаление ключей или частые retry.

### 4.8 RandomTrailers

- Выключено по умолчанию.
- Для Init/Response/Cookie Reply добавляет случайные байты **после** фиксированного WG-сообщения.
- Для Transport Data добавляет нулевые байты внутрь AEAD plaintext.
- Длина внешнего trailer выбирается по `fastrandn(udpWindow - packetSize)`; верхняя граница свободного места не включается. Если свободного места нет, trailer равен 0.
- Upstream UDP window начинается с 500 байт и увеличивается до high-water mark базовых исходящих transport datagrams до padding/trailer. Окно нельзя обучать по входящему padded datagram или уже добавленному trailer.
- Для transport CPA имеет приоритет, если задан; для handshake/cookie RT остаётся независим.

**Критичная неоднозначность классификации:** upstream сначала проверяет handshake offsets, а затем transport. При разных S1-S4 длинный transport packet может попасть в handshake branch, где случайные байты на другом offset случайно соответствуют H1/H2/H3. Пакет будет отвергнут по MAC1, хотя его H4 и AEAD корректны. Это подтверждено [upstream issue #186](https://github.com/amnezia-vpn/amneziawg-go/issues/186).

Официальная документация рекомендует одинаковые S1-S4. BoringTun превращает рекомендацию в проверяемое ограничение: при `RandomTrailers=true` конфигурация с разными S1-S4 отклоняется. Upstream UAPI принимает такие значения, но не гарантирует надёжную классификацию. При одинаковых S и непересекающихся H-диапазонах кандидаты смотрят на один и тот же type field.

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
| AWG 1.0 ↔ AWG 1.5 | Базовые S/H/J механизмы совместимы при одинаковых значениях. I1-I5 — дополнительные pre-handshake datagrams; старый receiver обычно просто не использует их. |
| AWG 1.x/1.5 ↔ AWG 2.x | Нужны общие S/H значения; S3/S4 должны оставаться нулевыми, если старый peer не поддерживает Cookie/Data prefixes. Parser старого клиента может отвергнуть новые ключи. |
| AWG 2.x ↔ AWG 3.0 | Совместимы при выключенном HP и одинаковых S/H. CPA и таймеры локальны. При включённом HP обе стороны должны использовать один ключ и S1-S4≥12. |
| AWG 3.0 ↔ AWG 3.1 | Базовый профиль совместим при RT=false и DisableCookies=false. Для внешних RT обе стороны должны включить поддержку; BoringTun требует одинаковые S1-S4. DisableCookies — локальная политика. |
| AWG 3.1 ↔ старые поколения | Если включены HP/RT или изменены S3/S4/H ranges, старый peer не сможет корректно разобрать пакеты. Возврат к общим S/H и отключение новых расширений может вернуть базовую совместимость. |

### Что должно совпадать

| Настройка | Совпадение | Причина |
|---|---|---|
| S1-S4 | Да | Точные offsets WG-сообщений |
| H1-H4 | Да | Допустимые type tags |
| HeaderProtectionKey | Да | Ключ ChaCha20 |
| RandomTrailers | Да, если sender добавляет handshake/cookie trailers | Receiver должен разрешать variable-length fixed handshake envelopes |

### Что не требует зеркального значения

| Настройка | Где действует |
|---|---|
| Jc/Jmin/Jmax | На стороне, отправляющей junk train |
| I1-I5 | На стороне, отправляющей CPS packets |
| ContentPaddingAddition | На стороне, отправляющей transport data |
| Таймеры | Локальная timer policy |
| DisableCookies | Локальная under-load policy принимающей стороны |
| PersistentKeepalive | Локальная настройка peer |

## 6. Риски и upstream edge cases

1. **RandomTrailers + разные S — issue #186.** Разные offsets могут приводить к ложной handshake classification и потере transport. BoringTun требует одинаковые S1-S4.
2. **ContentPaddingAddition не ограничивает handshake trailers — issue #185.** CPA влияет на transport; handshake и Cookie Reply всё ещё могут получить внешний RandomTrailers.
3. **Небезопасные J/CPS размеры — issue #189.** Upstream 3.1 не проверяет все cross-field combinations Jmin/Jmax и отрицательные длины CPS тегов. BoringTun валидирует их до отправки.
4. **Cookie Reply amplification.** Upstream не ограничивает размер Cookie Reply относительно вызвавшей handshake datagram. S3 и RT могут увеличить ответ; BoringTun сохраняет это wire behavior. На публичном endpoint требуется сетевой контроль и оценка reflection amplification risk.
5. **Header Protection — не AEAD.** Он скрывает служебные поля, но не заменяет Noise MAC и transport AEAD. Повтор nonce при одном HP key недопустим.

## 7. BoringTun-specific возможности и safety policy

| Поле/функция | Статус |
|---|---|
| `Jd` | Локальная задержка между pre-handshake junk datagrams; максимум 200 мс |
| `Ip`, `Id`, `Ib` | Локальная имитация DNS/QUIC/SIP/STUN, домена и browser profile; не часть AWG version negotiation |
| `suppress_pre_handshake` / responder mode | Локальное подавление исходящего I/J/imitation burst |
| Protocol probe replies | Локальный ответчик на распознанные probe datagrams; не стандарт AWG |
| Jc≤128, Jmax≤1280 | Ограничения памяти/фрагментации BoringTun |
| RT требует S1=S2=S3=S4 | Safety validation для известной неоднозначности upstream classifier |
| HP + protocol imitation | S-prefix принудительно случайный для сохранения уникальности nonce |

Имитация в S-prefix не должна подменять nonce Header Protection. При включённом HP BoringTun заполняет S-prefix случайными байтами; самостоятельные pre-handshake imitation datagrams остаются отдельным механизмом.

## 8. Соответствие исходникам BoringTun

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

## 9. Проверенные источники

- [Официальная документация AmneziaWG](https://docs.amnezia.org/documentation/amnezia-wg/)
- [amneziawg-go v0.2.19](https://github.com/amnezia-vpn/amneziawg-go/tree/v0.2.19)
- [amneziawg-go v3.0.0](https://github.com/amnezia-vpn/amneziawg-go/tree/v3.0.0)
- [amneziawg-go v3.1.20260812](https://github.com/amnezia-vpn/amneziawg-go/tree/v3.1.20260812)
- [amneziawg-go v3.1.20260828](https://github.com/amnezia-vpn/amneziawg-go/tree/v3.1.20260828)
- [noise-types.go](https://github.com/amnezia-vpn/amneziawg-go/blob/v3.1.20260828/device/noise-types.go) — размеры ключей, UintRange, HeaderCipherNonceSize.
- [uapi.go](https://github.com/amnezia-vpn/amneziawg-go/blob/v3.1.20260828/device/uapi.go) — реальные типы и проверки UAPI.
- [send.go](https://github.com/amnezia-vpn/amneziawg-go/blob/v3.1.20260828/device/send.go) — S-prefix, HP, RT, CPA, UDP window, handshake keepalive.
- [receive.go](https://github.com/amnezia-vpn/amneziawg-go/blob/v3.1.20260828/device/receive.go) — receive classifier, cookie policy, handshake lifecycle.
- [timers.go](https://github.com/amnezia-vpn/amneziawg-go/blob/v3.1.20260828/device/timers.go) — timer defaults and formulas.
- [obf.go](https://github.com/amnezia-vpn/amneziawg-go/blob/v3.1.20260828/device/obf.go) и `obf_*.go` — CPS grammar.
- [Issue #185](https://github.com/amnezia-vpn/amneziawg-go/issues/185), [Issue #186](https://github.com/amnezia-vpn/amneziawg-go/issues/186), [Issue #189](https://github.com/amnezia-vpn/amneziawg-go/issues/189).

> Совместимость оценивается по точному набору параметров и конкретному upstream revision, а не только по надписи «AWG 3.1». Любое изменение wire framing должно сопровождаться двусторонним interop-тестом BoringTun ↔ официальный amneziawg-go в обеих ролях.
