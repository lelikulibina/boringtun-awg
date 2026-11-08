# nftables и сетевая фильтрация vpn-relay

> Срез реализации на ветке `feature/boringtun-router-daemon`, commit
> `d72feae4ac1d6a31f309df3892949857c38d8833`.
>
> Документ описывает фактическое поведение кода на указанном commit. Это
> техническая инвентаризация, а не утверждение, что текущая политика уже
> эквивалентна любой конкретной firewall-конфигурации.

## 1. Область ответственности

Сетевая политика vpn-relay состоит из нескольких взаимосвязанных частей:

1. **nftables** — классификация пакетов, выбор разрешённого направления
   транзита, блокировка неразрешённого транзита, conntrack marks и NAT.
2. **iproute2 policy routing** — выбор egress TUN по packet mark.
3. **socket fwmark** — вывод внешнего зашифрованного UDP-трафика WG/AWG через
   основную таблицу маршрутизации, чтобы не отправлять транспортный пакет
   обратно в туннель.
4. **IPv6 gating** — запрет IPv6 на интерфейсах, для которых IPv6 отключён.
5. **lifecycle/ownership** — установка, проверка владения, откат и удаление
   созданной таблицы и policy routes.

Основная реализация находится в:

- `vpn-relay/src/routing.rs` — чистая генерация `RoutingPlan`, nftables script
  и команд iproute2;
- `vpn-relay/src/linux.rs` — исполнение команд, защита чужих ресурсов и
  удаление собственных ресурсов;
- `vpn-relay/src/runtime.rs` — порядок запуска, откат, выключение и
  восстановление sysctl;
- `vpn-relay/src/config.rs` — модель и валидация правил маршрутизации.

Таблица nftables имеет family `inet`, а имя задаётся параметром
`[daemon].nft_table` (в примере — `vpn_relay`).

## 2. Модель конфигурации

Направление задаётся не ролью интерфейса, а каждым отдельным правилом:

```toml
[[routing.rules]]
priority = 100
ingress = "wg-server"
source = "10.10.0.0/24"
destination = "0.0.0.0/0"
egress = "awg-primary"
nat = "masquerade"
```

Поля правила:

- `priority` — порядок выбора правила в пределах одного ingress;
- `ingress` — TUN, с которого пакет входит в маршрутизатор;
- `egress` — TUN, через который пакет должен выйти;
- `source` — необязательный список IPv4/IPv6 CIDR источника;
- `destination` — необязательный список IPv4/IPv6 CIDR назначения;
- `nat` — `none` (по умолчанию) или `masquerade`.

Если source и destination не заданы, правило соответствует всему трафику,
пришедшему через указанный ingress. Если задан только один селектор, второй
не ограничивает совпадение.

Валидация конфигурации проверяет, в частности:

- ingress и egress существуют;
- ingress и egress не совпадают;
- при заданных source и destination у них есть хотя бы одно общее семейство
  адресов;
- списки CIDR не пусты и содержат корректные префиксы;
- приоритеты не дублируются в пределах одного ingress;
- NAT содержит только поддерживаемое значение.

Один интерфейс может быть ingress в одних правилах и egress в других.
Наличие или отсутствие peer Endpoint не определяет направление.

### Приоритет и пересечение правил

При построении плана правила сортируются по имени ingress, затем по
возрастанию priority. В prerouting для нового соединения первое совпавшее
правило выставляет mark и выполняет `return`. Поэтому для одного ingress
порядок имеет семантическое значение: более приоритетное правило может
перехватить трафик, который совпал бы и с последующим.

Приоритеты разных ingress независимы.

## 3. Какие объекты nftables создаются

Генератор создаёт в выбранной таблице:

- set `managed_interfaces` типа `ifname` — все интерфейсы, которыми
  управляет vpn-relay;
- chain `prerouting` — hook `prerouting`, priority `mangle`, policy
  `accept`;
- chain `forward` — hook `forward`, priority `filter`, policy `accept`;
- chain `postrouting` — hook `postrouting`, priority `srcnat`, policy
  `accept`;
- при наличии IPv6-disabled интерфейсов — set
  `ipv6_blocked_interfaces` и дополнительную chain `output`.

Таблица создаётся с table-level comment:

```nft
add table inet vpn_relay { comment "managed by vpn-relay"; }
```

Комментарий используется не просто как описание: это маркер владения,
который проверяет linux backend перед заменой или удалением таблицы.

Все интерфейсы из конфигурации включаются в `managed_interfaces`, а не
только интерфейсы, упомянутые как ingress или egress. Это важно для
fail-closed поведения: случайный транзит через любой управляемый TUN
блокируется, если для него нет подходящего разрешающего routing rule.

## 4. Путь пакета: классификация и метки

### 4.1. Новый пакет, входящий через управляемый TUN

В prerouting выполняется следующая логика:

1. Для пакетов с `iifname @managed_interfaces` очищается packet mark:
   `meta mark set 0`.
2. Для нового соединения (`ct state new`) перебираются routing rules,
   отсортированные по ingress и priority.
3. Правило проверяет точный ingress и, если заданы, source/destination CIDR
   соответствующего семейства IP.
4. При совпадении:
   - `meta mark` устанавливается в routing mark выбранного egress;
   - это значение сохраняется в `ct mark`;
   - выполняется `return` из prerouting chain.

Если ни одно правило не совпало, mark остаётся нулевым. Само по себе это ещё
не разрешает пакет: в forward chain он попадёт под завершающий drop для
управляемого ingress.

### 4.2. Последующие пакеты исходного направления

Для уже установленного соединения (`established,related`) с направлением
conntrack `original` prerouting проверяет `ct mark` по известным egress
marks. При совпадении сохранённая метка восстанавливается в `meta mark`,
после чего выполняется `return`.

Это позволяет всем пакетам одного потока использовать тот же egress,
который был выбран для первого пакета. Правило не пересчитывается заново
по текущему набору routing rules.

### 4.3. Ответные пакеты

Для `established,related` с `ct direction reply`, входящих через
управляемый интерфейс, packet mark устанавливается в ноль, затем выполняется
`return`.

Это принципиально: ответ должен маршрутизироваться к исходному ingress
через main routing table, а не через policy table исходящего направления.

### 4.4. Связь с ip rule

Routing mark egress связан с отдельной таблицей маршрутизации:

- table ID начинается с `10000`;
- priority ip rule начинается с `10000`;
- в таблицу добавляется default route через соответствующий egress TUN;
- ip rule выбирает эту таблицу по fwmark.

Socket marks — отдельный класс меток. Для каждой такой метки создаётся
правило priority `9000`, направляющее пакет в `main`. Оно имеет более
высокий приоритет, чем egress policy rules, и предназначено для внешнего
зашифрованного UDP-трафика туннелей. Для socket marks правила создаются
для IPv4 и IPv6, даже если inner IPv6 выключен.

Routing marks назначаются только уникальным интерфейсам, которые реально
используются как egress хотя бы в одном routing rule. Несколько правил с
одним egress используют одну метку и одну policy table.

## 5. Forward filter: разрешение и блокировка транзита

В forward chain сначала отбрасываются invalid-пакеты, пришедшие через
управляемый интерфейс:

```nft
iifname @managed_interfaces ct state invalid drop
```

Затем для каждого routing rule генерируется разрешение направления
ingress → egress:

```nft
iifname "INGRESS" oifname "EGRESS" \
    ct state new,established,related \
    meta mark ROUTING_MARK accept
```

Отдельно генерируется разрешение ответного направления egress → ingress:

```nft
iifname "EGRESS" oifname "INGRESS" \
    ct state established,related \
    ct mark ROUTING_MARK accept
```

После разрешающих правил следуют два catch-all drop:

```nft
iifname @managed_interfaces drop
oifname @managed_interfaces drop
```

Именно они формируют fail-closed транзитную политику:

- пакет с managed TUN не может быть переслан наружу без разрешающего
  ingress → egress rule;
- пакет не может быть переслан в managed TUN без разрешённого обратного
  направления;
- транзит между двумя клиентскими TUN-интерфейсами не разрешается сам по
  себе;
- если интерфейс присутствует в конфигурации, но не участвует в подходящем
  routing rule, транзит через него будет отброшен;
- established/related не является глобальным разрешением: для ответа
  дополнительно требуются правильные ingress/egress и ct mark.

Важное отличие от firewall с глобальным правилом
`ct state established,related accept`: vpn-relay не разрешает любой
established пакет только по состоянию conntrack. Он привязывает разрешение
к конкретной паре интерфейсов и routing mark.

### Граница этой политики

Текущие filter rules защищают именно транзит (`forward`). В таблице нет
общей input chain и нет общего запрета локального трафика. Пакеты,
адресованные самому network namespace/хосту, идут через input hook, а не
через forward. Поэтому утверждение «любой трафик с TUN блокируется, кроме
явно разрешённого» было бы слишком широким: код гарантирует fail-closed
для транзита через managed TUN, но не задаёт полноценную input policy для
самого хоста.

Также policy `accept` у forward chain не является глобальным разрешением
поверх всех остальных nftables base chains. Другие таблицы/цепочки
системного firewall могут дополнительно отбрасывать пакеты. Drop является
терминальным; accept в одной base chain не отменяет drop в другой.

## 6. NAT

NAT реализован в postrouting chain с hook priority `srcnat`.

Для каждого routing rule генерируются селекторы:

- ingress interface;
- egress interface;
- conntrack mark выбранного egress;
- заданные source/destination CIDR, если они есть.

Для `nat = "masquerade"` создаётся masquerade statement. Для `nat = "none"`
генерируется `return`: это не позволяет последующему NAT rule изменить
решение для уже совпавшего правила.

NAT rules идут в том же порядке, что и routing rules: по ingress и
priority. Комментарий в генераторе явно фиксирует намерение сохранить
приоритет выбора NAT.

По умолчанию NAT выключен. Сам факт использования egress TUN не означает,
что vpn-relay автоматически маскарадует исходный адрес.

NAT не заменяет routing decision: сначала packet mark и policy routing
определяют egress, а postrouting выполняет выбранное NAT-действие.

## 7. IPv6

IPv6 включается отдельно для каждого интерфейса. По умолчанию
`ipv6_enabled = false`.

Все интерфейсы с выключенным IPv6 помещаются в
`ipv6_blocked_interfaces`. Для них генерируются три направления защиты:

1. prerouting: drop IPv6-пакетов, входящих через такой интерфейс;
2. forward: drop IPv6-пакетов, выходящих через такой интерфейс;
3. output: drop локально созданных IPv6-пакетов, направляемых через такой
   интерфейс.

Таким образом, блокируются IPv6 ingress, IPv6 egress и локально
сгенерированный IPv6 egress через интерфейс, где IPv6 выключен.

Для egress с выключенным IPv6 не создаются IPv6 route и IPv6 fwmark rule.
Если IPv6 выключен хотя бы на одном из двух концов routing rule,
IPv6-вариант CIDR-селекторов для этого правила не генерируется.

Socket mark rules для внешнего UDP остаются и для IPv6: это намеренно
отделено от inner IPv6 policy.

## 8. Установка nftables и защита чужих таблиц

Перед применением linux backend выполняет:

```sh
nft -j list table FAMILY TABLE
```

Таблица считается принадлежащей vpn-relay только если JSON содержит
объект table с точными:

- family;
- name;
- table-level comment = `managed by vpn-relay`.

Комментарий на отдельном rule не считается доказательством владения.
Невалидный JSON также не подтверждает владение.

Поведение при проверке:

- таблица отсутствует (распознанные сообщения nftables
  `No such file or directory` / `does not exist`) — можно создавать;
- таблица существует и содержит точный ownership marker — её можно заменить;
- таблица существует, но marker отсутствует/не совпадает — startup
  прекращается с conflict, чужая таблица не удаляется;
- любая другая ошибка чтения таблицы — startup прекращается, ошибка
  передаётся вызывающему коду.

Если таблица принадлежит vpn-relay, backend формирует один nft script:
сначала `delete table`, затем весь новый script, и отправляет его через
`nft -f -`. Если таблицы не было, отправляется только script создания.

## 9. Откат, остановка и восстановление состояния

Runtime выполняет сетевую настройку в контролируемом порядке:

1. При `manage_ip_forwarding = true` считывает исходные значения
   `net.ipv4.ip_forward` и `net.ipv6.conf.all.forwarding`, затем включает
   оба forwarding sysctl.
2. Устанавливает policy routing (socket rules, egress routes и fwmark rules).
3. Устанавливает nftables table и chains.
4. При ошибке policy routing восстанавливает forwarding sysctl.
5. При ошибке установки nftables удаляет policy routing и восстанавливает
   forwarding sysctl.
6. При штатной остановке выключает workers/devices, удаляет policy routing,
   удаляет принадлежащую vpn-relay nftables table и восстанавливает исходные
   sysctl.

Удаление nftables безопасное по владению: `remove_nft` удаляет таблицу
только если повторная проверка вернула точный owned status. При ошибке
проверки или отсутствии marker функция ничего не удаляет. Ошибка команды
удаления в текущей реализации игнорируется.

Установка policy routing использует protocol tag `242`. Перед изменением
проверяются зарезервированные priority slots и таблицы маршрутизации.
Чужие правила на конфликтующем priority или чужие маршруты в зарезервированной
таблице приводят к отказу вместо перезаписи.

## 10. Что текущая политика гарантирует — и чего не гарантирует

### Гарантии в пределах сгенерированной политики

- Новый транзит через managed TUN требует явного routing rule.
- Ответный транзит допускается только для conntrack-соединения с ожидаемой
  парой интерфейсов и сохранённой routing mark.
- Неразрешённый транзит через managed TUN блокируется.
- Routing rule без source/destination селекторов сознательно разрешает весь
  транзит с данного ingress через данный egress.
- NAT не включается автоматически.
- IPv6 блокируется на интерфейсах, где он выключен, в ingress, forward
  egress и локальном output egress.
- Чужая nftables table не должна быть заменена/удалена без table-level
  ownership marker.
- При штатном завершении удаляются принадлежащие daemon nftables и
  policy-routing ресурсы.

### Не следует считать гарантированным

- Изоляцию клиентов внутри одного TUN-интерфейса на уровне L2/L3 dataplane
  самого туннельного backend. nftables forward policy не заменяет проверку
  peer AllowedIPs и поведение самого TUN/backend.
- Запрет доступа клиентов к локальным сервисам хоста. Для этого нужна
  отдельная input policy; текущая таблица её не создаёт.
- Запрет локальным процессам инициировать соединения через обычный output.
  Общий output filter не создаётся; output chain добавляется только при
  необходимости IPv6 blocking.
- Полную firewall-политику network namespace. Таблица vpn-relay не
  устанавливает input policy и не очищает/не управляет чужими таблицами.
- Разрешение трафика, который не проходит через managed TUN. Текущие
  catch-all правила ограничены интерфейсами из `managed_interfaces`.
- Защиту от изменения системного firewall сторонними компонентами после
  запуска.

## 11. Сопоставление с примером vpn_gateway

| Поведение | Пример vpn_gateway | Текущий vpn-relay |
|---|---|---|
| Входящий трафик к самому хосту | input policy drop, loopback/established/ICMP и WG UDP разрешены | Собственной input chain нет |
| Невалидные пакеты | drop в input и forward | drop в forward для managed ingress; отдельного input filter нет |
| Защита source IPv4 на WG | явная проверка source subnet на ingress | source CIDR — опциональный selector routing rule, это не anti-spoofing policy |
| Запрет маршрутизации между клиентами | явный drop назначения в клиентскую подсеть на WG | неразрешённый транзит через managed TUN блокируется catch-all drop; разрешённые правила могут намеренно соединять разные TUN |
| Клиентский трафик через AWG | только wg → awg и ответы awg → wg | любая настроенная пара ingress → egress |
| Состояния соединений | forward accept для new/established/related в прямом направлении, established/related в обратном | прямое направление требует mark; обратное требует ct mark и пары интерфейсов |
| Исходящие соединения самого контейнера | output policy accept | общий output policy не задаётся |
| NAT | masquerade на awg для заданной клиентской подсети | masquerade только для routing rule с nat=masquerade |
| IPv6 | ICMPv6 разрешён в input; forward policy в примере IPv4-specific | per-interface IPv6 enable/disable с блокировкой ingress/egress/output |
| Защита от чужих firewall-объектов | не показана | table-level ownership marker и conflict checks |

### Важное различие: anti-spoofing

В примере есть отдельное правило:

```nft
iifname "wg" ip saddr != 10.150.150.0/24 drop
```

В vpn-relay source CIDR в routing rule не эквивалентен этой проверке.
Он означает «разрешать этот диапазон источников для данного маршрута»,
но не создаёт отдельного общего запрета всех пакетов с недопустимым source
на ingress интерфейсе. Пакет с неподходящим source не совпадёт с таким
routing rule и не пройдёт forward catch-all, однако это не то же самое,
что независимая ingress anti-spoofing policy, особенно если для ingress
есть более широкое правило без source selector.

## 12. Текущие тесты и интеграционное покрытие

В `routing.rs` unit tests проверяют генерацию, в том числе:

- отсутствие source/destination selectors означает match всего ingress;
- несколько source/destination CIDR сериализуются в nft set expression;
- IPv4 и IPv6 selectors генерируются раздельно;
- unmatched managed-interface transit имеет catch-all drop;
- conntrack mark сохраняется и восстанавливается;
- reply direction сбрасывает packet mark для main table;
- IPv6-disabled interfaces попадают в set блокировки;
- NAT none/masquerade генерируется с нужными selectors и порядком.

В `linux.rs` unit tests проверяют:

- ownership требует точного family/name и table-level comment;
- comment на rule недостаточен;
- распознавание точной идентичности принадлежащих vpn-relay ip rules;
- распознавание принадлежащих daemon default routes и разрешённых kernel
  metadata.

Интеграционный сценарий `scripts/vpn-relay-netns-test.sh` проверяет в
network namespace:

- установку nftables table;
- отказ при существующей чужой таблице и сохранение её содержимого;
- отсутствие утечки policy rules при конфликте;
- отказ при чужом ip rule на зарезервированном priority;
- отказ при чужом маршруте в зарезервированной таблице;
- установку IPv4/IPv6 egress routes и fwmark policy;
- отсутствие IPv6 policy для IPv6-disabled egress;
- наличие IPv6 ingress/egress/output drop rules;
- удаление nftables table, routes и ip rules при graceful shutdown;
- восстановление исходных forwarding sysctl.

Эти тесты в основном проверяют структуру установленной политики и lifecycle
ресурсов. Они не заменяют end-to-end тесты реальной передачи пакетов для
каждого security-сценария.

## 13. Кандидаты на дальнейшую доработку

Это не список уже реализованных функций, а направления, которые стоит
обсудить и покрыть тестами перед изменением политики:

1. **Input policy:** определить, должны ли клиенты иметь доступ к локальным
   сервисам network namespace, к UDP listener WG/AWG и к диагностическим
   ICMP/ICMPv6.
2. **Anti-spoofing:** нужна ли отдельная привязка допустимых source CIDR к
   ingress interface/peer, независимая от маршрутов.
3. **Изоляция клиентов одного интерфейса:** определить, что именно backend
   гарантирует для peer-to-peer трафика внутри одного TUN и нужна ли
   дополнительная проверка AllowedIPs или firewall policy.
4. **Локальный output:** определить, должны ли локальные процессы иметь
   возможность использовать managed TUN, и как это согласовать с
   socket-fwmark механизмом.
5. **Модель default deny:** решить, достаточно ли catch-all только для
   транзита через managed TUN или нужна управляемая input/output политика.
6. **NAT semantics:** добавить packet-level тесты для пересекающихся правил
   с разными NAT modes и подтвердить first-match поведение на реальном
   nftables.
7. **Conntrack lifecycle:** проверить поведение при изменении конфигурации,
   перезапуске daemon и существующих conntrack entries.
8. **Сосуществование с системным firewall:** определить ожидаемую семантику
   нескольких base chains и необходимость явных hook priorities.
9. **Наблюдаемость:** рассмотреть counters/logging для разрешённых и
   отброшенных потоков, не создавая избыточный шум.
10. **Packet-level integration tests:** проверить разрешённый прямой поток,
    обратный ответ, запрет неописанного направления, запрет same-TUN
    транзита, IPv6 blocking, source spoofing и локальный доступ к хосту.

---

## 14. Ключевые исходники

- `vpn-relay/src/routing.rs` — генерация nftables и policy-routing plan.
- `vpn-relay/src/linux.rs` — выполнение nft/ip, ownership и cleanup.
- `vpn-relay/src/runtime.rs` — startup/rollback/shutdown и forwarding sysctl.
- `vpn-relay/src/config.rs` — конфигурационная модель и validation.
- `scripts/vpn-relay-netns-test.sh` — privileged network namespace integration.
- `vpn-relay/vpn-relay.example.toml` — пример routing rules и daemon settings.
