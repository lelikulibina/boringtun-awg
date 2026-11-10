# План реализации firewall и NAT для vpn-relay

> Рабочая ветка: `feature/vpn-relay-firewall-nat`
> Базовая ветка: `feature/boringtun-router-daemon`
> Базовый commit: `ad3f35d2790e7e47c8d050fb7b3c206c69ac2aa4`
> Последнее обновление: 2026-11-10 (negative config parser coverage; полный CI 42851385258)
>
> Этот документ является рабочим журналом реализации. Статусы меняются только
> после фактического изменения кода и выполнения соответствующих проверок.
> Неуспешные и ещё не выполненные проверки не отмечаются как завершённые.

## 1. Зафиксированные решения

| Область | Выбранная политика | Обязательная семантика |
|---|---|---|
| INPUT | `deny` | Запрещать доступ с managed TUN к локальному хосту по умолчанию; разрешать только явно описанные исключения |
| OUTPUT | `managed` | Контролировать только локально созданные пакеты, фактически направленные через managed TUN; не управлять остальным OUTPUT хоста |
| FORWARD | `deny` | Сохранять fail-closed транзит: только явно выбранные routing rules и корректные ответы |
| NAT | `extended` | `none`, `masquerade`, статический `snat`; без `dnat` и `redirect` |

Дополнительные архитектурные ограничения:

- vpn-relay владеет только своей nftables table и собственными iproute2 resources.
- Политики INPUT/OUTPUT должны быть ограничены managed-интерфейсами; глобальная
  input/output policy хоста не меняется.
- Общее `ct state established,related accept` не должно обходить INPUT deny.
- NAT должен быть однозначно связан с тем же routing decision, который выбрал egress.
- Нельзя заявлять о peer-aware anti-spoofing на уровне nftables: после TUN пакет
  не содержит криптографической идентичности peer.
- AllowedIPs и peer isolation проверяются на уровне BoringTun/backend и реальным
  трафиком; ограничения должны быть документированы.
- IPv4 и IPv6 должны иметь симметричную фильтрацию. IPv6 NAT поддерживается
  только при явной корректной реализации и проверке.
- Никакие изменения не должны удалять или заменять чужие таблицы/правила.

## 2. Статусы

- [ ] Не начато
- [~] В работе
- [x] Завершено и проверено
- [!] Заблокировано или требует отдельного архитектурного решения

Статус этапа [x] разрешён только после выполнения критериев приёмки и фиксации
результатов проверок в разделе 10.

## 3. Этап 0 — ответвление и инвентаризация

- [x] Создать отдельную рабочую ветку от актуального commit исходной ветки.
- [x] Проверить базовый commit и структуру vpn-relay.
- [x] Сверить документ `docs/VPN_RELAY_NFTABLES.md` с текущими реализациями
  `config.rs`, `routing.rs`, `linux.rs`, `runtime.rs`.
- [x] Найти существующие unit tests и network-namespace сценарии:
  `routing.rs`, `config.rs`, `vpn-relay-netns-test.sh`,
  `vpn-relay-peer-traffic-test.sh`, `vpn-relay-multi-uplink-test.sh`.
- [x] Зафиксировать текущие marks, conntrack, NAT и lifecycle: routing marks
  сохраняются в meta mark, а отдельный conntrack decision id — в старших 16
  битах ct mark с сохранением младших 16 бит; reply direction возвращается в
  main table; NAT использует точный decision id; firewall устанавливается до
  создания TUN, policy routing и включения forwarding.
- [x] Проверить реализацию AllowedIPs в BoringTun: после decapsulation оба
  варианта `WriteToTunnelV4/V6` проверяют `Device::peer_owns(peer, addr)`
  до записи в TUN. Исходный адрес проверяется по единому trie
  `peers_by_ip`, что защищает от source spoofing между peer.
- [x] Проверить реальный peer-to-peer путь на одном TUN: multi-uplink
  network-namespace test разрешает обоим клиентам проходить firewall endpoint,
  затем подтверждает, что .3 → .2 блокируется при отсутствии routing decision.
  Проверка прошла в CI run 42646765536.

Критерий приёмки: инвентаризация отражает код базового commit, а не только
предыдущую документацию; все выявленные расхождения внесены в этот журнал.

## 4. Этап 1 — security invariants и packet-level тесты

### INPUT

- [x] managed ingress без разрешения не достигает локальных IPv4 сервисов (TCP deny packet probe, CI 42836214324).
- [x] managed ingress без разрешения не достигает локальных IPv6 сервисов (TCP deny packet probe, CI 42836214324).
- [x] Явно разрешённый source/interface/protocol/port доступ работает (IPv4/IPv6 TCP allow probes, CI 42836214324).
- [x] Ответы на соединения, инициированные хостом, не дают клиенту обходить
  INPUT deny: forged reverse tuple достигает TUN, но блокируется без host-flow tag (CI 42836214324).
- [x] В генератор добавлен stateful reply path: INPUT/OUTPUT разрешают
  established/related только в conntrack reply direction, а явные allow rules
  ограничены original direction. Два forged-reply packet probes проверяют INPUT
  и OUTPUT; оба отклоняют reply для потока, начатого через unmanaged interface
  (CI 42836214324).
- [x] Loopback и трафик с unmanaged интерфейсов не меняются; loopback TCP и physical-ingress packet probes прошли (CI 42674872629).

### OUTPUT

- [x] Локальный пакет, направленный через managed TUN, проходит заданную OUTPUT
  policy (IPv4/IPv6 TCP allow и ICMPv6 probes, CI 42836214324).
- [x] Запрещённый managed egress блокируется (IPv4/IPv6 TCP deny и ICMPv6 deny
  packet probes, CI 42836214324).
- [x] Локальный трафик через физический/unmanaged интерфейс не меняется; underlay и локальные INPUT/OUTPUT source addresses проверены packet-level тестами (CI 42674872629).
- [x] Socket fwmark для внешнего WG/AWG UDP продолжает использовать main table:
  route lookup подтверждает underlay, а encrypted UDP наблюдается на физическом
  veth и отсутствует на TUN (CI 42836214324).

### FORWARD и conntrack

- [x] Сохраняется запрет нового потока без routing rule: IPv4/IPv6 probes
  отсутствуют на обоих uplink, даже при наличии обычного main route (CI 42836214324).
- [x] Сохраняется разрешение только выбранной пары ingress/egress:
  multi-uplink packet probes и TCP/UDP потоки наблюдаются на выбранном uplink,
  а overlapping priority выбирает только заданный egress (CI 42836214324).
- [x] Ответный трафик разрешённого потока проходит только в обратную пару:
  TCP/UDP iperf3 forward и reverse проверены для primary/secondary uplink,
  включая IPv6 (CI 42836214324).
- [x] Неверный/нулевой/чужой conntrack mark не открывает транзит; для host
  INPUT/OUTPUT reply дополнительно требуется отдельный `0x80000000` tag.
- [x] NAT не меняет поведение фильтрации и не применяется к запрещённым потокам; denied FORWARD не наблюдался ни на одном из двух uplink (CI 42674872629).

### Владение и lifecycle

- [x] Чужая nftables table с совпадающим именем не изменяется; отдельные foreign INPUT/OUTPUT/FORWARD chains coexist без обхода vpn-relay deny (CI 42674872629).
- [~] Ошибка применения nftables и последующих шагов приводит к rollback ранее установленных ресурсов; конфликт таблицы и отдельные failure-injection сценарии проверены, полный перебор точек отказа ещё не выполнен.
- [x] Shutdown останавливает backend workers, удаляет policy routes, затем
  уничтожает managed TUN links, и только после этого удаляет nftables policy;
  исходное forwarding состояние восстанавливается в самом конце.
- [x] Повторный запуск и аварийное завершение не оставляют опасного состояния: после SIGKILL startup восстанавливает исходные namespace-wide forwarding sysctl из приватного durable journal, затем безопасно переустанавливает daemon-owned firewall, policy routes и TUN. Полный SIGKILL/restart lifecycle и graceful restore прошли CI 42849072652.
- [!] `manage_ip_forwarding=true` меняет namespace-wide IPv4/IPv6 forwarding и затрагивает host/router settings интерфейсов; не включать на общем host namespace без отдельного решения. Для общего хоста использовать `false` и внешнее управление. Требуется отдельное проектирование per-interface forwarding (включая совместимость IPv6 kernels с `force_forwarding`) и packet-level проверка.

Критерий приёмки: тесты проверяют передачу реальных пакетов в network namespaces,
а не только строки сгенерированного nftables script.

## 5. Этап 2 — конфигурационная модель

### Реализованная часть первого прохода

- [x] Генератор создаёт INPUT и OUTPUT base chains при любой конфигурации.
- [x] INPUT разрешает только совпавшие явные allow rules, затем блокирует
  весь оставшийся managed ingress.
- [x] OUTPUT разрешает только совпавшие явные allow rules, затем блокирует
  весь оставшийся managed egress.
- [x] Нет общего established/related accept, обходящего INPUT deny.
- [x] OUTPUT проверяет фактический oifname; outer UDP, ушедший через underlay,
  не попадает под managed OUTPUT deny.
- [x] Проверить ruleset командой nft в network namespace.
- [x] Peer traffic netns test использует явные INPUT/OUTPUT allow rules.
- [x] Packet-level probes подтверждают разрешённый TCP/8080 и запрет TCP/8081
  отдельно на server INPUT и server OUTPUT; также проверяется ICMP.
- [~] Добавлен отдельный forged-reply probe: host-originated UDP flow идёт через
  unmanaged underlay, а ответ с точным обратным tuple приходит через managed
  TUN; пакет должен быть виден на TUN, но не должен попасть в host socket.
  Ожидает CI.

- [x] Добавлен `[firewall]` с независимыми `input.rules` и `output.rules`.
- [x] Правило разрешения привязано к одному существующему managed interface.
- [x] Поддержаны source CIDR для INPUT и destination CIDR для OUTPUT.
- [x] Поддержаны TCP, UDP, ICMP и ICMPv6; порты разрешены только для TCP/UDP.
- [x] Пустые списки, порт 0, неизвестные интерфейсы, IPv6 CIDR на интерфейсе
  с выключенным IPv6 и селекторы неправильного направления отклоняются.
- [x] Отсутствие allow rules означает deny для соответствующего managed hook.
- [x] Добавлены parser tests на неизвестные интерфейсы и селекторы неверного
  направления; остальные отрицательные случаи ещё требуют отдельного покрытия.
- [x] Добавлены реальные TCP listener/client probes в peer traffic netns test:
  разрешённый TCP/8080 и запрещённый TCP/8081 для INPUT/OUTPUT; IPv4/IPv6
  probes прошли в CI 42836214324.



Текущая конфигурационная модель уже реализована и показана в
`vpn-relay/vpn-relay.example.toml`: INPUT/OUTPUT allow rules задаются через
`[firewall.input.rules]` и `[firewall.output.rules]`, а NAT action и
`nat_to` являются свойствами выбранного `[[routing.rules]]`. Отдельная
`[[nat.rules]]` модель не используется, чтобы не создавать второй источник
истины для выбора ingress/egress.

Задачи:

- [x] Зафиксировать security defaults: INPUT/OUTPUT managed deny без явных
  allow rules, FORWARD deny без routing decision; политики не переключаются
  конфигурационными флагами. Значение base-chain policy accept не меняет
  этот локальный deny и не затрагивает глобальный firewall хоста.
- [x] Описать типизированные INPUT/OUTPUT rule selectors в конфигурационной
  модели и документации.
- [x] Описать протоколы TCP/UDP/ICMP/ICMPv6 и семантику портов в `docs/VPN_RELAY_NFTABLES.md`.
- [x] Описать IPv4/IPv6 CIDR и поведение при смешанных семействах:
  selectors сопоставляются только в пределах одного address family.
- [x] Добавить типизированный NAT action `Snat(IpAddr)` наряду с `None` и `Masquerade`: TOML `nat = "snat"` требует `nat_to`, семейство адреса валидируется относительно selectors и IPv6 ingress/egress, nftables генерирует `snat ip`/`snat ip6`; parser, typed-action и nft generation tests проходят.
- [x] Зафиксировать NAT как свойство выбранного routing rule. Отдельная
  `[[nat.rules]]` секция не вводится: это исключает второй независимый
  механизм выбора ingress/egress. Расширение добавит адрес SNAT к routing rule.
- [x] Валидировать ссылки на интерфейсы, address family, пустые списки,
  дубликаты и неоднозначные совпадения: добавлен отказ на точные и
  семантически эквивалентные CIDR сети (с разными host bits). Пересекающиеся,
  но не эквивалентные CIDR разрешены намеренно; порядок first-match по
  priority и сохранение conntrack decision документированы и покрыты
  routing tests. Дополнительно проверены пустые firewall/routing selectors,
  неизвестные firewall interfaces, пустые/нулевые ports и ports для ICMP.
- [x] Обновить пример TOML и CLI `--check` tests.
- [x] Проверить `deny_unknown_fields` для корневой конфигурации, INPUT firewall rule и routing/NAT rule; добавлены регрессионные parser tests на неизвестные поля.

Критерий приёмки: конфигурация не может выразить неоднозначную или
неподдерживаемую политику; ошибки обнаруживаются до создания системных ресурсов.

## 6. Этап 3 — единый Routing Decision

- [x] Выделить внутреннюю модель выбранного правила: `RoutingDecision`
  содержит ingress, egress, source/destination selectors, отдельные поля
  routing mark и conntrack mark, а также NAT action.
- [x] Routing mark назначается egress-интерфейсу и разделяется решениями,
  использующими один uplink.
- [x] Conntrack mark уникально идентифицирует выбранное routing decision,
  даже если несколько правил используют один egress; идентификаторы берутся
  из выделенного диапазона старших 16 бит `0x40010000`–`0x4fff0000`;
  младшие 16 бит исходного conntrack mark сохраняются.
- [x] Классификация новых соединений записывает routing mark и уникальный
  conntrack mark из одного упорядоченного набора решений.
- [x] Для established original-direction пакетов routing mark восстанавливается
  по conntrack decision id; reply-direction возвращается в main table.
- [x] FORWARD reply и NAT используют тот же уникальный conntrack decision id.
- [x] NAT ограничен исходной ingress/egress парой, поэтому чужой conntrack mark
  сам по себе не может применить NAT на произвольном интерфейсе.
- [x] Unit tests описывают пересекающиеся selectors с одним egress и разными
  NAT actions; multi-uplink packet test подтверждает на реальном трафике выбор
  статического SNAT для точного source и masquerade для более широкого
  overlapping rule при одинаковых destination и egress (CI 42665725191).
- [x] Проверить отсутствие коллизий socket fwmark и routing marks: parser tests
  покрывают явные дубликаты, пересечение диапазонов и автоматическое выделение.
- [x] Сохранить детерминированность генерации nftables/iproute2 plan; решения и
  egress marks строятся из упорядоченных коллекций.

Критерий приёмки: маршрут, FORWARD и NAT не могут выбрать разные routing rules
для одного потока; unit tests покрывают приоритеты и пересечения.

## 7. Этап 4 — реализация INPUT deny

- [x] Добавить INPUT base chain в таблицу vpn-relay с policy accept, поскольку
  глобальный INPUT namespace принадлежит системному firewall.
- [x] Сначала отбрасывать invalid на managed ingress.
- [x] Применять явные разрешения только к managed ingress.
- [x] Запрещать остальные пакеты с managed ingress до любого общего
  established/related accept, способного обойти политику.
- [x] Разделены conntrack original/reply направления: явные INPUT/OUTPUT
  allow rules принимают original direction и устанавливают host-flow tag
  `0x80000000`; reply разрешается только при совпадении этого tag. Это не
  позволяет established flow, начатому через unmanaged egress, обходить
  managed INPUT deny. Forged-reply packet test подтверждает блокировку ответа
  на host-flow, начатый через unmanaged underlay (CI 42668190390).
- [x] Не блокировать loopback; TCP connect к 127.0.0.1 подтверждён packet-level тестом (CI 42674872629).
- [x] Не блокировать unmanaged ingress; physical UDP probe доходит до host socket.
- [x] Добавлены packet-level IPv4/IPv6 ICMP, TCP и ICMPv6 allow/deny проверки
  (WG и AWG, CI 42668190390).
- [x] Проверено coexistence с чужими nftables base chains: ранний foreign accept не отменяет последующий deny vpn-relay; INPUT/OUTPUT/FORWARD counters и сохранность chains после shutdown подтверждены (CI 42674872629).

Критерий приёмки: неразрешённый пакет с managed TUN к локальному адресу
блокируется независимо от наличия conntrack entry; другие ingress не меняются.

## 8. Этап 5 — OUTPUT managed

- [x] Создавать output base chain независимо от IPv6-disabled gating.
- [x] Сначала отбрасывать invalid на managed TUN egress.
- [x] Фильтровать только пакеты с фактическим managed TUN egress.
- [x] Определить безопасную модель default deny и явных разрешений.
- [x] Не блокировать socket-marked outer UDP, направленный через underlay;
  packet capture видит encrypted UDP на underlay и не видит его на TUN.
- [x] Не влиять на физический/unmanaged egress; peer traffic tests проверяют
  underlay host flows и внешний UDP transport.
- [x] Проверить local IPv4/IPv6, TCP/UDP/ICMP, explicit allow/deny и socket marks
  на реальном WG/AWG трафике (CI 42668190390 и 42674872629).

Критерий приёмки: тесты доказывают, что managed egress контролируется, а
unmanaged output остаётся неизменным.

## 9. Этап 6 — NAT extended

- [x] Сохранить `none` как отсутствие трансляции; packet capture подтверждает
  исходный IPv4 и IPv6 source на remote uplink.
- [x] Реализовать IPv4 `masquerade`; packet capture подтверждает SNAT на адрес
  primary TUN.
- [x] Реализовать IPv4 статический `snat` через `nat = "snat"` и обязательный
  `nat_to` в routing rule.
- [x] Проверить IPv6 masquerade и IPv6 static SNAT: packet capture подтверждает
  замену source на адреса primary TUN и fd20::99 соответственно
  (CI 42665725191).
- [x] Связать NAT с единственным routing decision и conntrack state: classifier
  назначает уникальный decision ID, а NAT использует тот же conntrack mark.
- [x] Проверить несколько правил, приоритеты и перекрывающиеся selectors:
  packet-level multi-uplink test подтверждает static SNAT для точного source и
  masquerade для широкого перекрывающегося правила на том же egress
  (CI 42665725191).
- [x] Проверить отсутствие NAT на INPUT/OUTPUT и запрещённом FORWARD:
  packet captures подтверждают неизменность source для локальных INPUT/OUTPUT,
  а tcpdump на обоих uplink не видит пакеты без routing decision
  (integration-tests CI 42815100743).
- [x] Packet-level regression test смены IPv4 адреса egress прошёл: после удаления
  10.20.0.1/24 и назначения 10.20.0.99/24 новый masquerade flow выходит с
  10.20.0.99 (полный integration CI 42831549649).

Критерий приёмки: пакет получает ровно одну ожидаемую NAT policy; запрещённый
или локальный трафик не подвергается source NAT.

## 10. Этап 7 — AllowedIPs и peer isolation

- [x] Проследить путь расшифрованного IPv4/IPv6 пакета в BoringTun:
  оба `WriteToTunnelV4/V6` пути проходят через `Device::peer_owns` до записи
  пакета в TUN.
- [x] Подтвердить, что peer identity известна до передачи пакета в TUN.
- [x] Подтвердить проверку source address по AllowedIPs именно отправившего
  peer через единый `peers_by_ip` индекс.
- [x] Проверить пересекающиеся и вложенные AllowedIPs: router peer .2 владеет
  широкими IPv4 /24 и IPv6 /64, peer .3 — более специфичными /32 и /128;
  packet-level spoof probes подтверждают, что первый peer не может отправить
  source IP второго (CI 42669268349).
- [x] Проверить peer-to-peer обмен между двумя клиентами одного интерфейса:
  multi-uplink netns test ожидает блокировку обмена между клиентами .2 и .3.
- [x] Зафиксировать границу ответственности: nftables не видит peer identity
  после декапсуляции; source anti-spoofing обеспечивает BoringTun backend,
  а interface-level routing rules не являются peer-specific ACL.
- [!] Runtime AllowedIPs/peer hot reload не реализован: TunnelHandle сейчас
  предоставляет snapshot/shutdown/wait, а peers настраиваются только при
  BackendRegistry::create. Нельзя проверять update races до проектирования
  API reconfiguration и атомарного согласования backend, routing и firewall.
  Пересекающиеся prefix ownership для текущей статической конфигурации проверены
  packet-level тестом (CI 42669268349).

Критерий приёмки: гарантии подтверждены тестами на реальном BoringTun traffic;
неподтверждённые свойства не заявляются.

## 11. Этап 8 — runtime, rollback, ownership

- [x] Сформировать и валидировать Config, socket marks, RoutingPlan и backend
  config до изменения системного состояния.
- [x] Разрешить peer endpoint на этапе backend preflight и передавать точные
  `SocketAddr` в создание туннеля без повторного DNS lookup; подготовленное
  состояние проверяется на соответствие числу peers.
- [x] Установить ресурсы в безопасном порядке: fail-closed nftables policy →
  TUN interfaces → policy routes → IP forwarding.
- [x] Установить nftables fail-closed policy до policy routes и включения IP
  forwarding; при ошибке последующих шагов откатывать уже установленные
  policy routes и nftables table.
- [x] Проверить startup rollback при конфликте nft table, ip rule и route,
  включая сохранность чужих ресурсов (CI 42665725191).
- [~] Сделать rollback симметричным каждому успешному шагу: setup TUN, interface configuration, nftables activation, policy-routing staging, forwarding enable, durable forwarding recovery и graceful shutdown имеют rollback/failure-injection покрытие. Crash-consistent sysctl ownership закрыт; остаётся полный перебор ошибок cleanup и rollback на каждой границе системного вызова.
- [x] Не удалять чужие ip rules/routes/nftables objects; проверены foreign
  nftables table/base chains, masked ip rules и IPv4/IPv6 routes.
- [~] Проверить частичные ошибки на каждом шаге установки: setup TUN, interface configuration, nftables, IPv4/IPv6 policy route, forwarding enable/restore и staged stale-rule cleanup имеют failure-injection сценарии; остаётся расширить матрицу cleanup rollback failures и проверить каждую точку системного вызова.
- [x] Проверить shutdown, повторный запуск, lock и network namespace lifecycle: graceful shutdown, duplicate lock и SIGKILL/restart проверены. Versioned forwarding journal сохраняется до изменения sysctl, привязан к inode network namespace, проверяется по owner/mode/nlink/size/schema и восстанавливается до повторного включения forwarding. Journal удаляется только после успешного восстановления; при ошибке остаётся для следующего запуска. Полный lifecycle прошёл CI 42849072652.
  (CI 42665725191).
- [x] Проверить удаление/переименование TUN во время работы: исходный FD
  проверяется через Linux `TUNGETIFF`; drop-only bootstrap исключает трафик до
  верификации; рабочие nftables selectors привязаны к `iface_index`; имя+index
  mismatch guards блокируют одноимённую замену. Root netns integration test
  удаляет `awg-primary`, создаёт новый TUN с тем же именем и другим ifindex,
  отправляет пакет, проверяет `counter drop`, ожидает fatal shutdown и
  подтверждает сохранение firewall (CI 42831549649).

### Архитектурное уточнение runtime reconfiguration (исследование 2026-11-09)

Проверены фактические интерфейсы `vpn-relay/src/backend/mod.rs`,
`backend/boringtun.rs`, `runtime.rs`, `routing.rs` и typed API
`boringtun/src/device/mod.rs`.

Подтверждённые ограничения текущего кода:

- `DeviceHandle::update_peer` уже умеет добавлять, изменять и удалять peer,
  заменять AllowedIPs, менять endpoint, keepalive и preshared key. Изменение
  выполняется под write lock одного Device.
- `DeviceHandle::snapshot` возвращает endpoint, AllowedIPs и keepalive, но не
  preshared key. Поэтому snapshot работающего backend недостаточен для
  достоверного восстановления предыдущей peer-конфигурации.
- vpn-relay `TunnelHandle` экспортирует только counters snapshot, shutdown и
  wait; backend peer-update API наружу не выведен.
- `Runtime` не хранит исходный `Config` после startup. Следовательно,
  отсутствует authoritative committed config, необходимый для diff и rollback.
- Изменение routing rules, firewall selectors, NAT, интерфейсов или fwmarks
  затрагивает несколько kernel ресурсов и не может быть безопасно реализовано
  как последовательность независимых вызовов `update_peer`.

Принято разделить будущую переконфигурацию на два уровня:

1. **Peer-only reconfiguration** — изменение набора peer и их endpoint,
   AllowedIPs, PSK и keepalive при неизменной конфигурации интерфейсов и
   неизменном `RoutingPlan`. Runtime хранит последнюю успешно применённую
   конфигурацию как источник rollback; backend заранее валидирует/разбирает
   все операции и предоставляет batch API с единой точкой сериализации.
   При ошибке применяется предыдущий committed peer set; если rollback не
   удался, runtime должен перейти в fail-closed состояние и явно сообщить
   фатальную ошибку, а не продолжить работу со смешанным набором peer.

2. **Network/policy reconfiguration** — изменения интерфейсов, адресов, MTU,
   listen/socket marks, routing, firewall, NAT и forwarding. Для этого нужен
   отдельный staged transaction: построить и проверить новый Config/Plan;
   установить совместимую fail-closed policy; подготовить новые/изменённые
   ресурсы; переключить routing и backend в определённом порядке; удалить
   устаревшие ресурсы только после успешного commit; при ошибке восстановить
   предыдущий snapshot ресурсов. До реализации такого transaction эти поля
   считаются restart-required, а не hot-reloadable.

`DeviceHandle::with_device_mut` уже предоставляет нужную точку сериализации:
он инициирует cooperative yield datapath readers и выполняет closure под
эксклюзивным доступом к `Device`. Поэтому серия внутренних изменений внутри
одного такого closure не будет наблюдаться datapath как промежуточные
состояния. Текущая публичная `update_peer`, напротив, берёт этот lock отдельно
на каждый вызов, поэтому цикл вызовов из vpn-relay не атомарен.

Однако единый lock сам по себе не обеспечивает all-or-nothing при ошибке:
`Device::update_peer` может вернуть `Error::PeerSetup` при создании нового
peer. Следовательно, все новые `Tunn`/`Peer` должны быть подготовлены до
изменения `peers`, `peers_by_idx` и `peers_by_ip`, а commit closure должен
содержать только операции без fallible setup. Ещё одна точка риска —
`Peer::set_endpoint` и `Peer::shutdown_endpoint` вызывают `Socket::shutdown`
через `unwrap`; перед использованием этих методов в транзакционном пути
необходимо заменить panic-поведение на контролируемую ошибку либо сделать
закрытие endpoint best-effort с диагностикой.

Нельзя считать замену списка peer атомарной только потому, что каждый
`update_peer` защищён внутренним lock: серия вызовов может быть видна datapath
между операциями. Нужны batch semantics и тесты одновременного трафика во время
обновления, удаления и rollback. Также требуется отдельно проверить поведение
при endpoint DNS resolution failure до начала commit.


#### Контракт будущего peer batch API

Batch API должен реализовывать **полную замену peer set**, а не просто обёртку
над циклом `update_peer`:

1. До изменения live state разобрать ключи, PSK, AllowedIPs и endpoints;
   разрешить DNS и проверить уникальность public keys, корректность prefix и
   отсутствие конфликтующего владения AllowedIPs.
2. Подготовить объекты всех новых `Peer`/`Tunn` до commit. Ошибка подготовки
   любого нового peer не должна менять текущие peer, endpoint, ключи или
   `peers_by_ip`; пропуск зарезервированных LFSR index допустим.
3. Для существующих peer определить явную семантику **установить или очистить**
   endpoint, PSK и keepalive. Обычный `Option<T>` в текущем `update_peer`
   означает «не менять при None» и потому не подходит для полной замены.
4. Commit выполнять одной операцией `with_device_mut`, под единым эксклюзивным
   доступом к `Device`: datapath не должен увидеть промежуточное состояние
   AllowedIPs или частично заменённый peer set. После начала commit не должно
   оставаться fallible setup-операций.
5. Runtime хранит последний успешно committed `Config` отдельно от live
   snapshot. При ошибке до commit старое состояние остаётся нетронутым; после
   успешного commit authoritative config обновляется только один раз.
6. Rollback после ошибки commit допустим только через повторное применение
   полного предыдущего peer set. Если восстановление не удалось, backend
   обязан вернуть отдельную фатальную ошибку; runtime не должен продолжать
   обычную работу с неопределённым peer state.

Обязательные тесты: отказ staging нового peer без изменения старых peer;
передача AllowedIPs между peer без наблюдаемого промежуточного владельца;
удаление peer и очистка его endpoint/keepalive/PSK; сохранение существующих
Noise sessions для peer, чьи параметры не менялись; непрерывный двусторонний
трафик во время batch commit; rollback после искусственной ошибки подготовки.

Критерий приёмки: каждый сценарий отказа оставляет namespace в безопасном и
предсказуемом состоянии; чужие ресурсы не меняются.

## 12. Этап 9 — документация и CI

- [x] Обновить `docs/VPN_RELAY_NFTABLES.md` по фактической реализации.
- [x] Добавить архитектурную схему packet path и порядок hooks в `docs/VPN_RELAY_NFTABLES.md`.
- [x] Документировать INPUT/OUTPUT/FORWARD/NAT, conntrack, marks и ownership.
- [x] Документировать границы AllowedIPs и peer isolation; отдельно указано, что nftables не видит cryptographic peer identity после decapsulation.
- [x] Обновить vpn-relay/vpn-relay.example.toml: присутствуют routing/NAT,
  firewall INPUT/OUTPUT и комментарии по static SNAT.
- [x] Unit, parser и packet-level integration tests включены в CI.
- [x] Выполнить rustfmt, clippy, cargo test, feature checks и netns tests:
  CI 42674872629 завершился success; integration, WG/AWG packet traffic,
  multi-uplink, feature checks и `all-systems-go` успешны.
- [x] Зафиксировать CI run и фактические статусы jobs: 42674872629 на HEAD
  c06082b8a0e2b776b1d563edfaca3d03f14665ef, conclusion success.

Критерий приёмки: документация соответствует коду; обязательные CI jobs зелёные;
нет непроверенных заявлений о безопасности.

## 13. Журнал выполнения

| Дата | Изменение | Проверки | Статус |
|---|---|---|---|
| 2026-11-09 | Создана ветка `feature/vpn-relay-firewall-nat` от `ad3f35d2790e7e47c8d050fb7b3c206c69ac2aa4` | GitHub branch ref проверен | Завершено |
| 2026-11-09 | Добавлен рабочий план реализации | Commit 93244b354acef1344c9ab9ec2600372633de3ea6 | Завершено |
| 2026-11-09 | Проверены BoringTun AllowedIPs ingress validation и backend routing lookup | Просмотрены `Device::peer_owns`, `WriteToTunnelV4/V6`, `peers_by_ip` | Завершено |
| 2026-11-09 | Уточнена модель NAT: действие остаётся в routing rule | Отдельная NAT-секция не нужна, так как egress уже выбирается routing rule | Завершено |
| 2026-11-09 | Добавлены INPUT/OUTPUT chains, explicit allow rules и managed default deny | Unit/parser tests; CI run 42625442963: unit tests, clippy, rustfmt, feature checks и AWG interoperability успешны; peer traffic integration упал из-за отсутствующих explicit allow rules | Проверено, полный CI 42808265342 |
| 2026-11-09 | Peer traffic netns scenario переведён на явные INPUT/OUTPUT allow rules | Run 42629958261: WG и AWG peer traffic tests успешно прошли; общий integration job упал позже на multi-uplink тесте, где endpoint-конфигурации ещё не имели allow rules | Проверено, полный CI 42808265342 |
| 2026-11-09 | Multi-uplink test адаптирован к INPUT/OUTPUT deny-by-default | Добавлены точечные разрешения на client, router и uplink endpoints; CI ещё выполняется | Проверено, полный CI 42808265342 |
| 2026-11-09 | Ужесточена проверка address family для SNAT | Исправлен случай, когда family присутствовал только в одном selector, но отсутствовал в пересечении source/destination; добавлен regression parser test | Проверено, полный CI 42808265342 |
| 2026-11-09 | Добавлены packet-level INPUT/OUTPUT probes | Peer traffic test запускает TCP listeners на обоих концах, проверяет разрешённый порт 8080 и отдельно INPUT deny/OUTPUT deny на 8081; iperf3 TCP/UDP 5201 также явно разрешён | Проверено, полный CI 42808265342 |
| 2026-11-09 | Выделена модель `RoutingDecision` | Routing classifier, FORWARD и NAT используют один список решений; CI после переименования выявил устаревший публичный re-export `NftRule`, исправление внесено | Проверено, полный CI 42808265342 |
| 2026-11-09 | Добавлена conntrack-aware обработка ответного трафика INPUT/OUTPUT | Явные allow rules ограничены original direction; established/related reply принимается только на managed interface; добавлены unit assertions | Проверено, полный CI 42808265342 |
| 2026-11-09 | Разделены routing mark и conntrack decision id | Уникальный conntrack id назначается каждому routing decision; established route restore, обратный FORWARD и NAT используют этот id; NAT ограничен исходной парой интерфейсов | Проверено, полный CI 42808265342 |
| 2026-11-09 | Изменён порядок startup/shutdown | nftables policy устанавливается до создания/поднятия TUN, policy routing и включения forwarding; shutdown держит firewall до удаления TUN links; обновлён netns readiness check | Ожидает network-namespace CI |

| 2026-11-09 | Packet-level ICMPv6 INPUT/OUTPUT deny probes | CI 42668190390: WG и AWG peer traffic tests, включая ICMPv6 allow и deny по source/destination selectors, успешно прошли | Завершено |
| 2026-11-09 | Проверка вложенных AllowedIPs между peers | Commit 84ab63a; CI 42669268349: IPv4 /24 и IPv6 /64 для первого peer, более специфичные /32 и /128 для второго; spoof probes не достигли router TUN | Завершено |
| 2026-11-09 | Успешная полная проверка firewall/NAT и peer traffic | CI 42668190390: all-systems-go success; rustfmt, clippy, tests, feature checks, AWG 3.1, netns, WG/AWG packet tests и multi-uplink прошли | Завершено |
| 2026-11-09 | Добавлены failure-injection проверки частичного policy routing и IPv6 forwarding | Commit db3be5a; network-namespace job CI 42670711006 успешно проверил cleanup IPv4 routes/rules после отказа IPv6 route replace и restore IPv4 forwarding после отказа IPv6 sysctl | Подтверждено CI |

| 2026-11-09 | Полная packet-level проверка firewall/NAT и coexistence | CI 42674872629 на HEAD c06082b8a0e2b776b1d563edfaca3d03f14665ef: `all-systems-go` success; netns startup/rollback, WG, AWG 3.1, loopback, foreign INPUT/OUTPUT/FORWARD chains, локальные source addresses и блокировка denied FORWARD на обоих uplink прошли | Подтверждено CI |

| 2026-11-10 | Сверен статус статического SNAT с кодом и тестами | `NatAction::Snat(IpAddr)`, обязательный `nat_to`, проверка address family/IPv6 flags и генерация IPv4/IPv6 nftables SNAT уже реализованы; parser и routing unit tests присутствуют. Устаревший открытый пункт плана исправлен после успешного CI 42836214324. | Подтверждено CI 42836214324 |

| 2026-11-10 | Добавлена проверка восстановления после SIGKILL | Namespace integration test принудительно завершает daemon через SIGKILL, проверяет сохранение fail-closed nftables и policy routes, исчезновение TUN links, повторный запуск поверх принадлежащих daemon ресурсов и штатную очистку после restart. Тест явно фиксирует оставшееся ограничение: namespace-wide forwarding sysctl переживает SIGKILL, так как Drop не выполняется; для безопасного автоматического восстановления требуется durable ownership state. | Ожидает CI |
| 2026-11-10 | Усилен rollback multi-egress policy staging | `apply_egress_policy_routing` теперь откатывает все candidate resources при любой ошибке, включая отказ удаления stale IPv6 resources или stale fwmark rule; добавлен отдельный failure-injection probe. CI 42840732399 прошёл полностью. | Подтверждено CI 42840732399 |

## 14. Правила ведения плана

1. Перед началом каждого этапа проверять актуальный head рабочей ветки.
2. Обновлять этот файл вместе с завершением логического изменения, а не задним
   числом после всей реализации.
3. Для каждой отметки [x] указывать commit и реально выполненные проверки.
4. Если обнаружено архитектурное ограничение, фиксировать его здесь до
   продолжения реализации.
5. Не отмечать CI завершённым, пока соответствующий workflow run не завершён.
6. Не объединять несвязанные этапы в один большой commit.
7. Не менять исходную ветку; рабочие изменения вести только в этой ветке.

| 2026-11-09 | Добавлен ранний drop invalid для managed INPUT/OUTPUT | Правила ограничены managed ingress/egress; добавлены unit assertions; исправлено экранирование newline в nft script | Проверено, полный CI 42808265342 |
| 2026-11-09 | Исправлен multi-uplink packet test для второго клиента | Второй клиентский firewall теперь разрешает тестовый routed трафик; предыдущий failure был вызван его собственным OUTPUT deny до router ingress | Ожидает повторный packet-level CI |
| 2026-11-09 | Переписана документация nftables | Документ соответствует текущим INPUT/OUTPUT/FORWARD, conntrack decision IDs, NAT, IPv6 gating, ownership и runtime; явно описана граница peer identity | Готово |

| 2026-11-09 | Проверен anti-spoofing на уровне BoringTun | После decapsulation IPv4/IPv6 пакет попадает в TUN только если `Device::peer_owns` подтверждает владение source IP через единый `peers_by_ip` индекс; regression tests проверяют передачу prefix между peers | Backend-проверка подтверждена; packet-level race tests остаются |
| 2026-11-09 | Проверена граница peer isolation | Multi-uplink netns test проверяет запрет .3 → .2; nftables не получает peer identity после decapsulation, source anti-spoofing выполняется BoringTun | Требует повторного успешного CI после исправления тестового firewall |

| 2026-11-09 | Привязаны INPUT/OUTPUT replies к явной авторизации исходного host flow | Allow rules выставляют отдельный high-16-bit ct mark tag `0x80000000`; reply rules требуют его; младшие 16 бит сохраняются; unit assertions обновлены | Ожидает nft/netns CI и packet-level forged-reply test |

| 2026-11-09 | CI для host-flow conntrack tag и текущей firewall/NAT реализации | Run 42646765536: all-systems-go success; unit tests, clippy, rustfmt, feature checks, AWG 3.1 interoperability, netns routing, WG/AWG bidirectional traffic и multi-uplink packet tests прошли | Завершено |
| 2026-11-09 | Добавлен forged-reply packet probe | Проверяет, что reply к host-originated unmanaged UDP flow виден на managed TUN, но блокируется INPUT без host-flow conntrack tag | Проверено, полный CI 42808265342 |


| 2026-11-09 | Удалён дублирующийся OUTPUT reply probe; forged-reply сценарий дополнен отдельной проверкой underlay и диагностикой отправителя | Коммиты 8543b36, e8fb434; ожидается новый CI. Предыдущий run 42654386211 выявил, что forged reply не доходил до server TUN; добавлены захват исходного host-flow на клиентском underlay и логирование отправки | Проверено, полный CI 42808265342 |
| 2026-11-09 | Статический SNAT проверяется адресом, отличным от адреса egress TUN | Коммит bdcf1d7: nat_to=10.20.0.99, peer AllowedIPs и endpoint INPUT/OUTPUT selectors расширены для обратного пути; ожидается packet-level CI | Проверено, полный CI 42808265342 |
| 2026-11-09 | OUTPUT reply probe разделён на один сценарий без дублирования | Удалён повторный блок, который повторно отправлял тот же UDP запрос и ошибочно завершал тест; основной сценарий подтверждает получение запроса сервисом, EPERM на ответе и отсутствие пакета на клиентском TUN | Проверено, полный CI 42808265342 |


| 2026-11-09 | Исправлен IPv6 unmatched-destination probe | CI run 42659938329 показал, что прежний адрес `2001:db8:2::1` одновременно использовался отдельным разрешённым правилом статического IPv6 SNAT; негативный тест ошибочно проверял разрешённый поток. Проверка перенесена на `2001:db8:3::1`, для которого нет routing decision. Повторная packet-level проверка ожидается в следующем CI run | Проверено, полный CI 42808265342 |


| 2026-11-09 | Документация packet path и peer identity синхронизирована с реализацией | В `docs/VPN_RELAY_NFTABLES.md` уже присутствуют Mermaid-схема hook order, правила INPUT/OUTPUT/FORWARD/NAT, семантика протоколов/портов и границы AllowedIPs/peer identity; соответствующие пункты плана отмечены выполненными | Готово |


| 2026-11-09 | Расширена проверка сохранности чужих policy routes | Network-namespace startup rollback test теперь одновременно создаёт чужие IPv4 и IPv6 default routes в зарезервированной таблице; daemon должен отказать до перезаписи, сохранить обе записи и убрать собственные ресурсы | Проверено, полный CI 42808265342 |


| 2026-11-09 | Добавлены regression tests неизвестных полей firewall/NAT | Проверяется отказ от `allow_all` в firewall rule и неизвестного `nat_target` в routing rule; это предотвращает молчаливое игнорирование ошибочно названных security-параметров | Проверено, полный CI 42808265342 |


| 2026-11-09 | Проверка coexistence с чужими nftables base chains | Network-namespace тест создаёт отдельную таблицу с INPUT/FORWARD/OUTPUT base chains на более раннем hook priority; проверяет их наличие после запуска и штатного shutdown vpn-relay | Проверено, полный CI 42808265342 |

| 2026-11-09 | Добавлены packet-level loopback и foreign INPUT/OUTPUT base-chain probes | Проверяется доступность локального TCP listener через 127.0.0.1 и то, что foreign accept chains с priority -10 не отменяют последующий deny vpn-relay; ожидает CI | Проверено, полный CI 42808265342 |

| 2026-11-09 | Расширены packet-level проверки coexistence и NAT scope | Добавлены foreign FORWARD accept-chain probe, проверка локальных INPUT/OUTPUT source addresses без NAT и захват запрещённого FORWARD на обоих uplink; ожидает полного CI | Проверено, полный CI 42808265342 |

| 2026-11-09 | Backend preflight сохраняет разрешённые peer endpoints | Коммиты 8c2f23e, fe2b83f, ea98f71, db44a2c; `PreparedInterface` переносит точные `SocketAddr` из preflight в создание BoringTun без повторного DNS resolve; unit test проверяет подготовленный literal endpoint | Завершено; CI run 42680908328, attempt 2: all-systems-go success. Attempt 1 падал на ICMPv6 INPUT deny, повторная integration job прошла; первопричина первого сбоя не установлена |
| 2026-11-09 | Устранён panic при закрытии peer endpoint | `Peer::shutdown_endpoint` и `Peer::set_endpoint` больше не вызывают `unwrap()` на `Socket::shutdown`; ошибка graceful shutdown логируется, закрытие гарантируется drop socket. Расширен endpoint roaming regression test: замена endpoint с уже отключённым UDP socket не должна паниковать | Проверено, полный CI 42808265342 |


| 2026-11-09 | Добавлен backend-neutral контракт замены peer set и runtime API `Runtime::replace_peers` | BoringTun preflight повторно разрешает endpoints до commit; полный peer set передаётся в `DeviceHandle::replace_peers`; authoritative interface config заменяется только после успешного backend commit. API намеренно не меняет routing/firewall и не позволяет менять остальные параметры интерфейса; полная транзакция конфигурации остаётся следующим этапом | Проверено, полный CI 42808265342 |


| 2026-11-09 | Добавлен локальный control socket для peer replacement | Daemon принимает ограниченный JSON-запрос через Unix socket в текущем network namespace; сокет имеет права 0600, запрос ограничен 1 MiB и обслуживается последовательно в основном runtime loop. CLI `--replace-peers INTERFACE` читает peers из config file и отправляет их работающему daemon; runtime меняет authoritative peer config только после успешного backend commit. Полная reload/transaction конфигурации, routes и firewall пока не реализована | Проверено, полный CI 42808265342 |


## 15. Этап 10 — безопасная граница runtime reload

- [x] Зафиксировать неизменяемые параметры интерфейса: набор и имена интерфейсов,
  тип туннеля, адреса, MTU, IPv6 gating, listen port, private key, явный и
  разрешённый socket fwmark, параметры AmneziaWG.
- [x] Добавить `Config::validate_reload_compatibility`: разрешать изменение
  peer sets, routing decisions и INPUT/OUTPUT firewall rules; отклонять
  изменение параметров, требующих пересоздания tunnel device или смены
  lifecycle ресурсов daemon.
- [x] Добавить тесты на допустимые изменения peer/routing и отказ при изменении
  private key, AWG parameters, socket fwmark и набора интерфейсов.
- [x] Добавить runtime API, который принимает полный candidate config, выполняет
  validation/preflight всех peer endpoints и только затем запускает transaction.
- [x] Разделить подготовку и commit peer sets для нескольких tunnel devices;
  обеспечить rollback уже committed devices при последующем отказе. Runtime заранее
  preflight-ит все изменённые interfaces и выполняет rollback в обратном порядке.
- [x] Реализовать безопасный переход nftables и policy routing с отдельными
  операциями staging новых egress routes, атомарного nftables switch и cleanup
  старых routes только после switch. Старый план не удаляется при rollback нового.
- [x] Обеспечить fail-closed поведение при смене routing marks и route tables:
  mark ranges обязаны быть непересекающимися; allocator проверяет занятые route
  tables, priorities и чужие ip rules, ссылающиеся на candidate table IDs.
- [x] Обновлять authoritative config/runtime plan только после успешного
  peer+nft commit; ошибки rollback и cleanup переводят daemon в fatal state.
- [x] Добавить failure-injection и packet-level tests для успешного reload,
  ошибки nft transaction, ошибки route install, rollback firewall/routes,
  multi-interface peer rollback и непрерывного трафика. Проверки подтверждены
  CI runs 42714141354 (route failure rollback), 42720463290 (multi-device peer
  rollback) и 42724351018 (непрерывный WG/AWG traffic при runtime reload).
- [x] Добавить control socket request и CLI для полного reload конфигурации;
  существующий `--replace-peers` оставить совместимым либо явно deprecated.
- [x] Подтвердить текущий этап полным CI, включая network-namespace и packet
  tests (run 42705792288, all-systems-go success). Дополнительные failure-injection
  сценарии остаются отдельной задачей.

Архитектурные ограничения, выявленные при исследовании:
1. `linux::apply_nft` заменяет всю принадлежащую vpn-relay таблицу одной
   nftables transaction. Это атомарно для nftables, но не атомарно совместно
   с iproute2.
2. `linux::apply_policy_routing` по-прежнему используется для первоначального
   запуска. Runtime reload не вызывает её: для перехода используются отдельные
   `apply_egress_policy_routing`/`remove_egress_policy_routing` операции с
   disjoint route tables и priorities. Сетевой тест подтвердил rollback после
   nftables failure и сохранение чужих ресурсов.
3. Peer configs и DNS preflight выполняются до commit через backend registry;
   `TunnelHandle::replace_peers` атомарен в пределах одного device. Runtime
   выполняет последовательный multi-device commit и rollback, но глобально
   атомарного commit между несколькими device handles нет.
4. `Runtime` сохраняет полный authoritative `Config`, prepared peer snapshots
   и текущий routing plan. Динамически выделенные route table IDs/priorities
   сохраняются при peer-only и firewall-only reload.
5. Immutable AWG config сравнивается напрямую через PartialEq/Eq
   AmneziaWgConfig. Тип в текущем BoringTun уже реализует структурное равенство;
   форматирование Debug для проверки совместимости не используется.

| 2026-11-09 | Добавлена проверка совместимости candidate config для будущего reload | Метод `Config::validate_reload_compatibility` и regression tests; CI ещё не запускался | Проверено, полный CI 42808265342 |


Текущее поведение runtime reload:
- Разрешено менять peers, routing decisions/selectors/NAT, INPUT/OUTPUT firewall,
  `routing.mark_base` и набор egress-интерфейсов. Старый и новый routing mark
  ranges должны быть непересекающимися.
- При смене egress/marks allocator подбирает свободные route table IDs и
  ip-rule priorities. До nftables switch устанавливаются новые egress routes;
  nftables classifier переключается одной kernel transaction; старые routes
  удаляются только после успешного switch.
- Allocator сохраняет чужие route tables и ip rules, в том числе rules,
  ссылающиеся на table ID с иным priority/fwmark. При неизменных egress/marks
  действующие динамические table IDs/priorities переносятся в новый plan, чтобы
  последующие peer-only/firewall-only reload не пытались мигрировать routes.
- Порядок: candidate validation → peer/DNS preflight → staging новых routes →
  последовательный peer commit → nftables transaction → authoritative Config
  snapshot update → cleanup старых routes. Ошибки peer/nft приводят к rollback
  peers и staged routes; неуспешный rollback переводит daemon в fatal shutdown.
- Failure-injection ошибки route install, rollback нескольких peer devices и
  непрерывный WG/AWG packet traffic во время runtime reload подтверждены CI:
  runs 42714141354, 42720463290 и 42724351018 соответственно.
- **Conntrack decision identity реализована:** история решений сохраняется
  атомарной заменой приватного файла `/run/vpn-relay-netns-{inode}.marks`
  с проверкой владельца, типа файла, hard-link count и прав `0600`.
  Неизменившиеся решения сохраняют mark; новые решения получают ранее не
  использованный ID из отдельного namespace `0x5...`. Legacy marks `0x4...`
  загружаются и сохраняются для уже существующих conntrack entries, но новые
  решения их не используют. Поэтому upgrade без history-файла также не
  переинтерпретирует старые conntrack marks. Переполнение 4095 новых ID
  приводит к отказу reload, а не к повторному использованию.

| 2026-11-09 | Реализован runtime reload и интерфейс управления | Runtime сохраняет authoritative Config и предыдущие endpoint resolutions; выполняет preflight всех изменённых peer sets, sequential commit с rollback, atomic nftables replacement и fatal shutdown при rollback failure. Добавлены control socket операции `reload_config`/`replace_peers`, CLI `--reload`, README и network-namespace failure-injection test. CI 42698384452 подтвердил базовый runtime commit: tests, clippy, rustfmt, feature checks, AWG 3.1, netns packet tests и all-systems-go прошли; CLI и новые reload netns сценарии ожидают CI | Реализовано, ожидает расширенного CI |

| 2026-11-10 | Начата миграция policy-routing ресурсов при runtime reload | Добавлены поиск свободных route-table/rule-priority slots, staging новых egress routes до nftables switch, cleanup старых ресурсов после commit и rollback staged routes при ошибке nftables. Compatibility validation теперь разрешает смену mark_base/egress только при непересекающихся mark ranges. Netns test расширен миграцией с двух egress на один, с проверкой rollback и удаления старых routes. Полный CI ещё не прошёл; обнаруженная ошибка компиляции FatalRollback исправлена, rustfmt и CI требуют повторной проверки | Проверено, полный CI 42808265342 |


Дополнительная защита динамического выделения policy-routing ресурсов:
- При выборе route table проверяются не только существующие маршруты, но и любые чужие ip rules, ссылающиеся на этот table ID, даже если у них другой priority и fwmark.
- Netns regression test резервирует первый динамический table ID 11000 чужим маршрутом и правилом на priority 12000; reload обязан выбрать следующий свободный слот и сохранить чужие ресурсы без изменений.


| 2026-11-10 | Подтверждена миграция policy-routing и сохранение dynamic slots | Run 42705792288: rustfmt, clippy, check_features, tests, AWG 3.1, isolated namespace reload/failure injection, bidirectional WG/AWG traffic и packet-level multi-uplink — success; all-systems-go success. Windows job skipped | Подтверждено CI |


| 2026-11-10 | Стабилизирована идентичность conntrack decisions между reload и restart | История decision marks сохраняется на диск атомарно; старые `0x4...` marks остаются валидными, новые выделяются из отдельного `0x5...` namespace. Добавлены тесты на стабильность при перестановке правил, сохранение legacy marks, запрет повторного использования, повреждённые/небезопасные state files. CI run 42708944656 на commit 24b799a: rustfmt, clippy, check_features, tests, AWG 3.1, integration-tests и all-systems-go — success; Windows job skipped | Подтверждено CI |

| 2026-11-10 | Подтверждён failure-injection тест ошибки staging policy route при reload | Run 42714141354: ip wrapper действительно блокирует candidate route replace; reload завершается ошибкой, daemon остаётся жив, старый nft classifier/route сохраняются, candidate rule/table удаляются | Подтверждено CI |


| 2026-11-10 | Подтверждена непрерывность WG/AWG packet traffic во время runtime reload | Run 42724351018: в обоих peer-traffic сценариях клиентский ICMP поток прошёл через полный server reload; проверены 60/60 ответов, живой daemon и post-reload ping. Все jobs и all-systems-go завершились success; Windows job skipped | Подтверждено CI |


| 2026-11-10 | Усилен стресс-тест непрерывного трафика при повторных reload | Commit 828b386; CI run 42725497030: для WG и AWG выполнены три последовательных nftables reload (add/remove/add независимого INPUT exception) на фоне 100 ICMP echo; проверены 100/100 ответов, daemon liveness и post-reload traffic. Все jobs и all-systems-go — success; Windows job skipped | Подтверждено CI |


| 2026-11-10 | Добавлен failure-injection тест ошибки cleanup старых policy routes после nftables switch | Netns integration test принудительно ломает удаление старого IPv4 route после успешного переключения nftables; проверяет fatal response, завершение daemon и повторную очистку старого и нового routing plan при Drop, включая восстановление forwarding и удаление TUN. CI run 42727974982: все обязательные jobs и all-systems-go — success; Windows job skipped | Подтверждено CI |


| 2026-11-10 | Усилены проверки multi-device peer rollback | Успешный rollback теперь проверяет восстановление обоих device snapshots; неуспешный rollback проверяет фактическое смешанное состояние (candidate peer на первом device, old peer на втором), которое требует fatal shutdown и запрещает публикацию candidate config. CI run 42727974982: tests, clippy, rustfmt, check_features, integration-tests, AWG 3.1 и all-systems-go — success; Windows job skipped | Подтверждено CI |


| 2026-11-10 | Прекращение обработки control socket после fatal transition | Runtime больше не дренирует очередь control socket после того, как reload привёл к fatal state: текущий запрос получает ошибку, затем accept loop прекращается, а run() немедленно переходит к Drop/shutdown. Netns test дополнительно проверяет, что после fatal exit повторная команда reload не может подключиться к control socket | Подтверждено CI, run 42730792684 |


| 2026-11-10 | Проверены daemon-level ограничения reload | Добавлен regression test: изменение nft table, владения IP forwarding и log level отклоняется как lifecycle-incompatible; изменение stats interval разрешено и проходит полную валидацию | Подтверждено CI, run 42730792684 |


| 2026-11-10 | Расширены regression tests immutable interface reload parameters | Отдельно проверяются изменения tunnel address, MTU, IPv6 gating, UDP listen port и tunnel type; candidate config проходит validate(), а reload compatibility обязан отклонить каждый lifecycle-incompatible diff. Дополнительно проверяется запрет удаления интерфейса | Подтверждено CI, run 42731867449 |


| 2026-11-10 | Проверена неизменяемость tunnel type и состава интерфейсов при reload | Добавлены валидные candidate configs для преобразования AWG-интерфейса в WireGuard и удаления интерфейса; оба варианта должны быть отклонены compatibility guard до runtime mutation | Проверено, полный CI 42808265342 |


| 2026-11-10 | Устранено сравнение AWG-параметров через Debug | Compatibility guard теперь использует структурное сравнение AmneziaWgConfig через реализованные PartialEq/Eq; устаревшее ограничение в плане разработки исправлено | Проверено, полный CI 42808265342 |


| 2026-11-10 | Усилены проверки безопасности conntrack mark state persistence | Проверено, полный CI 42808265342 |


| 2026-11-10 | Устранена TOCTOU-гонка при чтении conntrack mark state | Проверено, полный CI 42808265342 |


| 2026-11-10 | Добавлены граничные тесты формата и размера conntrack state | Проверяется отказ до десериализации для файла больше 4 MiB, отказ на malformed JSON и на неподдерживаемую версию state format; ожидает CI | Проверено, полный CI 42808265342 |


| 2026-11-10 | Защищён startup при двойной ошибке включения forwarding и rollback | Если включение IPv6 forwarding и восстановление исходного IPv4 forwarding оба завершаются ошибкой, startup теперь возвращает fatal transition и сохраняет установленную fail-closed nftables policy вместо её удаления. Добавлен unit test с инъекцией обеих ошибок; ожидает CI | Проверено, полный CI 42808265342 |


| 2026-11-10 | Исправлен rustfmt после fail-closed forwarding rollback | CI run 42795160585 выявил только форматирование двух match arms в failure-injection тесте; код и остальные обязательные jobs прошли, integration-tests ещё выполнялся на момент проверки. Исправлено форматирование без изменения логики; ожидается повторный CI | Проверено, полный CI 42808265342 |


| 2026-11-10 | Сделана fail-closed очистка при startup rollback и shutdown | Очистка policy-routing теперь возвращает ошибки вместо их игнорирования; если rollback добавленных правил/маршрутов не удался, startup сохраняет nftables policy и завершает запуск как fatal transition. При штатном Drop firewall снимается только после успешной очистки retired/active routes и восстановления исходных IPv4/IPv6 forwarding значений; при любой ошибке защиты nftables остаётся на месте. Удаление nftables также возвращает диагностируемую ошибку. Ожидает CI | Проверено, полный CI 42808265342 |


| 2026-11-10 | Закрыт startup forwarding rollback при ошибке очистки policy routes | Дополнительно обработан путь отказа включения forwarding: если удаление уже установленных policy rules/routes не удалось, daemon возвращает fatal transition и не снимает nftables policy; при ошибке удаления firewall также возвращается fatal transition. Добавлен тест, подтверждающий попытку восстановления обоих sysctl и агрегацию обеих ошибок | Проверено, полный CI 42808265342 |


| 2026-11-10 | Добавлен netns regression test fail-closed shutdown при ошибке удаления policy rule | В изолированном network namespace запускается daemon с ip-wrapper, который начинает отклонять удаление IPv4 socket rules только после успешного старта. При graceful SIGTERM проверяется, что Drop восстанавливает forwarding, оставляет неочищенное правило и сохраняет nftables policy; лог обязан содержать сообщение о fail-closed cleanup. Тест вручную удаляет оставленную policy перед завершением namespace | Проверено, полный CI 42808265342 |


| 2026-11-10 | Ошибки удаления устаревших IPv6 policy resources больше не игнорируются | При применении routing plan с IPv6-disabled egress очистка оставшихся IPv6 fwmark rules и default routes теперь проверяет результат каждой операции. Отсутствующие записи считаются уже очищенными; реальные ошибки приводят к отказу установки плана и запускают существующий rollback, не позволяя заявить IPv6 isolation при оставшемся stale route | Проверено, полный CI 42808265342 |


| 2026-11-10 | Устранено игнорирование ошибок замены policy rules и усилено восстановление forwarding | Удаление прежних socket/egress fwmark rules перед установкой теперь проходит через idempotent cleanup helper; реальные ошибки передаются в rollback вместо молчаливого продолжения. При ошибке включения IPv6 forwarding runtime пытается восстановить исходные значения обоих семейств; если восстановление любого семейства не удалось, startup оставляет nftables policy. Добавлен тест IPv6 restore failure наряду с проверкой IPv4 restore failure | Проверено, полный CI 42808265342 |


| 2026-11-10 | Защищён startup при неопределённом результате включения IPv4 forwarding | Ошибка записи `net.ipv4.ip_forward=1` теперь также запускает восстановление обоих исходных sysctl. Если восстановление любого семейства не удалось, startup завершает работу как fatal transition и сохраняет nftables policy. Добавлен failure-injection тест, в котором IPv4 enable и последующее IPv6 restore завершаются ошибками | Проверено, полный CI 42808265342 |


| 2026-11-10 | Гарантировано ожидание nft subprocess при ошибке записи policy script | В `apply_nft` ошибка записи в stdin раньше немедленно возвращала управление, оставляя дочерний процесс без явного ожидания. Теперь stdin закрывается при ошибке и выполняется `wait_with_output`, чтобы nft завершился и был reap-нут даже при broken pipe; исходная ошибка записи сохраняется для диагностики. Проверки rustfmt/tests/clippy и network-namespace integration ожидают CI | Проверено, полный CI 42808265342 |


| 2026-11-10 | Расширены shutdown forwarding failure-injection тесты для IPv4 и IPv6 | Два независимых namespace сценария отклоняют восстановление одного семейства после SIGTERM. Каждый проверяет, что nftables policy сохраняется, второе семейство forwarding успешно восстанавливается, а журнал содержит причину и fail-closed сообщение; после проверок тесты вручную возвращают sysctl и удаляют policy. CI 42801604865: integration-tests и all-systems-go success | Проверено, CI 42801604865 |


| 2026-11-10 | Добавлен предельный timeout для CI integration-tests | Job `integration-tests` ограничен 45 минутами; предыдущий run 42798780332 оставался на шаге `cargo test -- --ignored` более 20 минут. Новый timeout включён и подтверждён последующими успешными integration runs 42801604865 и 42804880491. | Проверено, CI 42804880491 |

| 2026-11-10 | Ограничено время выполнения ignored integration suite | Шаг `cargo test -- --ignored` имеет 15-минутный watchdog и принудительное завершение через 30 секунд после TERM; общий integration job ограничен 45 минутами. Оба ограничения подтверждены успешным прохождением ignored suite в CI 42801604865 и 42804880491. | Проверено, CI 42804880491 |

| 2026-11-10 | Проверен неопределённый результат IPv4 forwarding enable и двойной отказ rollback | Netns test моделирует sysctl, который сначала применяет `ip_forward=1`, а затем возвращает ошибку; проверяет восстановление обоих семейств и полную очистку. Отдельный сценарий ломает восстановление IPv6 и подтверждает сохранение fail-closed nftables policy при удалённых TUN/routes. CI 42804880491: полный integration job success. | Проверено, CI 42804880491 |

| 2026-11-10 | Проверено сохранение forwarding, включённого до запуска daemon | Netns lifecycle сценарий начинает с IPv4 и IPv6 forwarding=1, запускает vpn-relay, проверяет firewall/TUN readiness и штатный SIGTERM. После shutdown оба исходных значения остаются включёнными, а daemon-owned nftables и TUN links удалены. Проверено integration step в CI 42806204631. | Проверено, CI 42806204631 |

| 2026-11-10 | Устранён orphan control socket при ошибке post-bind настройки | Если установка mode 0600 или nonblocking listener завершается ошибкой, созданный Unix socket path очищается. Unit test с инъекцией ошибки подтвердил отсутствие stale path в tests job CI 42806204631. | Проверено tests job, CI 42806204631 |

| 2026-11-10 | Проверена настройка manage_ip_forwarding=false | Namespace test использует исходные значения IPv4=1 и IPv6=0 и проверяет startup/SIGTERM при отключённом управлении forwarding. Оба значения остались неизменными, daemon-owned TUN и nftables policy удалены; integration step CI 42806204631 success. | Проверено, CI 42806204631 |

| 2026-11-10 | Усилено владение control socket path при cleanup | ControlSocket запоминает device/inode созданного Unix socket и при Drop удаляет путь только если он всё ещё указывает на тот же socket. Regression test с заменой socket path на обычный файл подтвердил сохранность чужого объекта в tests job CI 42806204631. | Проверено tests job, CI 42806204631 |

| 2026-11-10 | Документировано глобальное воздействие manage_ip_forwarding | README, NFT lifecycle docs и пример конфигурации теперь предупреждают, что включение меняет namespace-wide IPv4/IPv6 forwarding и host/router поведение интерфейсов; рекомендуют dedicated network namespace или внешнее управление с `manage_ip_forwarding=false`. Per-interface forwarding вынесен в отдельную архитектурную задачу, чтобы не скрывать ограничение за обещанием восстановления только двух sysctl. | Документировано; архитектурная задача открыта |

| 2026-11-10 | Исправлено форматирование control socket ownership regression tests | CI runs 42806204631 и 42807204555 выявили rustfmt diff; форматирование исправлено без изменения логики и подтверждено полным CI run 42808265342. | Проверено, CI 42808265342 |

| 2026-11-10 | Проверен rollback при ошибке configure_interface после создания TUN | Новый failure-injection сценарий блокирует IPv4 address replace для первого AWG TUN уже после создания backend и поднятия link. Проверяется, что startup удаляет частично настроенный TUN, nftables policy и не меняет исходные forwarding sysctl. Ожидает CI | Проверено, полный CI 42808265342 |

| 2026-11-10 | Проверена подмена control socket path непосредственно во время bind | Unit test подменяет только что созданный Unix socket обычным файлом из configure callback. Bind отклоняет изменившуюся identity и сохраняет внешний файл; тест прошёл в tests job CI 42809930151. | Проверено, CI 42809930151 |

| 2026-11-10 | Ограничено время ожидания packet-level TCP/UDP probes | Все iperf3 client runs в multi-uplink integration test выполняются с timeout 15s. Изменение прошло полный integration job, включая packet-level multi-uplink routing, в CI 42810890525. | Проверено, CI 42810890525 |

| 2026-11-10 | Разобран CI 42817022304: исправление rustfmt и изоляция masquerade address-change probe | rustfmt выявил перенос фигурной скобки в config.rs; исправлено. Packet-level multi-uplink test показал отсутствие пакета после смены адреса при повторном использовании клиента .2; probe переведён на .3 для гарантированно нового conntrack tuple. Оба изменения ожидают повторной проверки полного CI | Ожидает CI |


### CI follow-up — 2026-11-10

- Run `42818275020`: `rustfmt`, unit tests, `clippy`, feature checks and AWG 3.1 interoperability passed; integration failed in the multi-uplink masquerade address-change probe because the temporary client `.3` had no matching routing decision for `203.0.113.1`. The fixture's matching selector is scoped to client `10.77.0.2/32`; the probe was returned to `.2`.
- Run `42819442900`: all non-integration jobs passed, but the address-change probe still failed. The diagnostic dump showed the primary policy route missing after the test removed the old IPv4 address.
- Follow-up run `42821344820`: adding `10.20.0.99/24` before deleting `10.20.0.1/24` was not sufficient. Linux treats the added same-prefix address as secondary; with the default `promote_secondaries=0`, deleting the primary address also removed the replacement. The failure dump confirmed that `awg-primary` had no IPv4 address and table 10000 had no primary default route.
- Fix: enable `net.ipv4.conf.awg-primary.promote_secondaries=1` in the isolated test namespace before adding the replacement address. Keep add-before-delete ordering, assert the replacement address remains, and assert the primary fwmark rule's route table still contains `default dev awg-primary` before sending the new ICMP flow. Keep client `.2`, ICMP identifier `4243`, and the packet-level assertion that the emitted source is `10.20.0.99`. The address-change check remains pending a successful integration CI run.

- Follow-up test isolation: the post-address-change ping also uses a distinct ICMP identifier (`4243`) so it cannot reuse conntrack NAT state established by the earlier masquerade probe. The preceding general masquerade probe uses identifier `4242`.


| 2026-11-10 | Подтверждён masquerade после смены egress IPv4 | CI run `42822336707` завершился success: все jobs, включая ignored integration suite, прошли. Проверка сохраняет secondary TUN address через `promote_secondaries=1`, подтверждает policy route и packet-level source NAT с новым адресом. | Проверено, полный CI `42822336707` |
| 2026-11-10 | Добавлена проверка идентичности исходного Linux TUN descriptor | `TUNGETIFF` проверяет привязку именно исходного FD, а не существование интерфейса с совпадающим именем. Runtime проверяет идентичность каждую секунду и перед reload; потеря/переименование исходного интерфейса переводит daemon в fatal shutdown. Числовые interface names отклоняются, поскольку BoringTun трактует их как переданные FD. Добавлен root-only ignored kernel integration test: удалить TUN и создать новый с тем же именем, после чего старый FD обязан остаться detached. | Ожидает CI |


## Привязка nftables к ifindex

При старте сначала применяется bootstrap policy по именам, пока TUN ещё не
созданы. После создания и настройки TUN runtime проверяет исходные дескрипторы
через `TUNGETIFF`, разрешает ifindex каждого интерфейса и повторяет проверку
дескриптора. Затем nftables-таблица атомарно заменяется вариантом с селекторами
`iif/oif` и наборами типа `iface_index`; policy routing устанавливается только
после переключения. Reload сохраняет индексы работающих интерфейсов.

Ifindex не является криптографической идентичностью и теоретически может быть
повторно использован ядром после удаления link. Поэтому numeric selectors
закрывают обычный сценарий подмены по имени, а периодический `TUNGETIFF`
остаётся обязательной дополнительной проверкой с fatal shutdown при detach.


### Bootstrap window

До создания TUN устанавливается не полноценная allow-policy, а drop-only
bootstrap: для имён всех управляемых интерфейсов присутствуют только deny
правила, без routing decisions, INPUT/OUTPUT exceptions и NAT. После создания
устройств, проверки исходных FD и получения ifindex bootstrap атомарно
заменяется рабочей policy. Таким образом, случайная подмена имени в период
создания интерфейсов не получает временного разрешения на forwarding.


### Same-name replacement guard and fatal shutdown

Indexed selectors alone do not deny a replacement interface: a new link with
the old name but a different ifindex would simply fall outside the managed
sets. The indexed policy therefore prepends per-interface name+index mismatch
guards to prerouting, input, forward (both directions) and output. A link with
a configured TUN name but a different index is explicitly dropped before any
allow rule. On fatal runtime transitions the daemon also retains nftables
policy after stopping workers and cleaning owned routes; only a normal,
successful shutdown removes the firewall.


Проверка подмены теперь выполняется и на уровне пакета: интеграционный сценарий
удаляет рабочий TUN, создаёт новое устройство с тем же именем и другим ifindex,
отправляет через него пакет, проверяет увеличение счётчика правила `counter drop`,
ожидает аварийного завершения daemon и подтверждает сохранение firewall.

| 2026-11-10 | Проверена защита от удаления и подмены TUN | `TUNGETIFF` на исходном FD; drop-only bootstrap; атомарный переход nftables с `iifname/oifname` на `iif/oif` + `iface_index`; mismatch guards с `counter drop`; root netns тест удаляет и пересоздаёт TUN под тем же именем, проверяет блокировку пакета и сохранение firewall после fatal shutdown. CI 42831549649: rustfmt, clippy, tests, feature checks, AWG 3.1, namespace, WG/AWG peer traffic и multi-uplink — success; Windows skipped. HEAD `bcbf0cfaeab1b74688281b3b0cef27f63580cb02`. | Завершено и проверено |

| 2026-11-10 | Закрыт основной packet-level firewall acceptance matrix | Полный CI run `42836214324` прошёл: IPv4/IPv6 INPUT/OUTPUT allow/deny, forged reply isolation для обоих направлений, socket-fwmark underlay, запрет новых потоков без routing decision, выбранная ingress/egress пара и TCP/UDP reverse traffic на обоих uplink. Отдельный полный CI `42831549649` подтвердил TUN identity replacement и masquerade после смены egress IPv4. | Проверено, полные CI `42836214324` и `42831549649` |

| 2026-11-10 | Добавлено durable восстановление forwarding после SIGKILL | Введён versioned `.forwarding` journal, привязанный к inode network namespace. Состояние записывается атомарно с mode 0600 и fsync до изменения sysctl; чтение защищено `O_NOFOLLOW` и проверками owner/mode/nlink/size/schema/namespace. Startup восстанавливает только реально изменённые семейства и удаляет journal лишь после успешного восстановления; при ошибке запись сохраняется. Добавлены unit tests round-trip, namespace mismatch, corrupt JSON, dangling symlink и идемпотентное recovery. Netns test проверяет SIGKILL/restart, восстановление forwarding, policy rules/routes/TUN и штатный shutdown. | Полный CI `42849072652`: tests, clippy, rustfmt, feature checks, namespace lifecycle, WG/AWG peer traffic, multi-uplink и AWG 3.1 — success; Windows skipped. HEAD `b4c7197897f6b5b8eed1799b1ad6ab209971c8a2` |

| 2026-11-10 | Закрыты дополнительные отрицательные parser cases | Добавлены regression tests на пустые INPUT/OUTPUT CIDR selectors, неизвестный firewall interface, пустой/нулевой port list, ports с ICMP и пустой routing destination. `Config::validate` отклоняет каждую конфигурацию до создания системных ресурсов. | Полный CI `42851385258`: tests, clippy, rustfmt, feature checks, namespace lifecycle, WG/AWG peer traffic, packet-level multi-uplink и AWG 3.1 — success; Windows skipped. HEAD `db71837251551026beb0a8fa6b58a11867bb521a` |
\n| 2026-11-10 | Расширена матрица rollback и исправлен двойной cleanup policy routing | Проверены все четыре границы установки IPv4/IPv6 route/rule; добавлена проверка агрегирования восьми cleanup failures на двух интерфейсах. Внешний rollback policy routing теперь очищает только socket fwmark rules: egress rollback остаётся ответственностью вложенного apply_egress_policy_routing_with, что исключает повторные удаления и не маскирует исходную ошибку. Добавлена failure-injection проверка вложенного rollback с ошибкой очистки и подтверждением, что все socket rules всё равно удаляются. Ожидает полного CI. | Реализовано, ожидает CI |\n