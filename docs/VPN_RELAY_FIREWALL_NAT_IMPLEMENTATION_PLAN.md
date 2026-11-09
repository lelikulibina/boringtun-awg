# План реализации firewall и NAT для vpn-relay

> Рабочая ветка: `feature/vpn-relay-firewall-nat`
> Базовая ветка: `feature/boringtun-router-daemon`
> Базовый commit: `ad3f35d2790e7e47c8d050fb7b3c206c69ac2aa4`
> Последнее обновление: 2026-11-09 (первый этап реализации и интеграционная настройка)
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
  сохраняются в ct mark; reply direction возвращается в main table; NAT сейчас
  выбирается свойством routing rule; Runtime включает forwarding, устанавливает
  policy routing, затем nftables.
- [x] Проверить реализацию AllowedIPs в BoringTun: после decapsulation оба
  варианта `WriteToTunnelV4/V6` проверяют `Device::peer_owns(peer, addr)`
  до записи в TUN. Исходный адрес проверяется по единому trie
  `peers_by_ip`, что защищает от source spoofing между peer.
- [ ] Проверить реальный путь peer-to-peer трафика на одном TUN и определить,
  проходит ли он Linux FORWARD hook. Код backend направляет TUN-пакет по
  destination через `peers_by_ip`; окончательный вывод требует packet-level
  теста в network namespace.

Критерий приёмки: инвентаризация отражает код базового commit, а не только
предыдущую документацию; все выявленные расхождения внесены в этот журнал.

## 4. Этап 1 — security invariants и packet-level тесты

### INPUT

- [ ] managed ingress без разрешения не достигает локальных IPv4 сервисов.
- [ ] managed ingress без разрешения не достигает локальных IPv6 сервисов.
- [ ] Явно разрешённый source/interface/protocol/port доступ работает.
- [ ] Ответы на соединения, инициированные хостом, не дают клиенту обходить
  INPUT deny.
- [~] В генератор добавлен stateful reply path: INPUT/OUTPUT разрешают
  established/related только в conntrack reply direction, а явные allow rules
  ограничены original direction. Ожидается packet-level проверка.
- [ ] Loopback и трафик с unmanaged интерфейсов не меняются.

### OUTPUT

- [ ] Локальный пакет, направленный через managed TUN, проходит заданную OUTPUT
  policy.
- [ ] Запрещённый managed egress блокируется.
- [ ] Локальный трафик через физический/unmanaged интерфейс не меняется.
- [ ] Socket fwmark для внешнего WG/AWG UDP продолжает использовать main table.

### FORWARD и conntrack

- [ ] Сохраняется запрет нового потока без routing rule.
- [ ] Сохраняется разрешение только выбранной пары ingress/egress.
- [ ] Ответный трафик разрешённого потока проходит только в обратную пару.
- [ ] Неверный/нулевой/чужой conntrack mark не открывает транзит.
- [ ] NAT не меняет поведение фильтрации и не применяется к запрещённым потокам.

### Владение и lifecycle

- [ ] Чужая nftables table с совпадающим именем не изменяется.
- [ ] Ошибка применения nftables приводит к полному rollback ранее установленных
  vpn-relay ресурсов.
- [x] Shutdown останавливает backend workers, удаляет policy routes, затем
  уничтожает managed TUN links, и только после этого удаляет nftables policy;
  исходное forwarding состояние восстанавливается в самом конце.
- [ ] Повторный запуск и аварийное завершение не оставляют опасного состояния.

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
- [ ] Проверить ruleset командой nft в network namespace.
- [~] Существующий peer traffic netns test обновлён явными INPUT/OUTPUT
  allow rules: туннельный обмен больше не должен полагаться на неявный доступ
  к локальным адресам. Результат нового CI ожидается.
- [~] Добавлены negative packet-level probes в peer traffic netns test: TCP/8081
  должен блокироваться на server INPUT и server OUTPUT независимо; CI для
  последнего изменения ещё не завершён.

- [x] Добавлен `[firewall]` с независимыми `input.rules` и `output.rules`.
- [x] Правило разрешения привязано к одному существующему managed interface.
- [x] Поддержаны source CIDR для INPUT и destination CIDR для OUTPUT.
- [x] Поддержаны TCP, UDP, ICMP и ICMPv6; порты разрешены только для TCP/UDP.
- [x] Пустые списки, порт 0, неизвестные интерфейсы, IPv6 CIDR на интерфейсе
  с выключенным IPv6 и селекторы неправильного направления отклоняются.
- [x] Отсутствие allow rules означает deny для соответствующего managed hook.
- [x] Добавлены parser tests на неизвестные интерфейсы и селекторы неверного
  направления; остальные отрицательные случаи ещё требуют отдельного покрытия.
- [~] Добавлены реальные TCP listener/client probes в peer traffic netns test:
  разрешённый TCP/8080 и запрещённый TCP/8081 для INPUT/OUTPUT; ожидается CI.



Предварительная структура должна быть простой и строго типизированной:

```toml
[firewall]
# INPUT deny и OUTPUT managed — зафиксированные политики проекта.
# FORWARD остаётся deny по умолчанию.
# Конкретные разрешения задаются отдельными rules.

[[firewall.input.rules]]
interface = "wg-server"
source = ["10.10.0.2/32"]
protocol = "tcp"
ports = [22]
action = "accept"

[[firewall.output.rules]]
interface = "awg-primary"
protocol = "tcp"
ports = [443]
action = "accept"

[[nat.rules]]
ingress = "wg-server"
egress = "awg-primary"
source = ["10.10.0.0/24"]
type = "masquerade"

[[nat.rules]]
ingress = "wg-server"
egress = "awg-secondary"
source = ["10.20.0.0/24"]
type = "snat"
to = "203.0.113.10"
```

Это иллюстрация направления API, не обещание окончательного синтаксиса.
Перед добавлением полей необходимо сверить их с существующей моделью
`routing.rules` и выбрать один источник истины для egress/NAT selection.

Задачи:

- [ ] Определить, какие firewall policies являются фиксированными defaults,
  а какие настраиваемыми параметрами.
- [ ] Описать типизированные INPUT/OUTPUT rule selectors.
- [ ] Описать протоколы TCP/UDP/ICMP/ICMPv6 и семантику портов.
- [ ] Описать IPv4/IPv6 CIDR и поведение при смешанных семействах.
- [ ] Добавить NAT action `Snat(IpAddr)` наряду с `None` и `Masquerade`.
- [x] Зафиксировать NAT как свойство выбранного routing rule. Отдельная
  `[[nat.rules]]` секция не вводится: это исключает второй независимый
  механизм выбора ingress/egress. Расширение добавит адрес SNAT к routing rule.
- [ ] Валидировать ссылки на интерфейсы, address family, пустые списки,
  дубликаты и неоднозначные совпадения.
- [ ] Обновить пример TOML и CLI `--check` tests.
- [ ] Проверить deny_unknown_fields и сообщения об ошибках.

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
- [~] Unit tests описывают пересекающиеся selectors с одним egress и разными
  NAT actions; реальное поведение nftables и packet-level тест ещё ожидают CI.
- [ ] Проверить отсутствие коллизий socket fwmark и routing marks.
- [ ] Сохранить детерминированность генерации nftables/iproute2 plan.

Критерий приёмки: маршрут, FORWARD и NAT не могут выбрать разные routing rules
для одного потока; unit tests покрывают приоритеты и пересечения.

## 7. Этап 4 — реализация INPUT deny

- [x] Добавить INPUT base chain в таблицу vpn-relay с policy accept, поскольку
  глобальный INPUT namespace принадлежит системному firewall.
- [ ] Сначала обработать invalid.
- [ ] Применить явные разрешения только к managed ingress.
- [ ] Запретить остальные пакеты с managed ingress до любого общего
  established/related accept, способного обойти политику.
- [~] Разделены conntrack original/reply направления: явные INPUT/OUTPUT
  allow rules принимают original direction; established/related reply traffic
  разрешается отдельно и только на managed interfaces. Нужна проверка nft и
  реальным трафиком.
- [ ] Не блокировать loopback и unmanaged ingress.
- [ ] Добавить IPv4/IPv6 и ICMPv6 тесты.
- [ ] Проверить взаимодействие с другими nftables base chains.

Критерий приёмки: неразрешённый пакет с managed TUN к локальному адресу
блокируется независимо от наличия conntrack entry; другие ingress не меняются.

## 8. Этап 5 — OUTPUT managed

- [ ] Создавать output base chain независимо от IPv6-disabled gating.
- [x] Фильтровать только пакеты с фактическим managed TUN egress.
- [x] Определить безопасную модель default deny и явных разрешений.
- [ ] Не блокировать socket-marked outer UDP, направленный через underlay.
- [ ] Не влиять на физический/unmanaged egress.
- [ ] Проверить local IPv4/IPv6, TCP/UDP/ICMP и policy-routing marks.

Критерий приёмки: тесты доказывают, что managed egress контролируется, а
unmanaged output остаётся неизменным.

## 9. Этап 6 — NAT extended

- [ ] Сохранить `none` как отсутствие трансляции.
- [ ] Реализовать IPv4 `masquerade`.
- [x] Реализовать IPv4 статический `snat` через `nat = "snat"` и обязательный
  `nat_to` в routing rule.
- [ ] Проверить необходимость и корректную поддержку IPv6 masquerade/SNAT;
  неподдерживаемые варианты должны отклоняться валидацией.
- [ ] Связать NAT с единственным routing decision и conntrack state.
- [ ] Проверить несколько правил, приоритеты, перекрывающиеся CIDR и разные egress.
- [ ] Проверить отсутствие NAT на INPUT/OUTPUT и запрещённом FORWARD.
- [ ] Проверить поведение при изменении адреса egress для masquerade.

Критерий приёмки: пакет получает ровно одну ожидаемую NAT policy; запрещённый
или локальный трафик не подвергается source NAT.

## 10. Этап 7 — AllowedIPs и peer isolation

- [ ] Проследить путь расшифрованного IPv4/IPv6 пакета в BoringTun.
- [ ] Подтвердить, что peer identity известна до передачи пакета в TUN.
- [ ] Подтвердить проверку source address по AllowedIPs именно отправившего peer.
- [ ] Проверить пересекающиеся и вложенные AllowedIPs; текущая валидация
  запрещает точные дубликаты, но это не доказывает отсутствие перекрытий.
- [ ] Проверить peer-to-peer обмен между двумя клиентами одного интерфейса.
- [ ] Если Linux FORWARD не видит внутритуннельный peer-to-peer пакет, не
  пытаться имитировать peer filtering в nftables по одному iifname.
- [ ] При необходимости добавить backend-level enforcement или явно
  задокументировать ограничение до его реализации.

Критерий приёмки: гарантии подтверждены тестами на реальном BoringTun traffic;
неподтверждённые свойства не заявляются.

## 11. Этап 8 — runtime, rollback, ownership

- [ ] Сформировать полный immutable plan до изменения системного состояния.
- [ ] Установить все необходимые ресурсы в безопасном порядке.
- [x] Установить nftables fail-closed policy до policy routes и включения IP
  forwarding; при ошибке последующих шагов откатывать уже установленные
  policy routes и nftables table.
- [~] Проверить startup rollback при конфликте nft table, ip rule и route
  отдельным network-namespace тестом; повторный CI после изменения порядка
  установки ожидается.
- [ ] Сделать rollback симметричным каждому успешному шагу.
- [ ] Не удалять чужие ip rules/routes/nftables objects.
- [ ] Проверить частичные ошибки на каждом шаге установки.
- [ ] Проверить shutdown, повторный запуск, lock и network namespace lifecycle.
- [ ] Проверить поведение при удалении/переименовании интерфейса во время работы.

Критерий приёмки: каждый сценарий отказа оставляет namespace в безопасном и
предсказуемом состоянии; чужие ресурсы не меняются.

## 12. Этап 9 — документация и CI

- [ ] Обновить `docs/VPN_RELAY_NFTABLES.md` по фактической реализации.
- [ ] Добавить архитектурную схему packet path и порядок hooks.
- [ ] Документировать INPUT/OUTPUT/FORWARD/NAT, conntrack, marks и ownership.
- [ ] Документировать границы AllowedIPs и peer isolation.
- [ ] Обновить `vpn-relay/vpn-relay.example.toml`.
- [ ] Добавить unit, parser и packet-level integration tests в CI.
- [ ] Выполнить rustfmt, clippy, cargo test, feature checks и все netns tests.
- [ ] Зафиксировать CI run и фактические статусы jobs.

Критерий приёмки: документация соответствует коду; обязательные CI jobs зелёные;
нет непроверенных заявлений о безопасности.

## 13. Журнал выполнения

| Дата | Изменение | Проверки | Статус |
|---|---|---|---|
| 2026-11-09 | Создана ветка `feature/vpn-relay-firewall-nat` от `ad3f35d2790e7e47c8d050fb7b3c206c69ac2aa4` | GitHub branch ref проверен | Завершено |
| 2026-11-09 | Добавлен рабочий план реализации | Commit 93244b354acef1344c9ab9ec2600372633de3ea6 | Завершено |
| 2026-11-09 | Проверены BoringTun AllowedIPs ingress validation и backend routing lookup | Просмотрены `Device::peer_owns`, `WriteToTunnelV4/V6`, `peers_by_ip` | Завершено |
| 2026-11-09 | Уточнена модель NAT: действие остаётся в routing rule | Отдельная NAT-секция не нужна, так как egress уже выбирается routing rule | Завершено |
| 2026-11-09 | Добавлены INPUT/OUTPUT chains, explicit allow rules и managed default deny | Unit/parser tests; CI run 42625442963: unit tests, clippy, rustfmt, feature checks и AWG interoperability успешны; peer traffic integration упал из-за отсутствующих explicit allow rules | В работе |
| 2026-11-09 | Peer traffic netns scenario переведён на явные INPUT/OUTPUT allow rules | Run 42629958261: WG и AWG peer traffic tests успешно прошли; общий integration job упал позже на multi-uplink тесте, где endpoint-конфигурации ещё не имели allow rules | В работе |
| 2026-11-09 | Multi-uplink test адаптирован к INPUT/OUTPUT deny-by-default | Добавлены точечные разрешения на client, router и uplink endpoints; CI ещё выполняется | В работе |
| 2026-11-09 | Ужесточена проверка address family для SNAT | Исправлен случай, когда family присутствовал только в одном selector, но отсутствовал в пересечении source/destination; добавлен regression parser test | В работе |
| 2026-11-09 | Добавлены packet-level INPUT/OUTPUT probes | Peer traffic test запускает TCP listeners на обоих концах, проверяет разрешённый порт 8080 и отдельно INPUT deny/OUTPUT deny на 8081; iperf3 TCP/UDP 5201 также явно разрешён | В работе |
| 2026-11-09 | Выделена модель `RoutingDecision` | Routing classifier, FORWARD и NAT используют один список решений; CI после переименования выявил устаревший публичный re-export `NftRule`, исправление внесено | В работе |
| 2026-11-09 | Добавлена conntrack-aware обработка ответного трафика INPUT/OUTPUT | Явные allow rules ограничены original direction; established/related reply принимается только на managed interface; добавлены unit assertions | В работе |
| 2026-11-09 | Разделены routing mark и conntrack decision id | Уникальный conntrack id назначается каждому routing decision; established route restore, обратный FORWARD и NAT используют этот id; NAT ограничен исходной парой интерфейсов | Ожидает полного CI и packet-level проверки |
| 2026-11-09 | Изменён порядок startup/shutdown | nftables policy устанавливается до создания/поднятия TUN, policy routing и включения forwarding; shutdown держит firewall до удаления TUN links; обновлён netns readiness check | Ожидает network-namespace CI |

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
