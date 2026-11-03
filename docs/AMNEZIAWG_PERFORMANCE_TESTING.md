# Тестирование производительности туннеля AWG

Workflow `AWG Performance Benchmarks` — дополнительный benchmark, не блокирующий обязательные PR checks. Его можно запустить вручную через **Actions → AWG Performance Benchmarks → Run workflow**. Workflow также запускается при изменении своего YAML, harness или этого документа в main.

## Методика

Workflow собирает BoringTun и закреплённую версию официального `amneziawg-go`, создаёт изолированные Linux network namespaces и измеряет зашифрованный туннель через iperf3.

Каждому endpoint назначается уникальное имя интерфейса даже при использовании одной реализации на обеих сторонах: UAPI-сокеты Linux WireGuard создаются в host `/var/run` и не изолируются network namespaces. Повторное имя интерфейса приводит к конфликту сокетов.

Производительность измеряется отдельно для однородных пар:
- `amneziawg-go` client ↔ `amneziawg-go` server;
- `boringtun-awg` client ↔ `boringtun-awg` server.

Это позволяет не смешивать накладные расходы datapath с межреализационной совместимостью.

## Сценарии измерений

- Vanilla WireGuard baseline.
- AWG 2.x baseline как контроль общей S/H-обфускации.
- Изолированные профили: HeaderProtectionKey, ContentPaddingAddition, RandomTrailers и DisableCookies.
- Профиль только с randomized timers.
- Полный профиль AWG 3.1 со всеми расширениями.
- Однородные пары amneziawg-go ↔ amneziawg-go и BoringTun ↔ BoringTun.
- Оба направления передачи данных.
- TCP: один поток, 5 секунд для каждого направления.
- UDP: целевые 100 Mbit/s для baseline и полного профиля, 5 секунд.

Текущая матрица содержит 10 профилей и 48 iperf3 measurements: 40 TCP + 8 UDP. Run 41716049376 завершил все 20 профильных прогонов (10 профилей × обе реализации/роли) успешно. Четырёхпоточный TCP удалён из диагностического benchmark: сначала нужно локализовать эффект отдельных расширений на базовом одном потоке. JSON-отчёты содержат throughput приёмника, байты, TCP retransmissions и UDP packet loss. В benchmark-режиме PCAP вообще не записывается: wire/PCAP проверяется отдельной interoperability-матрицей. Поэтому artifact содержит только компактные JSON-отчёты.

## Изолированный benchmark: результаты и выводы

[Run 41716049376](https://github.com/lelikulibina/boringtun-awg/actions/runs/41716049376) завершился успешно: **20/20 профильных прогонов**, 40 TCP и 8 UDP измерений. Полный benchmark job занял около 5 минут; это отдельная диагностическая задача, не PR merge gate. Artifact содержит только JSON и занимает **9 882 байта**; PCAP с iperf3 datapath не создаётся.

Результаты TCP (Mbit/s, client→server / server→client):

| Профиль | amneziawg-go | BoringTun |
|---|---:|---:|
| Vanilla WireGuard | 4 079 / 4 442 | 603 / 602 |
| AWG 2.x baseline | 9,22 / 9,85 | 398 / 383 |
| AWG 2.x J-only | 4 318 / 4 259 | 602 / 598 |
| AWG 2.x S/H-only | 9,22 / 13,84 | 399 / 386 |
| HeaderProtectionKey | 12,37 / 19,29 | 390 / 388 |
| ContentPaddingAddition | 13,84 / 13,21 | 395 / 398 |
| RandomTrailers | 10,06 / 12,37 | 392 / 392 |
| DisableCookies | 11,11 / 15,09 | 397 / 394 |
| Только randomized timers | 5,24 / 14,47 | 372 / 373 |
| Все расширения AWG 3.1 | 10,48 / 12,37 | 368 / 358 |

**Причина upstream Go TCP-регрессии локализована в S/H-параметрах AWG 2.x, а не в J-параметрах или отдельных расширениях AWG 3.1.** J-only профиль с Jc/Jmin/Jmax сохраняет почти vanilla throughput: 4,26–4,32 Gbit/s. S/H-only профиль с S1–S4/H1–H4 воспроизводит падение до 9–14 Mbit/s — практически тот же результат, что и полный AWG 2.x baseline. Следовательно, общий источник деградации — обработка S/H packet-length и header-marker obfuscation в upstream Go datapath. Нельзя приписывать её HeaderProtectionKey, ContentPaddingAddition, RandomTrailers или DisableCookies: каждый из них лишь работает поверх уже деградирующего legacy S/H path.

У BoringTun разница иная: J-only остаётся на уровне vanilla (около 598–602 Mbit/s), а S/H-only и AWG 2.x дают 383–399 Mbit/s. Полный AWG 3.1 профиль даёт 358–368 Mbit/s. Это умеренное снижение относительно vanilla, а не аналогичная катастрофическая деградация Go.

UDP 100 Mbit/s в vanilla и полном AWG 3.1 профиле обеих реализаций показал 99,99 Mbit/s и 0% потерь. Результаты — короткие 5-секундные измерения на GitHub-hosted runner, а не гарантия абсолютной производительности; TCP retransmissions в BoringTun высоки и заметны даже в vanilla, поэтому абсолютные throughput числа следует сравнивать только внутри одного запуска.

## Исторический baseline

[AWG Performance Benchmarks, run 41629778226](https://github.com/lelikulibina/boringtun-awg/actions/runs/41629778226) на HEAD `115a6c35d59a626e4c1f0f074b652618ff2f7092` завершился успешно:

- сборка BoringTun и upstream Go reference — success;
- все 4 комбинации реализации/профиля — success;
- **24 iperf3 measurements** завершены;
- отчёты и соответствующие PCAP загружены как artifact [`awg31-iperf3-performance`](https://github.com/lelikulibina/boringtun-awg/actions/runs/41629778226).

Workflow подтверждает работоспособность benchmark harness и завершение измерений. В этом документе намеренно не приводятся численные выводы о превосходстве одной реализации: сравнивать следует JSON-отчёты одного и того же запуска. Абсолютные значения на GitHub-hosted runner зависят от нагрузки и виртуализации.

**Оговорка по актуальности:** этот benchmark запускался на базовом кодовом HEAD `115a6c35d59a626e4c1f0f074b652618ff2f7092`, до последующего UAPI/AllowedIPs follow-up. Финальный PR CI на HEAD `25dcf432296f8f3cc52d76c889b60e8d5087d0b9` проверил корректность и interoperability, но performance workflow после этих follow-up изменений отдельно не перезапускался. Поэтому 24 измерения подтверждают работу методики и baseline, а не являются performance-регрессией для окончательного HEAD.

## Интерпретация

Сравнивайте:
1. Go и BoringTun внутри одного профиля;
2. AWG 3.1 и vanilla WireGuard внутри каждой реализации;
3. оба направления и все три режима трафика.

Для релизных выводов повторяйте benchmark на одном и том же выделенном runner и сравнивайте медианы нескольких запусков. Один запуск на GitHub-hosted runner не является стабильной гарантией производительности.

Benchmark намеренно отделён от обязательного PR CI: throughput зависит от среды и не должен делать проверки корректности flaky.


## Текущий статус расследования

Диагностический workflow включает AWG 2.x control, timers-only, J-only и S/H-only профили. Текущая версия — 10 профилей, 48 iperf3 измерений. Последний прогон 41716049376 завершился 20/20. Запускать через **Actions → AWG Performance Benchmarks → Run workflow**; результаты сравнивать внутри одного запуска и в обоих направлениях.
