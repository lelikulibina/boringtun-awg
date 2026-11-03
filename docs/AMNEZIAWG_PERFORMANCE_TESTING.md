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

Текущая матрица содержит 10 профилей и 48 iperf3 measurements: 40 TCP + 8 UDP. Run 41709590826 проверял предыдущие 8 профилей (40 измерений); в следующем запуске добавлены J-only и S/H-only legacy controls. Четырёхпоточный TCP удалён из диагностического smoke-benchmark: сначала нужно локализовать эффект отдельных расширений на базовом одном потоке. JSON-отчёты содержат throughput приёмника, байты, TCP retransmissions и UDP packet loss. В benchmark-режиме PCAP вообще не записывается: wire/PCAP проверяется отдельной interoperability-матрицей. Поэтому artifact содержит только компактные JSON-отчёты.

## Изолированный benchmark: результаты и выводы

[Run 41709590826](https://github.com/lelikulibina/boringtun-awg/actions/runs/41709590826) завершился успешно: **16/16 профильных прогонов**, 32 TCP + 8 UDP измерений. В нём проверены vanilla, AWG 2.x baseline, четыре отдельных расширения AWG 3.1, randomized timers и полный AWG 3.1. Artifact — **8 013 байт**, только JSON; PCAP в benchmark-режиме не создаётся.

Результаты TCP (Mbit/s, client→server / server→client):

| Профиль | amneziawg-go | BoringTun |
|---|---:|---:|
| Vanilla WireGuard | 4 066 / 4 349 | 600 / 563 |
| AWG 2.x baseline | 14,47 / 10,48 | 374 / 375 |
| HeaderProtectionKey | 23,69 / 6,08 | 387 / 386 |
| ContentPaddingAddition | 13,84 / 26,41 | 391 / 393 |
| RandomTrailers | 7,13 / 5,87 | 371 / 387 |
| DisableCookies | 6,50 / 9,85 | 390 / 395 |
| Только randomized timers | 11,11 / 10,69 | 369 / 365 |
| Все расширения AWG 3.1 | 14,26 / 10,69 | 362 / 361 |

UDP 100 Mbit/s прошёл без потерь в vanilla и полном AWG 3.1 профилях обеих реализаций.

**Вывод по контрольному профилю:** upstream Go уже падает до 10–14 Mbit/s на AWG 2.x baseline без расширений 3.1, против 4,1–4,35 Gbit/s vanilla. Каждый отдельный параметр 3.1 даёт сопоставимый порядок величины (примерно 6–26 Mbit/s), а randomized timers alone — около 11 Mbit/s. Это указывает на общий legacy AWG datapath/configuration, а не на отдельную новую функцию 3.1. Однако AWG 2.x baseline объединяет Jc/Jmin/Jmax и S1-S4/H1-H4; чтобы точно локализовать причину, следующий запуск добавляет раздельные J-only и S/H-only профили.

BoringTun на том же runner показывает 374–375 Mbit/s для AWG 2.x и 361–395 Mbit/s для профилей AWG 3.1 против 563–600 Mbit/s vanilla. Это умеренное снижение, а не катастрофическая деградация upstream Go. Результаты — короткие измерения на GitHub-hosted runner, не гарантия абсолютной производительности.

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

Диагностический workflow дополнен AWG 2.x control, timers-only, J-only и S/H-only профилями. Текущая версия — 10 профилей, 48 iperf3 измерений. Запускать через **Actions → AWG Performance Benchmarks → Run workflow**; результаты сравнивать внутри одного запуска и в обоих направлениях.
