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

Итого 40 iperf3 measurements: 32 TCP + 8 UDP. Четырёхпоточный TCP удалён из диагностического smoke-benchmark: сначала нужно локализовать эффект отдельных расширений на базовом одном потоке. JSON-отчёты содержат throughput приёмника, байты, TCP retransmissions и UDP packet loss. В benchmark-режиме PCAP вообще не записывается: wire/PCAP проверяется отдельной interoperability-матрицей. Поэтому artifact содержит только компактные JSON-отчёты.

## Изолированный benchmark: результаты и выводы

[Run 41708623320](https://github.com/lelikulibina/boringtun-awg/actions/runs/41708623320) завершился успешно: **12/12 профильных прогонов**, 32 TCP и 8 UDP измерений. Один прогон — 5 секунд, оба направления. Artifact содержит только JSON и занимает **6 116 байт**; ранее PCAP с полным iperf3-трафиком занимал около 1,8 GB.

Результаты TCP (Mbit/s, client→server / server→client):

| Профиль | amneziawg-go | BoringTun |
|---|---:|---:|
| Vanilla WireGuard | 7 572 / 7 768 | 1 085 / 1 085 |
| HeaderProtectionKey | 1,47 / 1,68 | 733 / 695 |
| ContentPaddingAddition | 1,68 / 1,47 | 711 / 742 |
| RandomTrailers | 2,31 / 1,47 | 733 / 702 |
| DisableCookies | 1,68 / 1,89 | 750 / 743 |
| Все расширения AWG 3.1 | 1,47 / 1,47 | 655 / 681 |

В Go baseline зафиксировано 0 TCP retransmissions. В отдельных AWG-профилях — примерно 189–266 retransmissions за 5 секунд. В BoringTun значения TCP retransmissions заметно выше и зависят от направления/профиля, но пропускная способность остаётся в диапазоне 655–750 Mbit/s. UDP 100 Mbit/s прошёл без потерь в baseline и полном AWG 3.1 профиле обеих реализаций.

**Промежуточный вывод:** сильная деградация upstream Go не локализуется на одном расширении 3.1: каждый из четырёх одиночных профилей даёт почти одинаково низкий TCP throughput. Но эти профили используют общую S/H-обфускацию AWG 2.x. Поэтому пока нельзя утверждать, что проблема вызвана именно 3.1. Следующий benchmark добавляет AWG 2.x baseline без расширений 3.1 и отдельный профиль randomized timers. Это контроль, который позволит отделить стоимость базовой S/H-обфускации от новых параметров.

BoringTun на том же runner показывает ожидаемо меньшую, но умеренную деградацию: около 1 085 Mbit/s vanilla против 655–750 Mbit/s в AWG-профилях. Результаты — короткие измерения на GitHub-hosted runner, а не стабильная гарантия производительности.

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

Диагностический workflow дополнен AWG 2.x control и timers-only профилями. Текущая версия — 8 профилей, 40 iperf3 измерений. Запускать через **Actions → AWG Performance Benchmarks → Run workflow**; результаты сравнивать внутри одного запуска и в обоих направлениях.
