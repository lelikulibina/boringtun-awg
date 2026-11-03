# Тестирование производительности туннеля AWG

Workflow `AWG Performance Benchmarks` — дополнительный benchmark, не блокирующий обязательные PR checks. Его можно запустить вручную через **Actions → AWG Performance Benchmarks → Run workflow**. Workflow также запускается при изменении своего YAML, harness или этого документа на feature branch.

## Методика

Workflow собирает BoringTun и закреплённую версию официального `amneziawg-go`, создаёт изолированные Linux network namespaces и измеряет зашифрованный туннель через iperf3.

Каждому endpoint назначается уникальное имя интерфейса даже при использовании одной реализации на обеих сторонах: UAPI-сокеты Linux WireGuard создаются в host `/var/run` и не изолируются network namespaces. Повторное имя интерфейса приводит к конфликту сокетов.

Производительность измеряется отдельно для однородных пар:
- `amneziawg-go` client ↔ `amneziawg-go` server;
- `boringtun-awg` client ↔ `boringtun-awg` server.

Это позволяет не смешивать накладные расходы datapath с межреализационной совместимостью.

## Сценарии измерений

- Vanilla WireGuard как baseline.
- AWG 3.1 с HeaderProtectionKey, ContentPaddingAddition, RandomTrailers, DisableCookies и randomized timers.
- Обе однородные пары реализаций.
- Оба направления передачи данных.
- TCP: один поток и четыре параллельных потока.
- UDP: целевая скорость 100 Mbit/s.
- Длительность одного измерения — 8 секунд.

Итого workflow выполняет 24 iperf3 measurements: 2 реализации × 2 профиля × 2 направления × 3 режима трафика. JSON-отчёты содержат throughput на приёмнике, число полученных байтов, TCP retransmissions и UDP packet loss, если он предоставляется iperf3.

## Последний запуск

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
