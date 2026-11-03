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

- Vanilla WireGuard как baseline.
- Vanilla WireGuard baseline.
- Изолированные профили: HeaderProtectionKey, ContentPaddingAddition, RandomTrailers и DisableCookies.
- Полный профиль AWG 3.1 со всеми расширениями.
- Однородные пары amneziawg-go ↔ amneziawg-go и BoringTun ↔ BoringTun.
- Оба направления передачи данных.
- TCP: один поток, 5 секунд для каждого направления.
- UDP: целевые 100 Mbit/s для baseline и полного профиля, 5 секунд.

Итого 32 iperf3 measurements: 24 TCP + 8 UDP. Четырёхпоточный TCP удалён из диагностического smoke-benchmark: сначала нужно локализовать эффект отдельных расширений на базовом одном потоке. JSON-отчёты содержат throughput приёмника, байты, TCP retransmissions и UDP packet loss. PCAP закрывается сразу после handshake, поэтому в artifact больше не попадает гигабайтный поток тестовых данных.

## Обнаруженная аномалия в исходном benchmark

В [run 41690711443](https://github.com/lelikulibina/boringtun-awg/actions/runs/41690711443) на старой методике (8 секунд, один TCP stream, четыре TCP streams и UDP) были получены следующие значения:

| Реализация | Профиль | TCP 1 поток, client→server | TCP 4 потока, client→server |
|---|---|---:|---:|
| amneziawg-go | vanilla WireGuard | 5654,27 Mbit/s | 5261,59 Mbit/s |
| amneziawg-go | AWG 3.1 | 1,97 Mbit/s | 12,32 Mbit/s |
| BoringTun | vanilla WireGuard | 775,29 Mbit/s | 776,05 Mbit/s |
| BoringTun | AWG 3.1 | 508,32 Mbit/s | 488,03 Mbit/s |

В Go-профиле AWG 3.1 также зарегистрировано 315 TCP retransmissions в одном потоке и 1302 в четырёх потоках; в vanilla-профиле Go — 0 и 0 соответственно. UDP 100 Mbit/s прошёл без потерь во всех четырёх комбинациях.

Это не доказывает, что проблема находится в конкретном расширении: старый тест включал HPK, ContentPaddingAddition, RandomTrailers, DisableCookies и randomized timers одновременно. Низкий TCP throughput может быть связан с одним из расширений, их взаимодействием или особенностью тестовой среды. BoringTun в том же сценарии сохраняет около 0,5 Gbit/s, поэтому нельзя списывать результат только на нагрузку GitHub runner.

Новая версия benchmark добавляет отдельные профили каждого расширения и полный профиль. До получения этих изолированных результатов **не делаем вывод**, какое расширение является причиной. Если проблема воспроизводится только на Go, отдельно проверяем upstream reference; если на обеих реализациях — проверяем wire-format и влияние padding на MTU/фрагментацию.

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


## Текущий статус расследования

Диагностический workflow обновлён: отдельные TCP-профили для HPK, ContentPaddingAddition, RandomTrailers и DisableCookies, плюс baseline и полный AWG 3.1. Он не является merge gate. Запускать через **Actions → AWG Performance Benchmarks → Run workflow** после публикации ветки изменений. Сравнивать результаты нужно в пределах одного запуска и в обоих направлениях.
