# AWG tunnel performance benchmarks

The `AWG Performance Benchmarks` GitHub Actions workflow is a non-blocking
benchmark. It can be started from **Actions → AWG Performance Benchmarks →
Run workflow**, and also runs when its workflow, harness, or this document
changes on the feature branch or the isolated `bench/max-throughput` branch. It does not participate in required PR status
checks.

The workflow builds this BoringTun fork and the pinned upstream
`amneziawg-go`, then creates isolated Linux network namespaces and measures
the encrypted tunnel with iperf3. Each endpoint receives a distinct interface
name even when both endpoints use the same implementation: Linux WireGuard
UAPI sockets are created under the host's `/var/run` filesystem and are not
isolated by network namespaces. Reusing an interface name across namespaces
causes a socket collision and prevents the second endpoint from starting.
The harness measures homogeneous pairs separately:
`amneziawg-go` client ↔ `amneziawg-go` server and `boringtun-awg` client ↔
`boringtun-awg` server. This avoids conflating datapath performance with
cross-implementation interoperability.

## Scenarios

- Vanilla WireGuard baseline.
- AWG 3.1 with HeaderProtectionKey, ContentPaddingAddition,
  RandomTrailers, DisableCookies and randomized timers.
- Homogeneous endpoint pairs: amneziawg-go ↔ amneziawg-go and BoringTun ↔ BoringTun.
- Vanilla WireGuard and AWG 3.1 profiles for each homogeneous pair.
- Both traffic directions.
- TCP with 1, 4, 8 and 16 parallel streams; each run lasts 10 seconds.
- UDP offered-rate sweep from 100 Mbit/s up to 20 Gbit/s. The sweep stops after receiver loss exceeds 1%, then performs up to three binary-search refinements.
- UDP summary reports the highest receiver throughput at or below 1% loss, the raw peak regardless of loss, the highest offered rate tested, and whether the 20-Gbit/s test ceiling was reached without crossing the loss threshold.
- Per-test tunnel CPU is measured from `/proc/<pid>/stat` for both tunnel processes. Reports include combined CPU seconds, consumed CPU cores, percent of one core, percent of host capacity, and per-process CPU seconds.

The job timeout is 50 minutes. JSON reports include receiver throughput, received bytes, TCP retransmissions, UDP loss, offered rate, and tunnel CPU usage. The UDP sweep's 20-Gbit/s ceiling is a test limit, not a claim about the library's theoretical maximum.
Reports and the matching packet captures are uploaded as the
`awg31-iperf3-performance` artifact.

## Interpreting results

Compare both the implementations (Go vs BoringTun) and the overhead of AWG 3.1 against vanilla WireGuard within each implementation, using results from the same workflow run. GitHub-hosted
runner load and virtualization make absolute throughput noisy; these results
are comparative diagnostics, not a stable hardware performance guarantee.
For meaningful release comparisons, repeat the workflow on the same dedicated
runner and compare medians across several runs.

The benchmark is intentionally separate from mandatory PR CI: throughput is
environment-dependent and should not make correctness checks flaky. It runs
manually from Actions or automatically when the benchmark workflow, harness,
or this document changes on the feature branch.
