# AWG tunnel performance benchmarks

The `AWG Performance Benchmarks` GitHub Actions workflow is a manual,
non-blocking benchmark. Run it from **Actions → AWG Performance Benchmarks →
Run workflow**. It does not participate in the required PR status checks.

The workflow builds this BoringTun fork and the pinned upstream
`amneziawg-go`, then creates isolated Linux network namespaces and measures
the encrypted tunnel with iperf3.

## Scenarios

- Vanilla WireGuard baseline.
- AWG 3.1 with HeaderProtectionKey, ContentPaddingAddition,
  RandomTrailers, DisableCookies and randomized timers.
- Both server roles: BoringTun server and amneziawg-go server.
- Both traffic directions.
- TCP with one stream and four parallel streams.
- UDP at a fixed offered rate of 100 Mbit/s.

Each measurement runs for 8 seconds. JSON reports include receiver throughput,
received byte count, TCP retransmissions, and UDP packet loss where reported.
Reports and the matching packet captures are uploaded as the
`awg31-iperf3-performance` artifact.

## Interpreting results

Compare the vanilla and AWG 3.1 numbers from the same workflow run. GitHub-hosted
runner load and virtualization make absolute throughput noisy; these results
are comparative diagnostics, not a stable hardware performance guarantee.
For meaningful release comparisons, repeat the workflow on the same dedicated
runner and compare medians across several runs.

The benchmark is intentionally separate from mandatory PR CI: throughput is
environment-dependent and should not make correctness checks flaky.
