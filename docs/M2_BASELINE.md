# M2 offline baseline

Measured October 9, 2026 on macOS 27.0.1 arm64, Qt 6.11.2, Debug build. This is synthetic loopback evidence, not LLM inference or Wi-Fi routing performance.

Repeat with the optional Qt test method after building: `INTERCEPTOR_RUN_BASELINE=1 build/debug/tests/m2_proxy_tests offlineBaseline`. The method is excluded from normal performance gates and uses local sockets only; sandboxed environments may need loopback permission.

The test sends 100 sequential 1052-byte JSON requests directly to a deterministic mock, then through the proxy. History capacity is 10. Timing polls at 1 ms. Streaming uses a synthetic 300 ms delay between NDJSON fragments. Measurements include the combined test client, mock, and proxy in one process; peak RSS is not isolated proxy memory. Fresh-process repetitions can differ due to scheduler and Debug overhead.

| Metric | Direct mock | Through proxy |
| --- | --- | --- |
| Median complete-request latency | 1.407 ms | 3.938 ms |
| p95 complete-request latency | 3.945 ms | 3.974 ms |
| Sequential throughput | 539.7 requests/s | 216.3 requests/s |
| Request-body throughput | 567731.8 bytes/s | 227550.8 bytes/s |
| NDJSON first payload | 4.068 ms | 4.127 ms |
| NDJSON complete response | 304.751 ms | 304.891 ms |

Combined peak resident memory: 27,705,344 bytes. The relay retains at most the configured row count and 8 MiB of bodies independently; incoming bodies default to 1 MiB, with 8 active transfers, 24 accepted sockets, 32 KiB headers, 64 KiB upstream buffer, and approximately 64 KiB downstream socket queue per transfer. Streaming emits 16 KiB blocks, with bounded stall handling. These are implementation bounds, not extrapolated memory-load results.

Proposed targets for discussion before M6: p95 added proxy latency below 10 ms, added streaming first-payload latency below 10 ms, at least 100 sequential requests/s for this 1 KiB synthetic workload, and stable memory during a sustained workload. These are provisional, not user-agreed live acceptance thresholds. M5 adds sustained-load verification; M6 selects actual workload and confirms targets before live tests.

Qt 6.11.2 emits a diagnostic for `writeEndChunked({})` despite correctly completing empty final chunks. Regression tests verify complete chunked bodies and incremental delivery. This dependency diagnostic remains documented; it is not evidence of byte loss.
