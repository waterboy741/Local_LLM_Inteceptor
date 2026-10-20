# M5 package and later lab validation

The current build is an explicit HTTP proxy. The package below does not include a signed privileged helper or a working Network Extension, and it does not automatically redirect other devices or locally originated connections. Keep network-dependent verification in M6.

## Reproducible local package

On the build Mac, install the dependencies in the README, including `macdeployqt`, then run:

```sh
bash scripts/package_macos.sh
```

The script configures and builds the release preset, requires the release tests to pass, copies the app bundle, deploys Qt frameworks into the copy, and writes `dist/llm_interceptor-macos.zip`. This is an unsigned local research artifact. It is not a notarized distribution and grants no capture, packet-injection, PF, or Network Extension privilege. Do not share a package with real request recordings or machine-specific settings.

To inspect the artifact before using it, unpack it into a disposable directory and check the bundled executable and frameworks. Run it on the build Mac or a compatible test Mac using the explicit loopback listener; use a synthetic HTTP server and synthetic prompts. A live Ollama or Wi-Fi test belongs to M6.

## M6 opt-in lab runbook

Record the date, macOS version, app commit, client app/version, server version, interface, addresses, server port, API path, and applicable Wi-Fi policy. Use sanitized synthetic payloads first. Record observed outputs and any failure, without saving credentials or real prompts.

### Read-only endpoint preflight (M6 preparation only)

The optional `lab_preflight` executable checks the supplied configuration, whether the selected interface is present/up and has a usable local IPv4 address, and whether a TCP connection to the configured server IP/port succeeds within a bounded timeout. It binds the connection to a local IPv4 address on the selected interface; the operating system can still route that connection over another interface. The probe initiates a TCP handshake and can create connection state or a log at the remote endpoint, although it sends no application request. A PASS means only source-address-bound TCP reachability at that moment. It does not verify the peer's path through the named interface, shared subnet/L2, ARP compatibility, Wi-Fi policy, PF evaluation, interception, reverse translation, Ollama behavior, or live redirection. It does not change routes, PF, ARP, forwarding, interface, or other local network settings.

On October 19, 2026, the user-authorized lab endpoint preflight succeeded, a single ICMP echo to the client succeeded, local neighbor entries were present for the client and server, and the Ollama version endpoint returned HTTP 200 (version 0.40.4). A synthetic request to `/v1/chat/completions` returned HTTP 200 with one completion. This confirms endpoint reachability from the research host and the specific responses observed at that time. It does not prove the TCP flow left via the selected interface, shared Wi-Fi/L2 behavior, ARP compatibility, or redirection. Sanitized observations are in the lab record; raw address-bearing output remains in ignored local build evidence files.

Build the debug target, then invoke it only when the lab and its authorized endpoint are available. Supply the actual values explicitly; there are no inferred defaults for interface, client/server addresses, or port:

```sh
./build/debug/lab_preflight \
  --interface "$RESEARCH_INTERFACE" \
  --client-ip "$CLIENT_IPV4" \
  --server-ip "$SERVER_IPV4" \
  --server-port "$SERVER_TCP_PORT" \
  --timeout-ms 1500 \
  --evidence preflight.json
```

The process prints the same JSON it optionally writes with `--evidence`; exit status 0 means the checks completed and TCP connected, 1 means a check failed, and 2 means arguments or evidence-file writing failed. The schema records UTC time, configured-field presence, check outcomes, timeout, and a stable status code. It omits the supplied interface name, addresses, MACs, credentials, packet contents, and prompts. Keep the actual configuration in the lab's separately controlled evidence notes. TCP outcomes are `reachable`, `refused`, `timed_out`, `error`, or `not_checked`; timeout accepts 1–5000 ms and defaults to 1500 ms.

### Explicitly enabled PF diagnostics (M6 preparation only)

`lab_preflight --pf-diagnostics` is a separate opt-in read-only inspection mode. It requires the same explicit interface/client/server/port values plus `--session-id`, and issues only fixed, allowlisted `/sbin/pfctl` show queries: PF status, main filter and translation rules, the application/session anchor tree, rules and counters scoped to that session anchor, and the state table. It never loads or flushes rules, enables PF, releases a PF reference, changes ARP, or invokes `sudo`. PF inspection may require administrator privileges; a permission failure is recorded as unavailable, with no retry or elevation attempt.

The local macOS `pfctl(8)` man page states that `-a` scopes ruleset operations, while `-s states` shows the state table; it does not promise that state output is anchor-scoped. The command therefore caps each query at 256 KiB, filters the bounded global state output in memory by the configured client/server IP and server port, discards raw output, and reports only a matching candidate count. It labels those rows as global candidates and never attributes them to the selected anchor. The output also separates main-ruleset anchor references from loaded session-anchor/rule evidence. Visible attachment references or nonzero counters do not prove a fresh packet evaluated or matched the anchor; `evaluation_proven` remains false. Output caps, timeouts, permission errors, or unrecognized output make the result incomplete. This mode does not establish active redirection, reverse translation, ARP delivery, or live support.

Run the full inspection after a corresponding M4 session anchor exists and the user has explicitly chosen to inspect PF. A preliminary invocation may establish whether the host grants read access, but cannot validate a nonexistent anchor:

```sh
./build/debug/lab_preflight \
  --pf-diagnostics \
  --session-id "$SESSION_ID" \
  --interface "$RESEARCH_INTERFACE" \
  --client-ip "$CLIENT_IPV4" \
  --server-ip "$SERVER_IPV4" \
  --server-port "$SERVER_TCP_PORT" \
  --pf-timeout-ms 3000 \
  --evidence pf-diagnostics.json
```

The JSON omits the configured interface name, addresses, session identifier, PF rule text, and raw states. Store actual lab configuration in separately controlled evidence notes. A completed diagnostic means all queries were read and parsed; it does not mean the configured references were found or traffic was intercepted. A preliminary lab invocation returned `permission_denied` on the first query; no rules or states were read. The command does not elevate or retry.

1. Verify direct client-to-mock-server connectivity and the configured path and port. Confirm that the server listens on the chosen LAN address and that the research Mac can reach it.
2. Exercise the packaged explicit proxy on loopback. Start Observe, point only the test client at the displayed listener, send a JSON request, and verify one upstream delivery and an intact response. Test a streaming response and a nonmatching path. Stop, then verify the listener has closed.
3. Exercise Modify with a synthetic chat request. Verify a shorter and a longer edited body arrive exactly once and that the response reaches the client. Verify Hold timeout and cancellation during stop.
4. Record bounded-history, export/import, and replay behavior with synthetic records. Confirm replay does not open a server connection and exported files contain no test credentials.
5. Only if a separately completed and reviewed redirection implementation exists, verify peer topology and opt-in live routing using the gates in [M0_LAB.md](M0_LAB.md). Confirm MAC/IP delivery, rule attachment, reverse translation, bypass traffic, cleanup, and network recovery. An unsigned M5 package alone cannot pass these gates.

Keep evidence as a checklist with PASS/FAIL, setup, timestamp, and sanitized observations. A successful offline build or loopback proxy test does not establish live Wi-Fi interception.
