# llm_interceptor — Development Plan

Status: Revised October 9, 2026. M0 through M3 are complete under their offline acceptance criteria, each with implementation, testing, and independent review COMPLETE votes. M4 is next; live lab validation is deferred to M6.

## Purpose

Build a standalone, macOS-first desktop application for controlled research on a local network. The application sits between an explicitly selected client and a locally hosted LLM service and provides three functions:

1. Redirect their traffic through the research machine using ARP spoofing.
2. Identify, filter, and display LLM JSON requests while forwarding traffic with minimal disruption.
3. Selectively intercept and modify JSON requests before forwarding them to the LLM.

Use is limited to devices and traffic authorized for the local research experiment. Target selection and session activation are explicit; launching the application must not change network state.

## Starting Point and Working Assumptions

The repository currently contains guidelines, ignore rules, and a license, but no application source, build configuration, or tests. Behaviors described in AGENTS.md are intended conventions, not verified existing capabilities.

- Stack: C++20, Qt 6 Widgets, CMake, Ninja, and Qt Test.
- Initial topology: one client, one local LLM server, and one research machine on the same IPv4 layer-2 network.
- Scope: HTTP traffic only. Initial protocol support is HTTP/1.1 with JSON request bodies; responses may be JSON or streamed newline-delimited JSON (NDJSON).
- Initial API: Ollama native HTTP with session-configured client IPv4, LLM server IPv4, server TCP port, and endpoint paths. Port 11434 is only Ollama's default/example, not a required runtime value. Start synthetic adapter coverage with POST /api/generate; confirm the actual client paths before adapter implementation.
- The client must retain its configured server address in ARP redirection mode. A separately configured explicit proxy mode will support early development and troubleshooting.
- IPv6, HTTP/2, HTTP/3, WebSockets, compressed request bodies, and multipart uploads are outside the initial inspection/editing scope. Define and test how unsupported traffic is forwarded or rejected before live use; never silently corrupt it.
- HTTPS/TLS interception, certificate authorities, and client certificate trust setup are out of scope. Encrypted traffic is never inspected or modified.

These assumptions guide offline implementation. Validate them against the actual lab in M6 before claiming live redirection support.

## User Workflow

1. Select the research interface and enter the client and LLM server addresses, server port, protocol, and API paths.
2. Run preflight checks and review the target pair, forwarding readiness, transport support, and required privileges.
3. Choose **Observe** or **Modify** and start a session. Observe is the default.
4. View a bounded request history with time, client, endpoint, model, method, status, latency, and modification state. Filter by these fields or request text.
5. Open a request to inspect headers, formatted JSON, original raw content, response metadata, and any applied changes.
6. In Modify mode, apply scoped rules or pause selected requests for manual editing and validation.
7. Stop the session, release held requests according to the configured policy, restore network configuration where possible, and display the cleanup result.

## Architecture

Keep packet handling, transport, JSON processing, persistence, and presentation separate.

| Component | Responsibility |
| --- | --- |
| Qt GUI (`src/gui/`) | Session setup, request list, filters, details, JSON editor, diff, and session health |
| Session controller (`src/session/`) | Explicit lifecycle, configuration, startup rollback, shutdown, and component coordination |
| Privileged network helper (`src/network/`) | Narrow operations for capture/injection, selected-pair ARP redirection, forwarding setup, and restoration |
| Transport proxy (`src/proxy/`) | Downstream/upstream connections, HTTP framing, streaming, backpressure, deadlines, and cancellation |
| Request pipeline (`src/interception/`) | Endpoint matching, bounded JSON parsing, Observe/Modify decisions, validation, and edit audit |
| Request history (`src/storage/`) | Bounded in-memory records, optional sanitized exports, retention, and replay metadata |
| Shared models (`src/core/`) | Typed configuration, immutable request events, errors, and metrics |

The GUI should not run with elevated privileges. Define a narrow authenticated local IPC boundary for privileged operations, with validation and session-scoped target restrictions. Document helper installation/signing options in M0, implement the selected approach in M4, and verify installation and privileges in the lab in M6.

Use mature protocol and JSON libraries where appropriate. Select dependencies after a focused compatibility, maintenance, licensing, and macOS packaging review; do not implement a production HTTP parser from scratch.

### Data Path

```text
Selected client
    -> research machine (explicit proxy initially; ARP redirection later)
        -> selected LLM connection: transport proxy
            -> request match / JSON inspection / optional modification
            -> local LLM server
        -> other redirected traffic: forwarding path

LLM responses -> research machine -> client
Request metadata and bounded body copies -> GUI/history
```

ARP redirection and application interception are separate mechanisms. The implementation must prove how both traffic directions reach the research machine, how selected connections enter the proxy, and how the proxy reaches the original server without loops. Do not attempt JSON changes by rewriting individual TCP packets; terminate and relay selected connections at the transport layer.

## Functional Requirements

### 1. ARP Redirection and Session Recovery

- Restrict each session to an explicitly configured client/server pair on the selected interface.
- Check address/MAC resolution, interface availability, topology assumptions, and forwarding readiness before changing ARP state.
- Establish forwarding and proxy readiness before starting redirection. Handle partial startup with rollback.
- Maintain bidirectional connectivity and prevent the application's own upstream traffic from being intercepted recursively.
- Snapshot only the system settings the application changes and restore them carefully without overwriting unrelated concurrent changes.
- On normal stop, cease redirection, attempt neighbor-state restoration, restore owned system configuration, and report failures.
- Design a helper watchdog for GUI failure. Document that abrupt machine loss and stale neighbor caches can still interrupt connectivity; recovery cannot be guaranteed under every failure.
- Detect interface loss, target disappearance, and privilege failures and surface an actionable session state.

### 2. Observe and Forward

- Identify relevant requests by configured destination, port, method, path, and content type; avoid treating every JSON body as an LLM prompt.
- Retain original request bytes for comparison within configured size limits. Inspection must not rewrite an unmodified JSON body.
- Preserve request/response semantics, authentication forwarding, errors, keep-alive behavior, ordering, and streaming delivery. HTTP framing or hop-by-hop headers may need protocol-correct adjustment by the proxy.
- Stream responses incrementally; do not wait for an entire generated answer before forwarding it.
- Forward nonmatching traffic through the appropriate path without parsing or storing its content.
- Bound request sizes, history, connection counts, parser depth, inspection buffers, and queued GUI events. Define oversized-body behavior explicitly.
- Keep capture/proxy work off the GUI thread. Slow rendering or full history must not stall forwarding.
- Hide credentials in the GUI and exclude them from exports by default. Persistence is opt-in; raw captures can contain sensitive content even when displayed fields are redacted.

“Undisturbed” means preserved application behavior and measured, low added latency. A proxy necessarily changes transport characteristics and adds overhead; it cannot promise zero impact.

### 3. Modify JSON Requests

- Enable editing only for matching, supported JSON requests and only after explicit selection of Modify mode.
- Support manual hold/edit/forward and deterministic scoped rules, such as replacing a prompt field or changing a model parameter.
- Match rules by endpoint and optional model/JSON-field conditions. Define rule ordering and apply each rule once per request.
- Preserve unknown fields and validate JSON syntax plus adapter-specific constraints before forwarding.
- Show an original/modified diff and record the rule or manual action responsible for each edit.
- Recompute framing and content length when necessary. Handle encodings explicitly; do not mutate unsupported signed, compressed, or otherwise unverifiable bodies.
- Give held requests a visible deadline. Configure whether timeout forwards the original request or returns an explicit error; default to forwarding the original for continuity.
- Bound held requests and handle client cancellation. Invalid edits remain blocked from submission while the user can forward the original.
- Do not retry submitted generation requests automatically when delivery is uncertain; retries can duplicate work.

## Milestones and Acceptance Criteria

### M0 — Offline Definition and macOS Feasibility Design

See [HTTP Traffic Redirection: macOS Design Investigation](docs/TRAFFIC_REDIRECTION.md) for the proposed PF-to-local-proxy packet path, return translation, lifecycle constraints, and proof-of-concept test matrix. This is researched design, not completed live validation. See [M0 lab definition and evidence record](docs/M0_LAB.md) for the confirmed Ollama/Wi-Fi scope, supported traffic matrix, PF syntax check, and live checks reserved for M6.

Define the configurable client/server/interface inputs, selected synthetic Ollama API and HTTP/1.1 transport, proposed topology, and synthetic request/response samples. Investigate macOS capture, packet injection, forwarding, transparent proxy integration, privileges, helper lifecycle, and packaging using primary documentation and parse-only checks. Actual lab inventory and disposable network proof belong to M6.

Acceptance:
- A topology diagram and supported traffic matrix exist in `docs/`.
- The first API and transport are selected, with sanitized fixtures. The product design accepts configurable research interface, client IPv4, LLM server IPv4, server TCP port (1–65535), and API paths. Validate usable unicast IPv4 addresses and port range; freeze one immutable snapshot for the active session. Selected values consistently drive preflight, PF matching, upstream connections, and diagnostics; reject mismatches rather than routing from HTTP Host. Actual lab addresses are required for live validation, not for defining this configuration contract.
- A documented design covers both directions of traffic, configured original-destination routing, loop avoidance, startup rollback, cleanup, and unresolved platform questions; it identifies the M6 evidence needed to validate these claims.
- ARP-incompatible networks and unresolved platform limitations are documented. Offline development may proceed; live operation remains unproven until M6.

### M1 — Application Foundation

Create the CMake presets, Qt application shell, configuration models, session state machine, bounded event/history interfaces, and test infrastructure. Add README setup and permissions guidance.

Acceptance:
- Debug build and offscreen lifecycle tests pass; closing the window shuts down workers cleanly.
- Debug, release, and sanitizer presets exist; sanitizer support is checked.
- Starting the GUI performs no network mutation or privileged action.

### M2 — Explicit Proxy and Observe Mode

Build the HTTP relay against a deterministic local mock LLM before adding network redirection. Implement endpoint filtering, JSON inspection, history, details, and streaming response forwarding.

Completed October 9, 2026. The local Observe proxy is explicitly started, forwards to the configured HTTP endpoint, and displays matching JSON requests. Offline tests cover the acceptance cases below, including GUI visibility and shutdown. Production, testing, and independent review each returned COMPLETE after the final changes. Debug, release, and sanitizer suites each passed 3/3 registered tests. The repeatable measurements, provisional targets, and limits are in [docs/M2_BASELINE.md](docs/M2_BASELINE.md). Rich request-list filters and metadata remain in M5; Wi-Fi routing and target-device verification remain in M6.

Acceptance:
- Matching requests appear in the GUI; nonmatching content is not retained.
- Unmodified body bytes and response content match mock-server expectations.
- Tests cover concurrent connections, keep-alive, chunked framing, malformed/truncated messages, disconnects, cancellation, timeouts, and NDJSON streaming.
- A repeatable baseline reports latency, streaming time-to-first-byte, throughput, and memory under stated limits. Agree on numeric performance targets before live testing.

### M3 — Manual and Rule-Based Modification (Offline)

Add request holding, JSON editing, diffs, rule configuration, validation, deadlines, and modification audit records.

Completed October 9, 2026 under the offline acceptance criteria. Production, testing, and independent review each returned COMPLETE. Debug and sanitizer builds passed all 4 registered suites; an M3 release run was not performed. See [docs/M3_MODIFICATION.md](docs/M3_MODIFICATION.md) for behavior and limits and [docs/M3_STATE.md](docs/M3_STATE.md) for the saved milestone state. Live target-device behavior remains deferred to M6.

Acceptance:
- The mock LLM receives exactly the intended modified JSON; unmatched requests remain unchanged.
- Tests cover nested fields, Unicode, missing fields, invalid JSON, oversized bodies, rule ordering, concurrent held requests, deadlines, cancellation, and disconnects.
- Observe mode cannot apply modifications. Switching modes has explicit behavior for already held requests.

### M4 — Network Helper Integration (Offline)

Implement the scoped helper, preflight/session orchestration, PF rule generation, watchdog, rollback, and cleanup reporting behind an injectable system-operation boundary. Develop with synthetic Ethernet frames, fake neighbor/settings/PF state, and parse-only platform checks. Keep live activation opt-in and explicitly unvalidated.

Acceptance:
- Offline tests cover ARP parsing and generation, packet bounds, malformed/truncated frames, unsupported types, interface/target validation, and configurable nondefault ports.
- Generated PF rules and proxy routing derive from one validated session snapshot; tests prove client/interface/server/port scope and loop avoidance by rule construction.
- Mocked startup failures, watchdog expiry, interface loss, conditional setting restoration, PF token ownership, and owned-state cleanup produce correct rollback/status results.
- Available PF syntax-only checks pass without installing rules. Dedicated anchor attachment and privilege/packaging prerequisites are documented for M6.
- Mocked results are labeled as such; active anchors, actual routing, neighbor changes, and recovery are not claimed as verified.

### M5 — Research Usability and Hardening

Add sanitized request export/import, bounded retention settings, session summaries, and reproducible offline replay into the inspection pipeline. Packet recording and CSV export mentioned in repository guidelines are secondary features; implement them after the core interceptor works, with explicit recording controls and bounded storage.

Acceptance:
- Long-running synthetic load stays within configured memory/storage limits and leaves the UI responsive.
- Exports omit credentials by default and round-trip supported research records. Offline replay cannot accidentally send requests to a live server.
- Relevant debug, release, and sanitizer checks pass. Packaging artifacts and the lab runbook are prepared; installation/privilege and device walkthrough verification are deferred to M6.

### M6 — Authorized Lab Validation

Perform every verification requiring the test Wi-Fi network or actual client/server assets here, after offline work is ready and lab access is available. Record the actual client/API paths, Ollama version/model, addresses, interface, subnet/L2 behavior, server LAN bind/firewall, OS versions, and applicable network policy.

Acceptance:
- Confirm peer reachability, selected endpoint/protocol, Wi-Fi ARP compatibility, and both-direction MAC/IP delivery using sanitized synthetic traffic first.
- Demonstrate that the dedicated PF anchor is actively evaluated, a fresh SYN reaches the proxy, and expected state/counters and reverse translation exist.
- The client keeps its configured server address; the proxy uses the selected server IP/port, including a nondefault-port test. No recursive upstream connections occur.
- Actual LLM requests are visible and native NDJSON responses stream; representative non-LLM bypass traffic works in both directions. Shorter and longer edited JSON bodies arrive intact and exactly once at the mock server in the real network path before testing edits against Ollama.
- Repeated start/stop, partial startup failure, interface loss, GUI/helper/proxy failure, existing connections, stale neighbors, and cleanup have measured outcomes. Unrelated PF rules/state/references remain intact.
- Helper packaging, installation, authentication, required privileges, watchdog behavior, and a multi-device walkthrough are verified with actual limitations.
- Compare live latency/streaming/throughput against stated targets. Resolve findings and obtain all three COMPLETE votes before claiming live support.

M6 availability does not gate completion of M0–M5. Live checks are separate opt-in work and must never be inferred from offline test success.

## Validation and Milestone Review

Prefer deterministic tests under `tests/` and small synthetic/sanitized data under `tests/fixtures/`. Keep live capture/redirection tests opt-in and separate from normal CTest runs.

For implementation milestones, follow AGENTS.md: assign production/build/docs, tests, and independent review to separate GPT-6.1 Sol agents using Light effort, with separate build directories. Review ownership, packet bounds, thread safety, cleanup, and milestone acceptance criteria. Require all three COMPLETE votes after findings are resolved and affected tests are rerun. This initial planning document does not claim those implementation votes.

Standard checks once build configuration exists:

```sh
cmake --preset debug
cmake --build --preset debug
ctest --preset debug --output-on-failure
git diff --check
```

Record actual results and coverage gaps for each milestone. Mocked restoration tests do not replace live recovery verification.

## Decisions and When to Resolve Them

1. Which LLM server and client applications will be used first, and which API paths do they call?
2. Do the selected client and server use HTTP/1.1, and which native Ollama endpoints does the client call? Preserve native NDJSON streaming; SSE is only a future generic transport option.
3. Are all three machines on the same IPv4 layer-2 segment, and does the network permit peer traffic and ARP changes?
4. Which macOS version and CPU architecture must the application support?
5. Which JSON fields and transformations are needed for the first experiment?
6. What request sizes, concurrency, hold deadlines, and retention limits match the workload?

Resolve product defaults, limits, and supported build targets during offline milestones. Actual client paths, network policy, target addresses, and device behavior are lab inputs for M6 and do not block configurable implementation.

Recommended development order: M0 → M1 → M2 → M3 → M4 → M5 → M6 (when lab access is available).
