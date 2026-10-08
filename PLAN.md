# Local LLM Interceptor — Development Plan

Status: Initial proposal, October 8, 2026. No implementation milestones are complete.

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
- Scope: HTTP traffic only. Initial protocol support is HTTP/1.1 with JSON request bodies; responses may be JSON or streamed server-sent events (SSE).
- Initial API: configurable host, port, and endpoint paths. Choose the first concrete API adapter after identifying the research server, such as an OpenAI-compatible API or Ollama's native API.
- The client must retain its configured server address in ARP redirection mode. A separately configured explicit proxy mode will support early development and troubleshooting.
- IPv6, HTTP/2, HTTP/3, WebSockets, compressed request bodies, and multipart uploads are outside the initial inspection/editing scope. Define and test how unsupported traffic is forwarded or rejected before live use; never silently corrupt it.
- HTTPS/TLS interception, certificate authorities, and client certificate trust setup are out of scope. Encrypted traffic is never inspected or modified.

These assumptions must be validated against the actual lab before implementing live redirection.

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

The GUI should not run with elevated privileges. Define a narrow authenticated local IPC boundary for privileged operations, with validation and session-scoped target restrictions. Select the helper installation/signing approach during the macOS feasibility milestone.

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

### M0 — Lab Definition and macOS Feasibility

See [HTTP Traffic Redirection: macOS Design Investigation](docs/TRAFFIC_REDIRECTION.md) for the proposed PF-to-local-proxy packet path, return translation, lifecycle constraints, and proof-of-concept test matrix. This is researched design, not completed live validation.

Document the client, server software/API, HTTP ports and protocol version, network topology, and representative sanitized request/response samples. Investigate current macOS capture, packet injection, forwarding, transparent proxy integration, privileges, helper lifecycle, and packaging using primary documentation and a disposable lab proof of concept.

Acceptance:
- A topology diagram and supported traffic matrix exist in `docs/`.
- The first API and transport are selected, with sanitized fixtures.
- A demonstrated design covers both directions of traffic, original-destination routing, loop avoidance, startup rollback, and cleanup.
- ARP-incompatible networks and unresolved platform limitations are documented. Do not advance live redirection on an unproven routing design.

### M1 — Application Foundation

Create the CMake presets, Qt application shell, configuration models, session state machine, bounded event/history interfaces, and test infrastructure. Add README setup and permissions guidance.

Acceptance:
- Debug build and offscreen lifecycle tests pass; closing the window shuts down workers cleanly.
- Debug, release, and sanitizer presets exist; sanitizer support is checked.
- Starting the GUI performs no network mutation or privileged action.

### M2 — Explicit Proxy and Observe Mode

Build the HTTP relay against a deterministic local mock LLM before adding network redirection. Implement endpoint filtering, JSON inspection, history, details, and streaming response forwarding.

Acceptance:
- Matching requests appear in the GUI; nonmatching content is not retained.
- Unmodified body bytes and response content match mock-server expectations.
- Tests cover concurrent connections, keep-alive, chunked framing, malformed/truncated messages, disconnects, cancellation, timeouts, and SSE streaming.
- A repeatable baseline reports latency, streaming time-to-first-byte, throughput, and memory under stated limits. Agree on numeric performance targets before live testing.

### M3 — ARP Redirection Integration

Implement the scoped privileged helper and verified network integration from M0. Connect preflight, start/stop, watchdog, and cleanup status to the GUI.

Acceptance:
- An opt-in test on the authorized isolated lab redirects only the configured pair through the research machine, with the client still using its original server address.
- LLM requests are visible, responses stream successfully, and representative non-LLM traffic between the pair still works.
- No forwarding loops occur. Repeated start/stop, partial startup failure, interface loss, and GUI crash have documented recovery results.
- Offline tests cover ARP parsing, packet bounds, malformed/truncated frames, unsupported types, target validation, and mocked restoration failures.

### M4 — Manual and Rule-Based Modification

Add request holding, JSON editing, diffs, rule configuration, validation, deadlines, and modification audit records.

Acceptance:
- The mock LLM receives exactly the intended modified JSON; unmatched requests remain unchanged.
- Tests cover nested fields, Unicode, missing fields, invalid JSON, oversized bodies, rule ordering, concurrent held requests, deadlines, cancellation, and disconnects.
- Observe mode cannot apply modifications. Switching modes has explicit behavior for already held requests.

### M5 — Research Usability and Hardening

Add sanitized request export/import, bounded retention settings, session summaries, and reproducible offline replay into the inspection pipeline. Packet recording and CSV export mentioned in repository guidelines are secondary features; implement them after the core interceptor works, with explicit recording controls and bounded storage.

Acceptance:
- Long-running synthetic load stays within configured memory/storage limits and leaves the UI responsive.
- Exports omit credentials by default and round-trip supported research records. Offline replay cannot accidentally send requests to a live server.
- Relevant debug, release, and sanitizer checks pass. Packaging and a two-device-or-more lab walkthrough are documented with actual limitations.

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

## Decisions to Resolve Before Implementation

1. Which LLM server and client applications will be used first, and which API paths do they call?
2. Do the selected client and server use HTTP/1.1, and do they require SSE streaming or other HTTP features?
3. Are all three machines on the same IPv4 layer-2 segment, and does the network permit peer traffic and ARP changes?
4. Which macOS version and CPU architecture must the application support?
5. Which JSON fields and transformations are needed for the first experiment?
6. What request sizes, concurrency, hold deadlines, and retention limits match the workload?

Recommended development order: M0 → M1 → M2 → M3 → M4 → M5.
