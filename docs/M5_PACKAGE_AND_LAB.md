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

1. Verify direct client-to-mock-server connectivity and the configured path and port. Confirm that the server listens on the chosen LAN address and that the research Mac can reach it.
2. Exercise the packaged explicit proxy on loopback. Start Observe, point only the test client at the displayed listener, send a JSON request, and verify one upstream delivery and an intact response. Test a streaming response and a nonmatching path. Stop, then verify the listener has closed.
3. Exercise Modify with a synthetic chat request. Verify a shorter and a longer edited body arrive exactly once and that the response reaches the client. Verify Hold timeout and cancellation during stop.
4. Record bounded-history, export/import, and replay behavior with synthetic records. Confirm replay does not open a server connection and exported files contain no test credentials.
5. Only if a separately completed and reviewed redirection implementation exists, verify peer topology and opt-in live routing using the gates in [M0_LAB.md](M0_LAB.md). Confirm MAC/IP delivery, rule attachment, reverse translation, bypass traffic, cleanup, and network recovery. An unsigned M5 package alone cannot pass these gates.

Keep evidence as a checklist with PASS/FAIL, setup, timestamp, and sanitized observations. A successful offline build or loopback proxy test does not establish live Wi-Fi interception.
