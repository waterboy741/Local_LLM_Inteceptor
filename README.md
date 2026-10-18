# llm_interceptor

M2 adds an explicitly activated local reverse proxy for Ollama Observe mode. Prepare the configuration, click Start Observe proxy, then set the client Ollama base URL to the displayed loopback listener. Launch performs no listening or network mutation. Clear session or close the window to stop the relay worker. ARP/PF redirection is not implemented.

## Build and test

Requires macOS Command Line Tools, CMake 3.24+, Ninja, and Qt 6.11+ Core, Widgets, Network, HttpServer, and Test. Install these dependencies through your preferred package manager. If Qt is not discovered automatically, put personal CMAKE_PREFIX_PATH settings in ignored CMakeUserPresets.json or pass them at configure time.

```sh
cmake --preset debug
cmake --build --preset debug
ctest --preset debug --output-on-failure
./build/debug/llm_interceptor.app/Contents/MacOS/llm_interceptor
```

The release and sanitizer presets use the same commands with their respective names. Sanitizer configuration checks compiler/linker support for AddressSanitizer and UndefinedBehaviorSanitizer. Tests run offscreen without capture privileges. M0 synthetic fixture checks can also run with `python3 -m unittest discover -s tests -p 'test_m0_fixtures.py' -v`.

GitHub Actions runs the debug, release, and sanitizer presets on a macOS runner for every push and pull request. The workflow installs Qt 6.11+ and Ninja, builds the application, and runs the same CTest suites; it performs no live network activation.

## Configuration and permissions

To proxy the device running this app, check **Proxy this device**. Leave LLM IPv4 at `127.0.0.1` for Ollama on the same device, or enter the remote Ollama server's IPv4 address. Set LLM TCP port to the real server port (normally `11434`) and local listen port to `18080`. Click **Prepare configuration**, then **Start Observe proxy**. Set your client application's Ollama base URL to the displayed `http://127.0.0.1:18080` (or the displayed automatically allocated port). For example, with a running local Ollama model:

```sh
curl http://127.0.0.1:18080/api/generate -d '{"model":"YOUR_INSTALLED_MODEL","prompt":"Hello","stream":false}'
```

The local option supplies the loopback client address and needs no research interface. Only applications configured to use this URL send requests through the interceptor; system traffic is not redirected. Keep the real Ollama server on a different port from the interceptor when using a loopback upstream. With a remote upstream such as `192.168.1.141:11434`, the local listener may also use `11434` if that port is free on this device. The relay rejects the same loopback listener port and connects directly upstream, independently of system proxy settings. Clear session stops the listener; restore the client's original Ollama base URL afterward.

For the research configuration, leave **Proxy this device** unchecked. Select a research interface from the detected interface list, then enter client/server unicast IPv4 addresses, a server TCP port from 1 to 65535, and comma-separated API paths. Port 11434 is the default example for Ollama and can be changed. The interface list reads current system interface names and descriptions without changing network settings; it includes inactive and loopback interfaces. Preparation stores the canonical interface name, validates syntax, and freezes a copy; lab suitability and reachability remain unverified. Use Refresh to update the interface list while idle; it preserves the selected interface if still present. If no interfaces are available, research preparation is disabled; **Proxy this device** remains available. Clear the session to change its configuration.

Launch and offline tests need no capture privileges; socket-based tests need permission to bind synthetic loopback endpoints. Future capture/injection/PF operations will use a scoped helper and explicit activation; never run the GUI as root. Capture only authorized traffic. Actual Wi-Fi/ARP/PF routing, privileges, packaging, and recovery will be verified in M6 when lab access is available. See [PLAN.md](PLAN.md) and [M0 lab record](docs/M0_LAB.md).

BoundedHistory retains a configured positive maximum row count and limits each summary to 4096 UTF-16 code units. Append/snapshot/clear are mutex-protected. SessionController and GUI are owner-thread objects; immutable configuration copies cross component boundaries. The Observe view retains only matching POST JSON object bodies for configured API paths, with response status and raw body details. Nonmatching bodies are forwarded but never stored. No authentication headers are displayed or retained.

## Observe relay limits and behavior

Qt HTTP Server supplies HTTP/1.1 parsing and Qt Network supplies upstream connections. Requests are buffered up to the configured body limit (default 1 MiB); decoded body bytes are forwarded unchanged. Response bytes stream incrementally with normalized chunked framing. Hop-by-hop headers, including Connection-nominated fields, are removed; redirects are returned to the client, not followed. This is a local reverse proxy: the client changes its base URL. CONNECT and protocol upgrades are rejected. Only loopback listening is allowed.

Limits: 24 accepted downstream sockets, 8 active relays, 32 KiB headers, 4 KiB URL, 100 header fields, 64 KiB upstream read buffer, approximately 64 KiB downstream socket queue, 2-second default transfer timeout and keep-alive idle timeout, 100 default history rows and an independent 8 MiB retained-body cap. Oversized requests are rejected by the mature parser. Settings are configurable through ProxyOptions where exposed; GUI currently offers listen port only. Explicit proxy configuration accepts loopback clients and upstreams on the same device; future ARP preflight retains distinct LAN peer requirements. ProxyServer lifecycle/history methods must be called on its owning thread; network/parser work runs on a separate Qt thread.

GPL-3.0-only, Copyright © 2026 waterboy741. Qt HTTP Server is used under its GPLv3 terms. See [LICENSE](LICENSE) and [licensing details](docs/LICENSING.md).

The current request list shows method, configured path, response status, and original JSON body details. Details use the displayed record snapshot, so eviction cannot substitute a different request. Rich metadata and interactive list filtering are deferred to M5. See [offline baseline](docs/M2_BASELINE.md) for repeatable measurements and provisional performance targets.

Repeated request Cookie fields are joined with semicolons; supported standard list-valued fields are joined with commas before Qt Network sends them. Repeated fields outside these supported classes, including unknown custom fields and singleton authentication/content-type fields, return HTTP 400 explicitly instead of silently losing a value. Response Set-Cookie fields remain separate.

M3 adds explicit Modify mode, bounded manual request holds, ordered JSON rules, raw original/edited audit, and JSON path diff previews. Timeout/Observe switching forwards originals; stopping cancels pending holds. See [modification behavior and limits](docs/M3_MODIFICATION.md).

M4 adds the offline network-helper module with synthetic ARP/PF plans, injected preflight/lifecycle operations, conditional rollback, and watchdog/recovery ownership tests. No real network backend or GUI ARP activation is available. See [offline helper design and limitations](docs/M4_OFFLINE_HELPER.md).
