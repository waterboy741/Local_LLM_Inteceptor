# HTTP Traffic Redirection: macOS Design Investigation

Date: October 8, 2026. Research and proposed design; no live redirection has been tested or enabled.

## The central distinction

A destination MAC address determines which interface receives an Ethernet frame. The destination IP address determines whether the enclosed packet is delivered locally or routed onward. Receiving the frame does not automatically deliver its TCP payload to a listening application.

ARP maps a next-hop IPv4 address to a link-layer address; changing that mapping changes the Ethernet destination, not the IP destination. See [RFC 826](https://www.rfc-editor.org/info/rfc826/).

All addresses and ports below are illustrative examples. Port 11434 is Ollama's default, not a required application setting. A session configures interface, client IPv4, LLM IPv4, LLM TCP port (1–65535), and API paths; validate them and freeze one immutable snapshot used for preflight, PF matching, and upstream routing. Actual lab values are needed only to activate and validate a live experiment.

Illustrative lab addresses:

| Role | IPv4 address | Symbolic MAC |
| --- | --- | --- |
| Client | 192.168.50.10 | C |
| Research Mac | 192.168.50.20 | P |
| LLM server | 192.168.50.30 | S |

After client-side ARP redirection, a new connection may arrive as:

```text
Ethernet: C -> P
IPv4:    192.168.50.10 -> 192.168.50.30
TCP:     53000 -> 11434
```

The MAC is correct for delivery to the research Mac. The IP is still the server's. This is normal router-like traffic, not a malformed frame.

Three different capabilities must be distinguished:

| Mechanism | Sees packet content? | Accepts the client TCP connection? | Suitable for JSON editing? |
| --- | --- | --- | --- |
| BPF/libpcap capture | Yes, if the frame reaches the capture interface | No | Only with a separate transport interception design |
| IP forwarding | Kernel routes packets onward | No | No application-level editing by itself |
| PF destination redirection plus TCP proxy | Proxy receives a TCP byte stream | Yes, for newly intercepted connections | Yes |

The installed macOS `bpf(4)` manual describes a link-layer interface that gives matching listeners packet copies. Reading a copy neither consumes the kernel's packet nor suppresses forwarding. Promiscuous mode does not solve local IP delivery, and is ordinarily unnecessary for frames already addressed to P. It also cannot force a switch or access point to deliver traffic it would otherwise withhold.

Without redirection, an ordinary wildcard listener does not claim every destination IP. `0.0.0.0` means local addresses, not arbitrary foreign addresses. Without a local destination or forwarding path, the incoming packet will not reach that listener. Apple's [IPv4 input source](https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/netinet/ip_input.c) distinguishes local delivery and forwarding; published source is supporting evidence, not proof of the running kernel's exact behavior.

## Proposed mechanism: PF redirection and two TCP connections

Use ARP only to get selected traffic onto the Mac. Use macOS Packet Filter (PF) to translate the selected incoming TCP destination to a local proxy listener. The operating system supplies TCP reassembly and reliability; the application parses HTTP from socket bytes.

```text
Client thinks it connects to server:11434
  -> Ethernet frame reaches research Mac
  -> PF translates selected destination to local proxy:18080
  -> kernel TCP stack accepts the connection
  -> HTTP proxy inspects or edits the JSON request
  -> separate upstream TCP connection to real server:11434

Server responds to research Mac's upstream connection
  -> proxy streams response over the downstream connection
  -> PF reverses downstream address translation
  -> client sees replies from server:11434
```

The installed `pf.conf(5)` manual's TRANSLATION section states that PF tracks original addresses in connection state, updates addresses/ports and checksums, and translates return traffic. It documents inbound `rdr` to a local address. This is the mechanism that resolves the MAC/IP mismatch.

Conceptual flow identities, using a loopback listener:

| View | Source | Destination |
| --- | --- | --- |
| Client's original connection | client:53000 | server:11434 |
| Translated downstream connection | client:53000 | 127.0.0.1:18080 |
| Independent upstream connection | research-Mac:ephemeral | server:11434 |
| Reply visible to client | server:11434 | client:53000 |

The upstream server sees the research Mac's source IP. Preserving the client's source IP would add routing and source-spoofing complexity and is not part of the initial design. Do not silently add forwarding headers; that changes application-visible behavior.

The proposed redirection match must include the incoming interface, IPv4, TCP, configured client address, configured server address, and configured server port. This avoids catching the application's locally originated upstream connections. Use the configured upstream endpoint for the first single-server implementation. For multiple targets later, obtain the original destination from validated PF connection state; do not trust an HTTP Host header to select an arbitrary upstream destination.

[mitmproxy's own macOS documentation](https://docs.mitmproxy.org/stable/howto/transparent/#macos) provides an existing example of PF-to-local-listener interception and describes original-destination discovery. Its broad example rules and system-wide setup are not a suitable application lifecycle design to copy verbatim. Current macOS behavior and coexistence with other networking software still require lab verification.

## Why separate TCP connections matter

A JSON body can span multiple TCP segments; one segment can contain parts of multiple HTTP messages. TCP also retransmits and delivers data in order independently of how captures are grouped. Changing a body length in individual packets would require sequence/acknowledgment translation, retransmission handling, flow control, and consistent behavior in both directions. See [RFC 9293](https://www.rfc-editor.org/rfc/rfc9293.html).

Two socket connections let the kernel handle those details separately. The HTTP layer must still correctly handle framing, keep-alive, chunked transfer coding, Content-Length, Expect: 100-continue, cancellation, body limits, and malformed/ambiguous messages. It must reject ambiguous framing rather than interpret it differently from the server. Edited requests need new framing; streamed responses should flow incrementally with bounded backpressure. See [RFC 9112](https://www.rfc-editor.org/rfc/rfc9112.html).

An editable request must be held before sending its body upstream. Bytes already delivered to the LLM cannot be recalled. Observe mode may relay incrementally; Modify mode needs bounded buffering for requests that may be edited.

## ARP scope, return paths, and bypass traffic

ARP selects a neighbor for an IP address, not a TCP port. Redirecting the client's server-IP mapping also attracts that client's other IPv4 traffic to the same server. The design therefore needs two paths:

1. Selected LLM TCP port: PF redirection and application proxy.
2. Other traffic attracted by ARP: kernel forwarding under scoped policy, without application content retention.

Filtering by HTTP path happens only after a TCP connection enters the proxy. Nonmatching requests on the same keep-alive connection must still be relayed through that proxy. They cannot be moved back to kernel forwarding mid-connection.

For the proxied flow, a separate upstream connection naturally returns to the research Mac. Server-side ARP redirection is not inherently needed for those upstream replies. For complete bidirectional visibility of forwarded, nonproxied flows, both client and server paths must traverse the Mac. One-sided ARP redirection can yield asymmetric forwarding; PF state policy and diagnostics must account for that. Choose and test one topology rather than assuming both cases behave identically.

The Mac must retain correct neighbor mappings for the real client and server. Test for accidental self-delivery and loops. Same-interface routing also warrants checking ICMP redirects: the Mac must not tell the client to bypass the research path. Apple's IPv4 source exposes forwarding and redirect controls; their exact use and restoration belong in the privileged helper's platform validation.

This design assumes same-subnet peers. If the client actually routes through a gateway, it resolves the gateway's MAC instead of the remote server's MAC. ARP operates on the local link; a routed/VLAN-separated topology needs a different interception placement. Wi-Fi client isolation, static neighbor mappings, and network ARP protections may prevent the experiment. Prefer wired lab validation first.

## Existing connections and lifecycle

Intercept from the initial TCP SYN. A listener cannot adopt an already established client/server connection merely because packets start arriving at its MAC. For the first implementation, require the research client to reconnect after activation. Do not claim seamless takeover of existing keep-alive or streaming connections.

Proposed activation sequence:

1. Validate interface, addresses, topology, server reachability, and forwarding/proxy support.
2. Snapshot settings the helper will own and start the bounded proxy listener.
3. Install narrowly scoped PF policy and verify its attachment and counters.
4. Prepare bypass forwarding and watchdog recovery.
5. Activate ARP redirection and open a fresh client connection.
6. Declare the session healthy only after packet arrival, socket acceptance, upstream delivery, and downstream response are demonstrated.

Shutdown is a connection transition, not just deletion of an ARP rule. Stop new experiment traffic and drain or explicitly terminate proxied connections before restoring the direct path. Restoring ARP while a proxied connection remains active sends its packets to the real server, which does not own that downstream TCP connection.

A GUI crash can be handled by a surviving helper watchdog. A proxy crash loses proxy-owned TCP connections; cleanup can restore future connectivity but cannot reconstruct those streams. Test recovery delays instead of promising uninterrupted fail-open behavior.

## macOS integration and privilege boundary

- Keep the GUI and HTTP parser unprivileged. Give a narrow helper responsibility for network-state changes, packet injection/capture setup, and cleanup.
- Use an application-owned PF anchor with verified translation/filter attachment points. Loading an anchor does not prove the active ruleset evaluates it.
- Inspect rule ordering and coexistence with VPNs, Internet Sharing, and other filters. The on-disk `/etc/pf.conf` is not proof of active runtime policy.
- Do not flush the global ruleset or state table. The installed `/etc/pf.conf` explicitly warns that other services dynamically insert anchors.
- Use PF enable-reference ownership as documented by the installed `pfctl(8)` manual (`-E` and token release with `-X`), rather than globally disabling PF during cleanup.
- Track application connection state and remove only state demonstrably owned by the session when necessary. Removing a rule alone may leave established state operating under old translation.
- Snapshot and conditionally restore global forwarding/redirect settings; account for concurrent owners and expose conflicts rather than overwriting their changes.
- Validate IPC requests and allow only the active target pair and approved operations. A loopback-bound listener becomes externally reachable through redirection; restrict its ingress accordingly.

Apple's [NEAppProxyProvider documentation](https://developer.apple.com/documentation/networkextension/neappproxyprovider) describes flows corresponding to sockets opened by apps, and [transparent-proxy network rules](https://developer.apple.com/documentation/networkextension/netransparentproxynetworksettings/includednetworkrules) require outbound direction. These do not establish that arbitrary transit frames from a different device will be delivered as flows. Therefore Network Extension is not the selected mechanism for this external-client topology without a separate feasibility demonstration. Also, modern OpenBSD/Linux interception syntax must not be assumed to work on macOS PF.

## Proof required before implementation is considered feasible

Use a disposable HTTP echo/mock server before involving an LLM. Record results, exact macOS version, interface type, relevant active policy, and packet traces with synthetic content.

| Test | Required evidence |
| --- | --- |
| Frame arrival | Client-to-Mac destination MAC with unchanged server destination IP |
| Capture versus delivery | Capture sees the frame; listener acceptance is independently measured |
| PF interception | Fresh SYN reaches proxy listener and creates the expected translation state |
| Upstream independence | Server sees a distinct Mac-to-server connection, with no recursion |
| Reverse translation | Client receives SYN-ACK and HTTP response with expected server IP/port |
| JSON modification | Longer and shorter JSON bodies arrive correctly and exactly once at mock server |
| HTTP streaming | Incremental SSE and newline-delimited JSON responses remain incremental |
| Bypass forwarding | A second server port works without content appearing in request history |
| Existing connection | Documented reconnect behavior; no claim of stream adoption |
| Failures | Listener absent, upstream refusal, cancellation, interface loss, GUI/proxy failure, and partial startup |
| Cleanup | Repeated start/stop restores connectivity and preserves unrelated PF rules/state |

Diagnostic stages in the GUI should distinguish: redirection active, frames received, PF match, proxy connection accepted, request parsed, upstream connected, and response relayed. A green ARP status alone is insufficient evidence of a working interceptor.

Recommendation: proceed with a single-target PF redirect-to-local-proxy proof of concept. The architectural answer is supported by macOS documentation and existing transparent-proxy practice; operational compatibility on this research network is deferred to the M6 lab validation milestone; it does not block offline M0–M5 work.
