# M0 synthetic fixtures

These small fixtures contain invented content and no captured traffic. The HTTP
requests use literal CRLF line endings and exact byte counts. `192.0.2.30` is an
illustrative documentation address. Server IPv4 address and HTTP port are session
configuration inputs; 11434 is an example/default only. A second fixture uses
`198.51.100.30:18081`, another documentation address and an alternate HTTP port.
`synthetic-fixture-model` is a placeholder,
not a model to install or assume is present on the actual server.

The selected baseline is Ollama native `POST /api/generate` over HTTP/1.1.
Request and response shapes follow [Ollama's generate API documentation](https://docs.ollama.com/api/generate)
and its [streaming documentation](https://docs.ollama.com/api/streaming), reviewed
October 8, 2026. Samples are deliberately minimal and are not captured output
from a running Ollama server.

- `generate-original.http`: JSON generation with streaming disabled.
- `generate-alternate-target.http`: identical generation body addressed to the
  alternate example server IPv4/port, demonstrating fixture coverage of both
  target configurations.
- `generate-shorter.http` and `generate-longer.http`: alternative prompt bodies
  with recomputed Content-Length for later modification tests.
- `generate-stream.http`: JSON generation with streaming enabled.
- `generate-response.json`: complete synthetic response.
- `generate-response.ndjson`: two partial responses followed by completion.
- `chat-original.http` and `chat-response.json`: alternate nonstreaming
  [Ollama chat API](https://docs.ollama.com/api/chat) shapes. The actual client
  application and its endpoint remain to be identified in the live lab.

Validate fixture integrity from the repository root:

```sh
python3 -m unittest discover -s tests -p 'test_m0_fixtures.py' -v
```

These checks validate fixture framing, API fields, alternate target data,
edit-case sizes, and NDJSON
record structure only. They do not demonstrate socket forwarding, incremental
delivery timing, application configuration validation, PF translation, capture,
ARP behavior, or live cleanup. Qt Test
and CTest integration belong to M1 when the build infrastructure exists.
