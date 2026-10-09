# Offline JSON modification

M3 uses only the explicitly activated local reverse proxy; no ARP/PF or lab assets are required. Observe remains the default. Choose Modify and apply the complete mode/rule configuration before edits can occur. The Apply action validates the entire set atomically; invalid settings leave the previous configuration in place.

Rules are ordered JSON objects with `id`, `path`, optional `model`, `fieldPath` (object-field names), and `value`. They replace an existing field once per request; missing fields and intermediate nonobjects remain unchanged. Model conditions see the current object after earlier rules. Unknown fields and Unicode are preserved semantically; rule edits serialize compact JSON. Arrays can be replaced as whole values but array-index traversal is outside initial scope.

Example:

```json
[{"id":"synthetic-prompt","path":"/api/generate","fieldPath":["prompt"],"value":"Synthetic replacement"}]
```

Manual hold occurs before upstream submission. The Held requests tab shows original/proposed JSON and remaining time. Editing does not send bytes. Validate and forward edit preserves exactly the entered UTF-8 bytes after validation; Forward original ignores the editor and sends exact incoming bytes. The editor retains unsent changes through history polling. Changed JSON paths and old/new values appear as a bounded +/- preview; original raw body remains in request details.

Timeout defaults to 30 seconds and forwards the exact original. Changing to Observe explicitly forwards all existing held originals; it does not apply proposed rules. Other configuration changes are rejected while requests are held. Stop, client cancellation, and disconnect cancel pending holds without upstream submission. Expired/stale IDs cannot edit newer requests; IDs remain monotonic across restarts. No submitted generation is retried by the modification layer.

Editable requests must be matching POST JSON objects with a nonempty string model, within the configured editable-size bound and depth 32. `/api/generate` prompt, when present, must be a string; absence permits model unload/control requests. `/api/chat` messages, when present, must be an array of objects with a supported role (system/user/assistant/tool) and string content. Other fields are preserved. Unsupported extended message representations are not edited. Invalid manual edits remain held. Invalid rule-generated schemas fall back to original bytes with audit. Unsupported/oversized initial bodies are forwarded unchanged up to the transport body limit.

Integrity headers Digest, Content-MD5, Signature, Signature-Input and non-Basic/non-Bearer Authorization schemes disable edits and holds. This conservative detection does not discover every proprietary signing scheme; use Observe for unknown signed APIs. Encoded request bodies are never edited.

Limits: 8 total active/held requests, up to 8 manual holds, 1 MiB editable body each, 32 rules, 16 object-path segments, 64-character rule IDs, 128-character path segments, 64 KiB serialized rule value, and 32 JSON levels. Original/proposed held bodies share storage until changed; changed pairs are bounded by 16 MiB total. History retains at most configured rows and 8 MiB of distinct original/modified bytes. Full hold capacity returns 503. Diff preview is capped at 64 changed paths, 1024 characters per value, and 65536 characters total.

Audit records original/modified bytes, modification status, and applied rule/manual action. Proposed rule IDs are explicitly marked as proposals on manually edited release and omitted on manual original release. Upstream refusal/timeout retains the attempted edit with 502/504 status. Undispatched stop-canceled holds do not create a submitted-request record.

Tests use synthetic local mocks; live routing and actual Ollama validation remain M6. The existing Qt empty-final-chunk diagnostic remains documented in the M2 baseline.
