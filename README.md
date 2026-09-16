# Placitum rewrite

English · [Русский](README.ru.md)

Placitum response rewriting inspector. It edits what goes to the client: removal, replacement and
insertion by regular expressions in the response body, plus header operations. It works in the
response phase. Profiles are groups of modifiers with conditions on status and content type, on by
default or turned on by a neighbour's request (`mutate` or `skip` on the action channel).

## How it works

Bytes do not travel over the bus. With `waf_hold response gate` the module holds the response and
puts its body into the exchange (Redis). The inspector reads the object by locator, applies the
active groups and puts the rewritten copy under `<node>:<rid>:rsp:out`. The reply carries the object
address, the header operations and the names of the applied groups; the module checks that the key
prefix matches its request, takes the object, swaps the held body, fixes `Content-Length` and
releases the response. Regular expressions run only here, with Go's RE2 engine in linear time: the
module never compiles expressions from the wire.

## Profile

```yaml
mode: enforce            # printed by the controller; the call mode is set on the route (waf_inspect … mode=).
                         # In files, observe computes the rewrite but sends the response untouched with
                         # REWRITE_OBSERVE; write "off" in quotes (YAML 1.1)
deny_response: rewrite_failed   # deny response record for a failed swap

groups:
  - name: mask_pii
    default: false       # turned on by a mutate request
    status: [200]
    content_type: [application/json, +json]
    body:
      - { op: replace, pattern: '\b(\d{4})\d{8}(\d{4})\b', to: "$1********$2" }
      - { op: remove,  pattern: "debug-token=[a-z0-9]+" }
      - { op: insert_before, pattern: "</body>", text: "<!-- filtered -->", max_matches: 1 }
  - name: strip_server
    default: true
    headers:
      - { op: unset, name: Server }
      - { op: set, name: X-Frame-Options, value: DENY }

trigger:
  prior:
    - { from: action, accept: [mutate], codes: [PII_SUSPECT] }
    - { from: modsec, accept: [skip] }
```

Both accepted verbs can weaken protection, so `from: "*"` is rejected.

Profiles are edited in the panel: generations from the controller override the image profiles, and
the YAML above is the form in which a generation reaches the process. An acceptance rule says whom
to accept requests from and for which reason; the sender names the group and what to do with it
(`group` and `set`) in the request. An unknown group shows up as `unknown_group` in the audit.

`from` is a declaration name, not a process name: two declarations of one process (`action`,
`action-strict`) are two different senders, and each needs its own rule.

Header restrictions mirror the module: `set Set-Cookie` is not allowed (that is the cookie channel),
`unset Set-Cookie` is; `set Content-Type` is allowed, `unset` is not; `Content-Length` and the rest
of the mechanics belong to the module.

## WebSocket frames

After an upgrade the module asks the inspector about every frame if the route names it in
`waf_inspect frame:c2s|frame:s2c|frame`. Frame groups (`on: frame`) apply to the frame payload the
same way: the inspector puts the rewritten copy under `<node>:<rid>:frm:out`, and the module
rebuilds the frame with the same opcode and fin (client frames with the original mask). Frames are
handled one by one, without reassembly, so an expression does not match across fragments.

```yaml
groups:
  - name: ws_in                 # client words are masked before the application sees them
    default: true
    on: frame
    direction: [c2s]
    body:
      - { op: replace, pattern: "badword", to: "***" }
  - name: ws_out                # application secrets are masked before the client sees them
    default: true
    on: frame
    direction: [s2c]
    opcode: [text]
    body:
      - { op: replace, pattern: "secret-[0-9]+", to: "secret-***" }
```

Frame group conditions are `direction` (`c2s`, `s2c`; empty means both) and `opcode` (`text`,
`binary`, `continuation`; empty means `text` only). Frame groups have no status, content type or
header operations, and response groups (`on: response`, the default) do not touch frames. `mutate`
and `skip` work within a frame: a neighbour on an earlier wave can turn a group on for the same
frame. When the module fails to pick up the rewritten frame, the direction exception decides
(`waf_exception <direction> body`): `deny` closes the connection, `pass` sends the original. The
route must capture the payload (`waf_capture frame body=`).

## Route setup

```jsonc
"capture":       ["request headers args body", "response headers body"],
"responseHold":  "gate",
"bodyLimit":     "response 4m",   "bodyLimitPolicy":        "pass",
"responseDeadlineMs": 3000,       "responseDeadlinePolicy": "pass",
"responseInspectors": [{ "name": "rewrite", "wave": 0, "timeoutMs": 2500 }]
```

- **Capture the whole body and hold the response.** With `monitor` the swap never happens: the
  released response is already with the client, and the record shows `applied: false`.
- **Set a response body limit.** The module default is `1m block`: once the response phase is on, a
  page larger than a megabyte goes to the client as a denial.
- **Give the phase a deadline.** The default is 50 ms, while half a megabyte has to be read from the
  exchange, rewritten and written back. The `pass` policy keeps the page when the rewrite is late.
- **No neighbours with `resume=require` in this phase**: the phase waits for them until the
  deadline, and the rewrite answer is lost with it.
- **Compressed upstream responses are not rewritten**: the body snapshot asks the upstream for
  `Accept-Encoding: identity`.
- **The archive and the preview keep the original**; the audit record marks the difference with a
  `rewrite` section.

## In the audit

The `rewrite` section of every participant reaches the incident card, and the panel shows a note
such as "response rewrite applied · mask, hdrs · 128B". `applied: false` is not a skip: that is how
an observing profile and a losing order look (only one object is taken), and the groups next to it
tell what would have been applied. An observing file profile (`mode: observe`) only mutes the
rewrite: the response goes out untouched with `REWRITE_OBSERVE` (or `REWRITE_NOOP` when there was
nothing to apply), and the `kind=inspector` event has `engine.passive: true` and `would_apply`.

The image health check, `rewrite-probe`, takes the real inspection path and checks that the
`_probe` profile applied its header group, without Redis and without traffic.

What it needs and all settings are in [INSTALL.md](INSTALL.md).

## License

[Placitum License Agreement](LICENSE.md). A Russian translation is in [LICENSE.ru.md](LICENSE.ru.md);
the English text is the legally binding one.
