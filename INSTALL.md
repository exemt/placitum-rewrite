# Installation

English · [Русский](INSTALL.ru.md)

The inspector does not listen on the network: it is a queue subscriber on the bus. It needs no
address and no service, and adding a copy touches neither the protection node nor the
configuration. Usually `placitum-core` installs it.

It works in the **response phase**, and that defines everything else: the response body does not
travel over the bus but lies in the buffer, where the module put it.

## What it needs

| Component | Required | Why |
| --- | --- | --- |
| NATS | yes | inspector queue, audit, log, profile generations |
| Buffer Redis | yes | the module puts the response body there; the inspector reads it and puts the rewritten copy under `<node>:<rid>:rsp:out` |
| Controller | yes | sends profiles as generations (`policy/rewrite` channel) |
| Action channel senders | no | groups that are off by default are turned on by their `mutate` requests |

Without the buffer the inspector has nothing to rewrite: it receives the response body only by
locator.

## Settings

| Variable | Default | Purpose |
| --- | --- | --- |
| `NATS_URL` | `nats://127.0.0.1:4222` | bus |
| `REDIS_URL` | from `inspector.conf` | buffer: response body and rewritten copy |
| `WAF_REWRITE_SUBJECT` | `waf.req.rewrite` | subscription; must match `subject=` in the inspector declaration |
| `WAF_REWRITE_NAME` | `rewrite` | name in the inspector registry and the presence frame |
| `WAF_REWRITE_QUEUE` | the name | bus queue: copies with one queue share the stream |
| `WAF_REWRITE_PROFILES` | `./profiles`; `/app/profiles` in the image | profiles; controller generations override them |
| `WAF_REWRITE_DATA` | `<profiles>.applied`; `/var/lib/waf/rewrite` in the image | where rollout puts the applied generation |
| `WAF_REWRITE_RELOAD_EVERY` | `1s` | how often to check the profile directory |
| `WAF_REWRITE_WORKERS` | number of CPUs | queue workers |
| `WAF_REWRITE_QUEUE_DEPTH`, `WAF_REWRITE_QUEUE_FULL`, `WAF_REWRITE_QUEUE_EXPAND` | `256`, `drop`, `off` | queue and overflow behaviour; the same through `inspector.conf` |
| `WAF_REWRITE_RESERVE_MS`, `WAF_REWRITE_MIN_BUDGET_MS` | `2`, `2` | reserve before the deadline and the minimum budget at which a message is still taken |
| `WAF_REWRITE_VERSIONS` | `2` | accepted message schema versions |
| `WAF_REWRITE_CONF` | `inspector.conf` in the working directory, then `/app/inspector.conf` | queue and Redis settings |
| `WAF_REWRITE_LOG` | `info` | starting log level; the panel changes it live |
| `WAF_HEARTBEAT_EVERY` | `4s` | presence frame interval |
| `WAF_LOG_SHIP` | `on` | whether the process log goes to the bus; `off` keeps it on stdout only |

## Docker Compose

```yaml
services:
  inspector-rewrite:
    image: placitum/rewrite
    scale: 2
    environment:
      NATS_URL: nats://nats:4222
      REDIS_URL: redis://redis:6379
      WAF_REWRITE_SUBJECT: waf.req.rewrite
      WAF_REWRITE_NAME: rewrite
    depends_on: [nats, redis]
```

## Checking

The inspector has no port of its own, so it is checked the way it works, with a bus message. The
probe in the image uses the `_probe` profile: a group with a single header operation, so the
`rewrite` section of the answer comes without Redis and without traffic.

```sh
docker exec <container> rewrite-probe --quiet --timeout 1s --uri /healthcheck
```

The image `HEALTHCHECK` does exactly this. A healthy start logs the bus connection, the queue name,
the loaded profiles and the worker count.

## Pitfalls

- **The subject lives in two places**: `WAF_REWRITE_SUBJECT` of the process and `subject=` in the
  module's inspector declaration. If they differ, the module waits on one subject, the inspector
  listens on another, and the deadline policy fires on every response.
- **The module and the inspector must use the same buffer.** The module puts the body into its
  Redis; an inspector reading another one answers that the object is missing, and the swap does not
  happen.
- **Regular expressions run only here.** The inspector compiles them (RE2, linear time), the module
  never sees them. A heavy expression costs response time, not node memory.
- **Quote `"off"` in profiles.** YAML 1.1 reads a bare `off` as `false`.
