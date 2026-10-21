# AnyXFS signalling protocol (`xfs-signal.dev.v1`)

The signalling server lets two AnyXFS devices that are on different networks find
each other by a pairing code, exchange WebRTC connection descriptions, obtain
short-lived TURN relay credentials, and meet again after a disconnection. It never
sees files: once the two devices are connected, everything travels directly
between them (or, if no direct path exists, through a TURN relay), end-to-end
encrypted by the devices themselves. Connecting through the server is **not**
authentication: the devices authenticate each other afterwards, inside their own
encrypted channel, and the people using them compare a short visual code.

This document describes what the server in this repository implements. The
source is the reference; where they differ, the code wins and this file is wrong.

## 1. Transport

- WebSocket at `/signal`, over TLS (`wss://`) in production. Plain `ws://` is only
  accepted on a loopback address.
- The client **must** offer the WebSocket subprotocol `xfs-signal.dev.v1`.
- `GET /healthz` answers `{"status":"ok","profile":"development"}`.
- Before the upgrade, connections are admitted per source: per IPv4 address /
  IPv6 /64, per IPv4 /24 / IPv6 /48, and a rate of new connections per address.
  A refused upgrade gets HTTP `429` with `Retry-After`, or `503`. Forwarded-for
  headers are never trusted.
- Browsers may connect only from the same host, or from origins listed with
  `-allowed-origins`. Native clients send no `Origin`.

## 2. Messages

Every message is one WebSocket **text** frame holding one UTF-8 JSON object, at
most 64 KiB by default (`-max-message-bytes`); a larger frame closes the
connection with code 1009. Decoding is strict: duplicate keys, unknown keys,
`null` values and trailing data are rejected (`8001`, connection closed).

| Field | Meaning |
| :--- | :--- |
| `t` | Message type (required) |
| `id` | Optional request id: exactly 8 bytes, unpadded base64url. Echoed in the direct response. |

Binary values (keys, nonces, signatures, hashes) are unpadded base64url.

### 2.1 Opening a session

The first message must be `hello`, within 5 seconds:

```json
{"t":"hello","v":1,"client":"anyxfs/1.0.3 (android)"}
```

`client` is optional, at most 128 bytes. Only the form
`anyxfs/<major.minor.patch> (<windows|macos|linux|android|ios>)` is recorded (see
§5); anything else counts as an unknown platform.

```json
{"t":"hello_ok","v":1,"minClientProto":1,"serverTime":1792000000,"region":"local","draining":false,"connNonce":"<32 bytes>","notices":[]}
```

`serverTime` is Unix seconds. `connNonce` is fresh for this connection and binds the
signatures in §2.4 and §2.5 to it. `notices` lists the operator's service notices
showing now (always present, possibly empty); see "Service notices" below. A first message other than `hello` gets `8003`,
an unsupported `v` gets `8002`; both close the connection.

Keep-alive: the server sends WebSocket pings every 20 s and closes a connection
that has been silent for 60 s. Clients may also send `{"t":"ping"}` and get
`{"t":"pong"}`.

### 2.2 Pairing by code

| Client sends | Server answers |
| :--- | :--- |
| `{"t":"create_room"}` | `{"t":"room_created","room":"<id>","code":"83920174","expiresAt":<unix>,"iceServers":[{"urls":["stun:…"]}]}` |
| `{"t":"join_room","code":"8392 0174"}` | to the joiner `{"t":"room_joined","room":"<id>","peerEphemeralId":"<id>","iceServers":[…]}`; to the creator `{"t":"peer_joined","room":"<id>","peerEphemeralId":"<id>"}` |

- Codes are 8 uniformly random digits, first digit non-zero. Spaces and hyphens
  in `join_room` are ignored. A code works once; after its room ends it is not
  handed out again for at least 10 minutes.
- The server keeps codes only as a keyed hash (HMAC-SHA256 under a random
  per-process key), never in clear.
- A wrong, used or expired code is always `8010`, answered no sooner than 300 ms.
  Repeated failures from one address or prefix escalate to `8012` / `8013` with
  `retryAfter` and a freeze of one minute, ten minutes, then one hour.
- `iceServers` holds STUN URLs chosen for the client's region (§4).
- One connection holds at most one room.

### 2.3 Exchanging connection descriptions

Once paired, either side may send

```json
{"t":"signal","room":"<id>","kind":"offer","payload":"<opaque string>"}
```

with `kind` one of `offer`, `answer`, `candidate`, `candidate_end`. The server
forwards it unchanged to the other side as
`{"t":"signal","room":"<id>","kind":…,"payload":…}` and never parses `payload`.

When the devices are connected, each sends

```json
{"t":"ready","room":"<id>","pkHash":"<16 bytes>"}
```

where `pkHash` is the first 16 bytes of SHA-256 of that device's identity public
key. When both have, the room ends and each side receives its own renewal ticket:

```json
{"t":"room_closed","room":"<id>","reason":0,"ticket":"<opaque>"}
```

Either side may end a room with `{"t":"bye","room":"<id>","reason":<uint>}`; both
get `room_closed` with that reason. If one side disconnects after pairing, the
other gets `{"t":"peer_left","room":"<id>","reason":8023}` and the room closes.

Room timers: an unpaired room lives 10 minutes (`8021` when it expires); pairing
must be completed within 2 minutes (`8022`); no room lives longer than 15
minutes. If the creator disconnects before anyone joins, the room is held for 60
seconds and then removed.

### 2.4 TURN relay credentials

```json
{"t":"turn_credentials","pk":"<Ed25519 public key, 32 bytes>","nonce":"<32 random bytes>","sig":"<64 bytes>"}
```

`sig` is an Ed25519 signature by `pk` over

```
"XFS-TURNREQ-v1" ‖ nonce ‖ u32_be(hello_ok.serverTime) ‖ SHA-256(connNonce)
```

and must arrive within 300 s of `hello_ok`. Because it covers this connection's
`connNonce`, a captured request cannot be replayed on another connection.

```json
{"t":"turn_credentials_ok","username":"1792003600:Ab3dE6gH","credential":"<base64>","ttl":3600,"urls":["stun:…","turn:…?transport=udp"]}
```

The credential follows the coturn REST scheme (`use-auth-secret`): `username` is
`<expiry>:<random>`, `credential` is base64(HMAC-SHA1(shared secret, username)).
The username contains no device identifier, and the public key is used only to
check the signature, then forgotten. `urls` are chosen for the client's region
(§4). Errors: bad signature or too late `8031`; no relay configured `8032`; more
than 5 requests a minute on one connection `8051`; the daily budget of the address spent (§3)
`8030` with `resetAt` (Unix seconds, the next midnight in Beijing time); the relay paused
by the operator `8032` with `"reason":"paused"`. Clients treat `8030` and `8032` as
"no relay this time" and still try a direct connection.

### 2.5 Meeting again after a disconnection

Each side keeps the ticket it received in `room_closed`. Tickets are opaque to
clients, valid 6 hours and at most 24 hours from the first one of a session,
signed with server keys that rotate daily (the current and previous key are
accepted). To meet again, both sides send

```json
{"t":"resume","ticket":"<ticket>","pk":"<identity public key>","ts":<unix seconds>,"sig":"<64 bytes>","sdpNeeded":true}
```

with `sig` an Ed25519 signature over

```
"XFS-RESUME-v1" ‖ ticket (the string as sent) ‖ u64_be(ts) ‖ connNonce
```

`ts` must be within 60 s of the server clock, and SHA-256(`pk`) must match the
identity the ticket was issued to. The server waits up to 2 minutes for the other
side of the same session, then sends each side

```json
{"t":"room_resumed","room":"<id>","peerEphemeralId":"<id>","peerSdpNeeded":true,"iceServers":[…]}
```

and the room continues as in §2.3. A bad ticket or signature gets `8060`; a newer
connection resuming the same side replaces the older one, which gets `8060`; a
wait that runs out gets `8021`. The server keeps no record of sessions: all it
needs is in the ticket.

### 2.6 Errors

```json
{"t":"error","code":8010,"message":"request rejected","retryAfter":2}
```

`retryAfter` (seconds) is present only when waiting helps.

| Code | Meaning |
| :--- | :--- |
| 8001 | Malformed or unexpected message (fatal for malformed input) |
| 8002 | Unsupported protocol version (fatal) |
| 8003 | First message was not `hello` (fatal) |
| 8010 | Pairing code unknown, used or expired |
| 8012 | Too many attempts; wait `retryAfter` |
| 8013 | Too many failed codes from this network; frozen for `retryAfter` |
| 8014 | Server is at its room capacity; try again shortly |
| 8020 | Not a member of that room |
| 8021 | Room or resume wait expired |
| 8022 | Pairing was not completed in time |
| 8023 | The other side left |
| 8031 | TURN request signature invalid or too late |
| 8030 | This address has used today's relay credentials; `resetAt` says when they come back |
| 8032 | No relay: none configured, or paused by the operator (`"reason":"paused"`); direct connections only |
| 8040 | Server-side capacity or internal error |
| 8050 | Forwarded message would exceed the size limit |
| 8051 | Too many messages on this connection |
| 8060 | Resume rejected (ticket, identity or signature) |


## Service notices

With `-notices-file`, the server reads a signed notices file every 5 s (only its
hash when unchanged) and sends the entries showing now in `hello_ok`:

```json
{"id":"maint-2026-10-25","level":"warning","startsAt":1792000000,"endsAt":1792090000,
 "title":{"zh-CN":"…","zh-TW":"…","en":"…","ja":"…"},"body":{…},"link":{"en":"https://…"}}
```

`level` is `info` or `warning`; `startsAt`/`endsAt` (Unix seconds) bound when the
notice is shown. `link` is optional and never sent to `ios` or `macos` clients.
The file is an envelope `{"payload":base64(JSON),"sig":base64(Ed25519),"key":"n1"}`
signed with the operator's key (`cmd/xfs-notice`); `-notices-pubkey` lists the
accepted public keys. A file that does not verify, or whose `issuedAt` is not newer
than the current one, is refused and the current version stays
(`sig_notices_rejected_total`). Its `relayPaused` flag makes `turn_credentials`
answer `8032` with `"reason":"paused"`.

## 3. Limits

Per connection (token buckets: a burst, then a steady refill): 60 messages, then
20 per second; 3 rooms created, then one every 20 s (and per address 10, then one
a minute); 5 join or resume attempts, then one every 30 s; 5 TURN credential
requests, then one every 12 s. Per address (IPv4 address or IPv6 /64): 300 TURN credentials a day (`-turn-daily-per-source`), counted per calendar day in Beijing time (UTC+8); beyond that `8030` with `resetAt`. The figure is generous because many users can share one address behind carrier NAT. Per address
and per prefix: join budgets, failure freezes (§2.2) and concurrent connection
caps. The defaults are in `internal/signal/server.go` and can be raised with
flags for testing.

## 4. Regions

With `-regions-file`, the server looks up the country of a connecting address
once, in an offline database on the server (no third-party query), and keeps only
the name of the region it falls in. Each region has its own STUN and TURN lists;
a region without its own list uses the default one. Example:
[`deploy/regions.json`](deploy/regions.json).

## 5. What the server keeps

| Data | Where | How long |
| :--- | :--- | :--- |
| Pairing codes | Memory, as keyed hashes | Until the room ends; hashes of ended codes 10 minutes more (also across a clean restart, with `-retired-codes-file`) |
| Client IP addresses | Memory, in rate-limit records only | About one hour after the last activity; for an address that drew TURN credentials, until the end of that Beijing day (at most 24 hours) |
| Connection descriptions (`payload`) | Not stored; forwarded as-is | — |
| Ticket keys | `-ticket-key-file` (two random keys) | Rotated daily |
| Anonymous events | `-events-db` (SQLite) | 400 days |

An anonymous event row holds only: the hour, the region, the event type
(`connect`, `rejected`, `room_created`, `room_paired`, `join_failed`,
`room_closed`, `resumed`, `resume_failed`, `turn_issued`, `turn_limited`), an error or close code,
the app platform and version from `hello`, and for a closed room how long it
lasted. It never holds an address, code, room, ticket, key or other identifier,
and rows cannot be linked to one another. See `internal/signal/events.go`.

The relay itself is [coturn](https://github.com/coturn/coturn); the configuration
used is [`deploy/turnserver.conf`](deploy/turnserver.conf). It relays only to public
addresses, and what it relays is end-to-end encrypted by the devices.
