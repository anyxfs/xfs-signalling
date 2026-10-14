# AnyXFS signalling server

The rendezvous server behind [AnyXFS (安传)](https://www.anyxfs.com), a free app for
sending files directly between your own devices — Windows, macOS, Android and iOS.

On the same network, AnyXFS devices find each other by themselves and never touch
this server. Across networks, two devices use it to meet by an 8-digit pairing code
and exchange WebRTC connection descriptions; then they talk directly, end-to-end
encrypted. If no direct path exists, they relay through a TURN server
([coturn](https://github.com/coturn/coturn)), which only ever sees encrypted data.

This repository is published so that what we say about the server can be checked:
what it receives, what it keeps (very little, see [PROTOCOL.md §5](PROTOCOL.md#5-what-the-server-keeps)),
and how the relay is configured. The AnyXFS apps themselves are not part of it.

- [PROTOCOL.md](PROTOCOL.md) — the wire protocol and what the server stores
- [`deploy/`](deploy) — the systemd unit, coturn configuration and host scripts we use

## Build and test

Go 1.25 or newer.

```sh
go test ./...
go vet ./...
go build -o bin/xfs-signalling ./cmd/xfs-signalling
```

Run locally (plain WebSocket is only allowed on loopback):

```sh
./bin/xfs-signalling -listen 127.0.0.1:8787 -stun stun:stun.l.google.com:19302
# ws://127.0.0.1:8787/signal, subprotocol xfs-signal.dev.v1; GET /healthz
```

## Command-line flags

| Flag | Purpose |
| :--- | :--- |
| `-listen`, `-tls-cert`, `-tls-key` | Address and TLS certificate; the certificate is reloaded when its files change, no restart needed |
| `-stun` | Default STUN URLs offered to clients |
| `-turn-urls`, `-turn-secret-file` | TURN URLs (at most two nodes) and the file holding the coturn `static-auth-secret` |
| `-regions-file` | Per-region STUN / TURN lists and the offline country database ([example](deploy/regions.json)) |
| `-events-db` | SQLite file for anonymous usage events ([PROTOCOL.md §5](PROTOCOL.md#5-what-the-server-keeps)) |
| `-ticket-key-file` | Keeps resume-ticket keys across restarts |
| `-retired-codes-file` | Keeps recently used pairing codes out of reuse across a clean restart |
| `-allowed-origins` | Extra browser origins allowed to connect |
| `-max-connections`, `-ip-connections`, `-prefix-connections`, `-connect-capacity` | Connection admission limits |
| `-metrics-listen` | Prometheus `/metrics` on an explicit loopback address |

`go run ./cmd/xfs-turn-check` checks a deployment: it fetches TURN credentials the
way a client does, and with `-probe-unauth host:3478` / `-probe-peers host:3478` it
verifies that coturn refuses unauthenticated allocations and refuses to relay into
private, loopback, link-local and cloud-metadata addresses (including the
`::ffff:127.0.0.1` form of CVE-2026-27624).

## Deployment

What we run: the signalling server on one host (TCP 443) and coturn on another
(UDP/TCP 3478, UDP 49152–65535), both with IPv4 and IPv6.

- `deploy/signal-host.sh` (RHEL family) installs the binary, the systemd unit
  `deploy/xfs-signalling.service`, `deploy/regions.json` and a country database
  (DB-IP "IP to Country Lite", CC BY 4.0, downloaded at deploy time), then starts
  the service once a TLS certificate is in `/etc/xfs/tls/`.
- `deploy/turn-host.sh` (Ubuntu) runs coturn from the official image
  `coturn/coturn:4.18.0` with `deploy/turnserver.conf`, then runs both
  `xfs-turn-check` probes. Distribution packages of coturn older than 4.10 are not
  safe for this use.
- Both hosts share one secret file (`/etc/xfs/turn-secret`): coturn checks the
  credentials the signalling server signs with it. Keep it out of any repository.
- `deploy/90-xfs.conf` holds the kernel settings (SYN cookies, UDP buffers).

Volumetric DDoS is not something a process can defend against; that is left to
the hosting provider.

## License

[Apache License 2.0](LICENSE). See [NOTICE](NOTICE). The names "AnyXFS" and "安传"
and the logo are not licensed for reuse.

---

## 中文简介

这是 [安传 AnyXFS](https://www.anyxfs.cn) 的信令服务器源码。安传是免费的设备间传文件应用，覆盖 Windows、macOS、Android 与 iOS。同一网络内的传输完全不经过这台服务器；跨网时，两台设备通过它用 8 位配对码碰头、交换连接信息，之后直接连接并端到端加密；无法直连时经开源中继 coturn 转发，中继只能看到密文。

公开源码是为了让大家能核实我们的说法：服务器收到什么、保存什么（很少，见 [PROTOCOL.md 第 5 节](PROTOCOL.md#5-what-the-server-keeps)）、中继如何配置。安传应用本身不在本仓库中。许可证为 Apache-2.0；"安传""AnyXFS"名称与标志不在授权范围内。
