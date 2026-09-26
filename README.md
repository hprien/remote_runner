# remote_runner

Runs predefined scripts triggered via a REST API call.

remote-runner consists of two components:

- **remote-runner** — an unprivileged Go webserver that receives requests over
  a mutually authenticated TLS 1.3 connection, validates them and streams
  results to the client and/or delivers them to a webhook. It executes
  nothing itself.
- **task-helper** — a root daemon that owns the scripts. It is started by
  systemd socket activation, accepts exactly one connection peer (the
  remote-runner user, verified via the socket permissions and SO_PEERCRED),
  validates the script checksum and executes the requested script as root.

```text
client ── mTLS 1.3 (pinned certs) ──▶ remote-runner ── unix socket ──▶ task-helper ──▶ script (root)
        ◀── NDJSON stream / webhook ──┘   (user: remote-runner)  │      (root owned scripts)
                                                  socket: /run/remote-runner/task.sock
                                                  mode 0660 root:remote-runner
```

The privilege boundary: whoever administers the root owned scripts directory
administers root execution. The web daemon can trigger scripts and read their
output — it can never read, modify or add script files.

## Building

```console
$ go build -o remote-runner .
$ go build -o task-helper ./task-helper
```

## Configuration

### remote-runner

All settings are command line flags:

| Flag | Default | Description |
|------|---------|-------------|
| `-listen` | `:8443` | Listen address (host:port) |
| `-task-socket` | — | Unix socket of the task helper (required) |
| `-server-cert` | — | PEM server certificate (required) |
| `-server-key` | — | PEM server key (required) |
| `-client-cert` | — | PEM client certificate that is pinned for authentication (required) |
| `-max-concurrent` | `4` | Maximum number of scripts running simultaneously |
| `-max-script-timeout-seconds` | `3600` | Maximum allowed `script_timeout_seconds` per request |
| `-max-webhook-delay-seconds` | `300` | Maximum allowed `webhook_delay_seconds` per request |
| `-webhook-timeout-seconds` | `30` | Timeout for outgoing webhook calls |
| `-webhook-client-cert` | — | PEM certificate presented to the webhook server |
| `-webhook-client-key` | — | PEM key for the webhook client certificate |
| `-webhook-server-cert` | — | PEM certificate of the webhook server that is pinned |

`-webhook-client-cert` and `-webhook-client-key` must be set together.

### task-helper

| Flag | Default | Description |
|------|---------|-------------|
| `-scripts-dir` | `/var/lib/remote-runner/scripts` | Root owned directory containing one folder per script |
| `-allowed-user` | `remote-runner` | The only user allowed to connect to the socket |
| `-max-concurrent` | `4` | Maximum number of scripts running simultaneously |
| `-max-script-timeout-seconds` | `3600` | Maximum allowed `script_timeout_seconds` per request |

The helper refuses to start when it was not started via systemd socket
activation, so the socket file and its permissions are always controlled by
the socket unit.

## Certificates

remote-runner authenticates itself with a self-signed server certificate and
authenticates users with a self-signed client certificate. Certificates are
**not** validated against a CA — they are **pinned**: a connection is only
accepted if the certificate presented by the peer is byte-identical to the
pinned one. TLS 1.3 is enforced for every connection (older versions are
refused at the handshake).

### Create a certificate and key

```console
$ openssl req -x509 -newkey ed25519 \
    -keyout server.key -out server.crt -days 3650 -nodes \
    -subj "/CN=127.0.0.1"
```
[Check curve security](https://safecurves.cr.yp.to/)

### Calling the API

```console
$ curl -i --tlsv1.3 \
    --cert client.crt --key client.key \
    --cacert server.crt \
    --data '{"script_name":"hello","script_checksum":"99647781e902f1de358822b26692771cedadd972c5fd83f9421a39464572d444","stream_script_stdout_stderr":true,"script_timeout_seconds":60}' \
    https://127.0.0.1:8443/run
```

## Scripts

Each script lives in its own folder inside the task-helper's `-scripts-dir`
and must be an executable regular file (no symlinks) named after the folder.
Scripts run **as root**, so the directory must be owned and only writable by
root:

```text
/var/lib/remote-runner/scripts/
└── hello/
    └── hello      (executable)
```

```console
$ chmod +x scripts/hello/hello
$ sha256sum scripts/hello/hello
99647781e902f1de358822b26692771cedadd972c5fd83f9421a39464572d444  scripts/hello/hello
```

## API

`POST /run` with body `application/json` (maximum 16 KiB):

| Field | Type | Required | Constraints |
|-------|------|----------|-------------|
| `script_name` | string | yes | must match an existing script folder |
| `script_checksum` | string | yes | SHA-256 hex checksum (64 hex chars) of the executable |
| `stream_script_stdout_stderr` | bool | yes | stream stdout/stderr to the client |
| `script_response_webhook_url` | string | no | must be an `https://` URL |
| `webhook_delay_seconds` | int | no | 0 … `-max-webhook-delay-seconds`, only allowed together with `script_response_webhook_url` |
| `script_timeout_seconds` | int | yes | 1 … `-max-script-timeout-seconds`; the script is terminated when it exceeds this |

Unknown fields, trailing data and invalid values are rejected.

Responses are newline delimited JSON (NDJSON,
`Content-Type: application/x-ndjson`). Every response starts with a status
object:

```json
{"type":"accepted","script_name":"hello","message":"Script execution started"}
```

or, when all concurrency slots are taken:

```json
{"type":"denied","script_name":"hello","message":"too many concurrent scripts"}
```

When `stream_script_stdout_stderr` is `true`, output chunks follow as

```json
{"type":"stdout","txt":"hello stdout\n"}
{"type":"stderr","txt":"hello stderr\n"}
```

Invalid requests get a `400 bad request`
Unauthenticated requests get a `403 forbidden`.

### Webhook

When `script_response_webhook_url` is set, the result is POSTed to that URL
`webhook_delay_seconds` after the script finished (or was terminated):

```json
{
  "script_name": "hello",
  "stdout": "hello stdout\n",
  "stderr": "hello stderr\n",
  "return_code": 0
}
```

A `return_code` of `-1` means the script was terminated because
`script_timeout_seconds` was exceeded.

## Run as a system service

Create a dedicated user without login shell and the scripts home:

```console
$ useradd --system --home-dir /var/lib/remote-runner --create-home \
    --shell /usr/sbin/nologin remote-runner
$ mkdir -p /var/lib/remote-runner/scripts
$ chown -R root:root /var/lib/remote-runner/scripts
$ chmod -R 750 /var/lib/remote-runner/scripts
$ cp remote-runner task-helper /usr/local/bin
$ chmod 700 /usr/local/bin/remote-runner
$ chmod 700 /usr/local/bin/task-helper
```

Install the certificates (owned by root, readable by remote_runner) and the
scripts. Then create the task helper socket
`/etc/systemd/system/task-helper.socket`:

```ini
[Unit]
Description=remote-runner - task helper socket

[Socket]
ListenStream=/run/remote-runner/task.sock
SocketUser=root
SocketGroup=remote-runner
SocketMode=0660

[Install]
WantedBy=sockets.target
```

and `/etc/systemd/system/task-helper.service`:

```ini
[Unit]
Description=remote-runner - execute scripts as root for the web daemon

[Service]
ExecStart=/usr/local/bin/task-helper \
    -scripts-dir /var/lib/remote-runner/scripts \
    -allowed-user remote-runner
Restart=on-failure

[Install]
WantedBy=sockets.target
```

Finally `/etc/systemd/system/remote-runner.service`:

```ini
[Unit]
Description=remote-runner - run predefined scripts via REST API
After=network-online.target task-helper.socket
Wants=network-online.target
Requires=task-helper.socket

[Service]
User=remote-runner
Group=remote-runner
ExecStart=/usr/local/bin/remote-runner \
    -listen :8443 \
    -task-socket /run/remote-runner/task.sock \
    -server-cert /etc/remote-runner/server.crt \
    -server-key /etc/remote-runner/server.key \
    -client-cert /etc/remote-runner/client.crt
Restart=on-failure

# hardening — the web daemon spawns no processes and only reads certificates
NoNewPrivileges=true
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectClock=true
ProtectHostname=true
ProtectSystem=strict
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
```

```console
# systemctl daemon-reload
# systemctl enable --now task-helper.socket remote-runner
```

## Logging

Both components log structured key=value lines to stderr, which journald
captures when they run as the services above. View them with:

```console
$ journalctl -u remote-runner -f                     # follow
$ journalctl -u remote-runner --since "1 hour ago"
$ journalctl -u remote-runner -g "security event"    # filter security events
$ journalctl -u task-helper -f                       # root side: execution
```

Every log line contains a `transaction_id` (UUIDv4) that ties all messages
belonging to one request together — from the incoming request over script
execution to webhook delivery.