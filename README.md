# remote_runner

Runs predefined scripts triggered via a REST API call.

remote_runner is a Go webserver that executes predefined, 
scripts over a mutually authenticated TLS 1.3 connection.
Results are either streamed to the client
and/or delivered to a webhook.

## Building

```console
$ go build -o remote_runner .
```

## Configuration

All settings are command line flags:

| Flag | Default | Description |
|------|---------|-------------|
| `-listen` | `:8443` | Listen address (host:port) |
| `-scripts-dir` | `scripts` | Directory containing one folder per script |
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

## Certificates

remote_runner authenticates itself with a self-signed server certificate and
authenticates users with a self-signed client certificate. Certificates are
**not** validated against a CA — they are **pinned**: a connection is only
accepted if the certificate presented by the peer is byte-identical to the
pinned one. TLS 1.3 is enforced for every connection (older versions are
refused at the handshake).

### Create a certificate and key

```console
$ openssl req -x509 -newkey ed25519 \
    -keyout server.key -out server.crt -days 3650 -nodes \
    -subj "/CN=remote-runner"
```
[Check curve security](https://safecurves.cr.yp.to/)

### Calling the API

```console
$ curl -i --tlsv1.3 \
    --cert client.crt --key client.key \
    --cacert server.crt \
    --data '{"script_name":"hello","script_checksum":"99647781e902f1de358822b26692771cedadd972c5fd83f9421a39464572d444","stream_script_stdout_stderr":true,"script_timeout_seconds":60}' \
    https://remote-runner.example:8443/run
```

## Scripts

Each script lives in its own folder inside `-scripts-dir` and must be an
executable regular file (no symlinks) named after the folder:

```text
scripts/
└── hello/
    └── hello      (executable)
```

```console
$ chmod +x scripts/hello/hello
$ sha256sum scripts/hello/hello
99647781e902f1de358822b26692771cedadd972c5fd83f9421a39464572d444  scripts/hello/hello
```

The `script_checksum` of a request must match this SHA-256 checksum.

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

Create a dedicated user without login shell and a home for the scripts:

```console
# useradd --system --home-dir /var/lib/remote-runner --create-home \
    --shell /usr/sbin/nologin remote-runner
# sudo -u remote-runner mkdir /var/lib/remote-runner/scripts
# install -o remote-runner -g remote-runner -m 0755 remote_runner /usr/local/bin/remote_runner
```

Install the certificates (owned by root, readable by remote_runner) and the
scripts. Then create `/etc/systemd/system/remote-runner.service`:

```ini
[Unit]
Description=remote_runner - run predefined scripts via REST API
After=network-online.target
Wants=network-online.target

[Service]
User=remote-runner
Group=remote-runner
ExecStart=/usr/local/bin/remote_runner \
    -listen :8443 \
    -scripts-dir /var/lib/remote-runner/scripts \
    -server-cert /etc/remote-runner/server.crt \
    -server-key /etc/remote-runner/server.key \
    -client-cert /etc/remote-runner/client.crt \
    -max-concurrent 4
Restart=on-failure

# hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/var/lib/remote-runner
CapabilityBoundingSet=
AmbientCapabilities=

[Install]
WantedBy=multi-user.target
```

```console
# systemctl daemon-reload
# systemctl enable --now remote-runner
```

## Logging

remote_runner logs structured key=value lines to stderr, which journald
captures when it runs as the service above. View them with:

```console
$ journalctl -u remote-runner -f                     # follow
$ journalctl -u remote-runner --since "1 hour ago"
$ journalctl -u remote-runner -g "security event"    # filter security events
```

Every log line contains a `transaction_id` (UUIDv4) that ties all messages
belonging to one request together — from the incoming request over script
execution to webhook delivery.
