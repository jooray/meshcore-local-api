# meshcore-localapi (Python)

A client for the MeshCore Local API, protocol 1. A MeshCore host app (MeshCore Open, or the
meshcored daemon) keeps the radio connection and serves a WebSocket on loopback at
`ws://127.0.0.1:8787/api/v1`. Other apps on the same machine pair with it once and then send and
receive mesh traffic through it. The protocol is described in `../SPEC.md`.

The client is synchronous and thread-based. One background thread owns the socket: it connects,
pairs, reads frames, and reconnects with backoff. Requests block the calling thread.

## Install

Python 3.11 or later. Dependencies: `websockets` (its sync client) and `cryptography`.

From another project managed with uv, using a local checkout:

```
uv add --editable ../meshcore-local-api/python
```

To work on the library itself:

```
uv sync
uv run pytest
```

## Usage

```python
import base64
from meshcore_localapi import JsonFileStore, LocalApiClient, LocalApiError, load_or_create_key

store = JsonFileStore("~/.config/myapp/localapi.json")   # key and replay cursors, mode 0600
key = load_or_create_key(store)
print("approve this app in the host app, fingerprint", key.fingerprint)

def on_event(event, sub):
    if event["type"] == "channel.data" and not event.get("outgoing"):
        print(event["channel"], base64.b64decode(event["payload"]))

client = LocalApiClient(key=key, name="myapp", version="1.0", cursor_store=store, on_event=on_event)
client.subscribe({"events": ["channel.data"], "channel": "#mychannel", "dataTypes": [0xFF00]},
                 cursor_key="#mychannel", join=True)
client.start()
client.wait_paired(150)

try:
    client.send_data("#mychannel", 0xFF00, b"hello")
except LocalApiError as e:
    print("refused:", e.code, "(may have been sent)" if e.maybe_sent else "")

client.close()
```

## What the client does

- Pairing: sends `hello` with the public key (base64 of the raw 64-byte X||Y point of a P-256
  key), signs the challenge, and waits for `hello` from the server. It signs the challenge's
  `message` only if it is `meshcore-local-api-pair-v1:<nonce>` or the older
  `meshcore-open-pair-v1:<nonce>` for that challenge's nonce. Any other message closes the
  connection without signing. A challenge with no `message` gets the older string, which is what
  servers without the field verify.
- Requests get ids and a timeout each: 15 s by default, 150 s for `channels.join`, because the
  user answers that one in a dialog. Pass `timeout=` or `method_timeouts=` to change them. A
  disconnect fails the waiting requests at once with `ConnectionClosed`.
- Errors: `LocalApiError` with `code`, `message`, `maybe_sent` and `method`. Subclasses:
  `RequestTimeout` (`timeout`), `ConnectionClosed` (`closed`), `MissingCapability`
  (`unsupported`), `PairingError` (`pairing`).
- From `hello` the client keeps `capabilities` (a frozenset), `limits` (a dict), `device`,
  `radio_connected` and `max_payload`.
- Subscriptions registered with `subscribe()` are made after every pairing and again after a
  `device` push with `connected: true` while they are not active. Channel subscriptions wait for
  the radio. With `join=True`, an `unknown_channel` answer asks the user to add the channel, once
  per connection.
- Replay: with `cursor_key` the subscription sends `since` from the stored cursor. `since` is
  inclusive, so the cursor keeps the ids of the events at its timestamp and the client drops the
  events a replay repeats. The cursor moves after `on_event` returns.
- `send_data()` puts `path` and `pathHashSize` on `channel.sendData` only when the server lists
  `tx_path_data`. Without it, a call with `path` raises `MissingCapability` and sends nothing,
  because an older server would ignore the path and flood.
- Reconnect: 5 s doubling to 60 s with jitter, back to 5 s after a successful pairing. After a
  close with 4003 (not approved, or revoked) it waits 2 minutes.
- Unknown fields, frame types and event types are ignored.

## Notes

- Callbacks (`on_event`, `on_device`, `on_hello`, `on_state`) run on the reader thread. Keep them
  short. Do not call `request()` from them; start a thread instead, or the reader waits for its
  own answer.
- An exception in `on_event` is logged and the event still counts as delivered.
- Storage is pluggable. Anything with `load_key()` and `save_key(der)` is a key store, and
  anything with `get_cursor`, `set_cursor` and `flush` is a cursor store. `MemoryStore` does both
  in memory. `JsonFileStore` writes atomically with mode 0600 and batches cursor writes to one per
  10 s, plus a flush on every disconnect and on `close()`. It reads a cursor stored as a bare
  timestamp string as one with no ids.
- The URL must be loopback unless you pass `loopback_only=False`.
- `event_payload()`, `event_path()` and `parse_time()` decode common event fields.
