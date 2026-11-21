# meshcore-localapi (JavaScript)

A client for the MeshCore Local API, protocol 1. A MeshCore host app (MeshCore Open, or the
meshcored daemon) keeps the radio connection and serves a WebSocket on loopback at
`ws://127.0.0.1:8787/api/v1`. Other apps on the same machine pair with it once and then send and
receive mesh traffic through it. The protocol is described in `../SPEC.md`.

ESM, Node 20 or later. Keys use `node:crypto`. The WebSocket is the global one on Node 22 and
later; on older Node the optional `ws` package is used. Types are in `src/index.d.ts`.

## Install

From a local checkout:

```
npm install ../meshcore-local-api/js
```

To work on the library itself:

```
npm install
npm test
```

## Usage

```js
import { JsonFileCursorStore, LocalApiClient, loadOrCreateKey } from 'meshcore-localapi';

const key = loadOrCreateKey('./localapi-key.pem');   // PKCS#8 PEM, mode 0600
console.log(`approve this app in the host app, fingerprint ${key.fingerprint}`);

const client = new LocalApiClient({
  key, name: 'myapp', version: '1.0',
  cursorStore: new JsonFileCursorStore('./localapi-cursor.json'),
  log: (m) => console.log(m),
});
client.on('event', (ev) => {
  if (ev.type === 'channel.data' && !ev.outgoing) console.log(ev.channel, Buffer.from(ev.payload, 'base64'));
});
client.subscribe({ events: ['channel.data'], channel: '#mychannel', dataTypes: [0xFF00] },
  { cursorKey: '#mychannel', join: true });
client.start();
await client.waitPaired(150_000);

try {
  await client.sendData('#mychannel', 0xFF00, Buffer.from('hello'));
} catch (e) {
  console.log(`refused: ${e.code}${e.maybeSent ? ' (may have been sent)' : ''}`);
}

await client.stop();
```

`LocalApiConnection` is the single connection underneath (handshake, requests, `event`, `device`
and `close` events, no reconnect), for code that runs its own connection loop.

## What the client does

- Pairing: sends `hello` with the public key (base64 of the raw 64-byte X||Y point of a P-256
  key), signs the challenge, and waits for `hello` from the server. It signs the challenge's
  `message` only if it is exactly `meshcore-local-api-pair-v1:<nonce>` for that challenge's
  nonce. Any other message, or none, closes the connection without signing. Servers that still
  send the older `meshcore-open-pair-v1:` prefix are not supported.
- Capabilities are strict: the client never uses a feature whose name is missing from
  `hello.capabilities` (SPEC sections 8 and 13). `request()` rejects with `MissingCapability` and sends
  nothing for `contacts.list` and `direct.sendText` (`contacts`), `advert.send` (`advert_send`),
  `regions.list`, `regions.resolve` and a `region` on a send (`regions`), `channels.join`
  (`channels_join`), `radio.stats` (`radio_stats`), `packet.sendRaw` (`raw_tx`), `path` on
  `channel.sendData` (`tx_path_data`) or `channel.sendText` (`tx_path_text`), and in
  `events.subscribe` for `since` (`replay`), `pubkeys` and the `direct.text` and `advert` events
  (`contacts`), `payloadTypes` and `packet.raw` (`raw_rx`). `requiredCapabilities(method, params)`
  returns the list for a request.
- Requests get ids and a timeout each: 15 s by default, 150 s for `channels.join`, because the
  user answers that one in a dialog. Pass a timeout per call or `methodTimeoutsMs` to change
  them. A disconnect rejects the waiting requests at once with `ConnectionClosed`.
- Errors: `ApiError` with `code`, `message`, `maybeSent` and `method`. Subclasses:
  `RequestTimeout` (`timeout`), `ConnectionClosed` (`closed`), `MissingCapability`
  (`unsupported`), `PairingError` (`pairing`). A connection refused during the handshake fails
  with `rejected` (close 4003) or `connect_failed`.
- From `hello` the client keeps `capabilities` (a Set), `limits`, `device`, `radioConnected` and
  `maxPayload`.
- Subscriptions registered with `subscribe()` are made after every pairing and again after a
  `device` push with `connected: true` while they are not active. Channel subscriptions wait for
  the radio. With `join: true`, an `unknown_channel` answer asks the user to add the channel, once
  per connection, when the server lists `channels_join`.
- Replay: with `cursorKey` the subscription sends `since` from the stored cursor when the server
  lists `replay` (without it, `since` is left out and nothing is replayed). `since` is
  inclusive, so the cursor keeps the ids of the events at its timestamp and the client drops the
  events a replay repeats. The cursor moves after the `event` listeners return.
- `sendData()` puts `path` and `pathHashSize` on `channel.sendData` only with `tx_path_data`;
  a server without it could ignore the path and flood.
- Reconnect: 1 s doubling to 30 s with jitter, back to 1 s after a successful pairing. After a
  close with 4003 (not approved, or revoked) it waits 2 minutes.
- Optional heartbeat: `heartbeatMs` sends `device.info` at that interval and drops a connection
  that does not answer within `heartbeatTimeoutMs`.
- Unknown fields, frame types and event types are ignored.

## Notes

- Storage is pluggable. `loadOrCreateKey` takes a file path or an object with `load()` (PEM or
  null) and `save(pem)`; use `loadOrCreateKeyAsync` when those return promises. A cursor store
  has `get(key)`, `set(key, cursor)` and optionally `flush()`, where a cursor is
  `{ receivedAt, ids }`. `JsonFileCursorStore` writes atomically with mode 0600 and batches writes
  to one per 10 s, plus a flush on every disconnect and on `stop()`.
- The URL must be loopback unless you pass `loopbackOnly: false`.
- `eventPayload()`, `eventPath()` and `eventId()` decode common event fields.
- Tests run against an in-process fake server built on `ws`, which is why `ws` is also a dev
  dependency.
