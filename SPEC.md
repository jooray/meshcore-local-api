# MeshCore Local API

Protocol version 1. Status: draft for review.

This document specifies a loopback WebSocket protocol through which one application that holds
the connection to a MeshCore companion radio lets other applications on the same device use that
radio. It is written for implementers of servers (the application that owns the radio) and of
clients (applications that want to send and receive mesh traffic).

Conformance vectors are in [`vectors/`](vectors/).

## Contents

1. [Overview and goals](#1-overview-and-goals)
2. [Conventions and terminology](#2-conventions-and-terminology)
3. [Transport](#3-transport)
4. [Message framing](#4-message-framing)
5. [Handshake and pairing](#5-handshake-and-pairing)
6. [Core methods](#6-core-methods)
7. [Core events and the device push](#7-core-events-and-the-device-push)
8. [Optional features](#8-optional-features)
9. [Limits](#9-limits)
10. [Errors and close codes](#10-errors-and-close-codes)
11. [Security considerations](#11-security-considerations)
12. [Versioning and compatibility](#12-versioning-and-compatibility)
13. [Capability registry](#13-capability-registry)
14. [References](#14-references)
- [Appendix A. Implementations](#appendix-a-implementations)
- [Appendix B. Adding the API to a MeshCore app](#appendix-b-adding-the-api-to-a-meshcore-app)
- [Appendix C. Example session](#appendix-c-example-session)

## 1. Overview and goals

A MeshCore companion radio accepts one connection at a time over BLE, USB serial or TCP. The
application holding that connection is the only one that can send or receive through the radio.
The companion protocol also drains the radio's message queue destructively, so two applications
cannot share the link by taking turns.

The MeshCore Local API moves that single connection behind a small local server. The application
that owns the radio (a chat app on a phone, a daemon on a computer) runs the server. Other
applications on the same device connect to it, prove a key the user approved, subscribe to the
traffic they need and send through the same radio. The radio protocol does not change. Reticulum's
`rnsd` follows the same model: one process holds the interfaces and every application on the
machine reaches the network through it.

Goals:

* One protocol that any MeshCore host application can implement, so that a client works with
  whichever one the user runs.
* Small mandatory core, with optional features announced by name so that a client never has to
  guess what a server does.
* Nothing reachable from outside the device and nothing usable without the user's explicit
  approval of each client.
* Opaque content: channel data is a `dataType` plus payload bytes, carried unchanged in both
  directions. The API does not parse application formats.
* Easy to implement from any language with a WebSocket library and P-256 ECDSA.

Non-goals for protocol 1:

* Access from another machine. A user who needs it can forward the port over SSH.
* Changing radio settings, contacts or channel keys, except adding a hashtag channel after the
  user agrees (section 8.4).
* Reading chat history beyond the replay archive (section 8.5).
* Reassembling multi-part transfers. They are channel data like any other.
* Authenticating the server to the client (section 11.4).

## 2. Conventions and terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT",
"RECOMMENDED", "NOT RECOMMENDED", "MAY" and "OPTIONAL" in this document are to be interpreted as
described in BCP 14 (RFC 2119, RFC 8174) when, and only when, they appear in all capitals.

Terms:

* **Radio**: a MeshCore node running companion firmware, attached to the host by BLE, USB serial
  or TCP.
* **Host app**: the application that owns the connection to the radio and runs the Local API
  server. Examples: a mobile chat app, a desktop app, a headless daemon.
* **Server**: the Local API endpoint inside the host app.
* **Client**: an application that connects to the server. It has a P-256 key pair; the public key
  is its identity.
* **User**: the person who controls the host app. For a headless host app, the operator who runs
  it.
* **Paired key**: a client public key that the user approved. The approval is stored by the host
  app until the user revokes it.
* **Connection**: one WebSocket session between a client and the server. A connection is
  **authenticated** once the server has sent the authenticated `hello` (section 5.6).
* **Usable radio**: the radio is connected and its channel list is loaded, so channel names
  resolve. Reported as `connected` (section 6.1).
* **Capability**: a string in `hello.capabilities` that names an optional feature (section 13).

JSON types are those of RFC 8259. "Integer" means a JSON number without a fraction or exponent.
"Base64" means the standard alphabet with padding (RFC 4648 section 4) unless a field says
otherwise. "Base64url" is RFC 4648 section 5. "Hex" is a string of hexadecimal digits, two per
byte; servers emit lowercase and accept either case. Lengths of strings are counted in Unicode
code points unless stated otherwise. Times are RFC 3339 date-time strings in UTC with a `Z`
suffix, such as `2026-10-26T12:00:00.000Z`.

Field tables list each field with its type. "or null" means the server sends `null` when the
value is unknown. A field marked "optional" may be absent. Clients MUST ignore fields they do not
know.

## 3. Transport

### 3.1 Endpoint

The server listens for WebSocket connections (RFC 6455) at:

```
ws://127.0.0.1:8787/api/v1
```

* The server MUST bind only to a loopback address: `127.0.0.1`, and MAY also bind `::1`. It MUST
  NOT listen on any other interface.
* Port 8787 is the default. A host app MAY let the user choose another port; it SHOULD show the
  port in the same place where the API is enabled. Clients SHOULD let the user configure the URL
  and default to the one above.
* The path is `/api/v1`. Any other path MUST be refused with HTTP 404.
* TLS is not used. The traffic does not leave the device.
* The server MUST NOT announce itself on the network (no mDNS, no broadcast).

### 3.2 Upgrade checks

The server MUST check the HTTP upgrade request before accepting it:

| Condition | Answer |
|---|---|
| Path is not `/api/v1` | HTTP 404 |
| An `Origin` header is present | HTTP 403 |
| The request is not a WebSocket upgrade | HTTP 426 (any 4xx conforms) |
| The `Host` header is not a loopback name (`127.0.0.1`, `localhost` or `[::1]`, with or without a port) | HTTP 403 (SHOULD) |
| Too many connections have not finished pairing (section 9.2) | HTTP 503 |

Browsers always send `Origin` on a WebSocket upgrade; native clients do not. Refusing `Origin`
keeps web pages from reaching the radio through the user's loopback interface. Clients MUST NOT
send an `Origin` header. The `Host` check is defence in depth against DNS rebinding and local
proxies.

### 3.3 WebSocket options

* Requests and responses are UTF-8 text frames. A binary data frame from the client MUST close
  the connection with code 1003.
* A message (the sum of all fragments of one data frame sequence) larger than
  `limits.maxMessageBytes` MUST close the connection with code 1009. The server SHOULD stop
  reading the message as soon as the bound is passed rather than buffering it.
* Compression (permessage-deflate) is not negotiated. Servers MUST NOT accept it.
* Subprotocols are not used.
* Ping and pong frames follow RFC 6455. The server does not require them. A client MAY send pings
  to detect a dead server.

## 4. Message framing

Every frame is one JSON object. There are five kinds:

| Kind | Direction | Shape |
|---|---|---|
| Handshake | both | `{"type": "hello" \| "pairing.challenge" \| "pair", ...}` (section 5) |
| Request | client to server | `{"id": ..., "method": "...", "params": {...}}` |
| Response | server to client | `{"id": ..., "ok": true, "result": {...}}` or `{"id": ..., "ok": false, "error": {...}}` |
| Event | server to client | `{"type": "event", "subscriptionId": "...", "event": {...}}` |
| Push and bare error | server to client | `{"type": "device", ...}` (section 7.6), `{"type": "error", "error": {...}}` |

### 4.1 Requests

* `id`: any JSON value. The server copies it unchanged into the response. Clients SHOULD use a
  unique integer or string per request. A request without `id` gets a response with `"id": null`.
* `method`: string, REQUIRED. A request without a string `method` gets a `bad_request` error
  response that carries its `id`.
* `params`: object, OPTIONAL. If it is absent or not an object, the server treats it as `{}`.
* Unknown fields in a request and unknown parameters in `params` MUST be ignored, with one
  exception: a server MUST refuse a parameter of an optional feature it does not offer when
  ignoring it would change what goes on the air (`region` in section 8.3, `path` in section
  8.8). Clients still check `hello.capabilities` first, because servers written before this
  rule ignore such parameters.

### 4.2 Responses

* A response has `id`, `ok` (boolean) and either `result` (object) or `error` (object).
* `error` has `code` (string, section 10.1) and `message` (string, human-readable, not for
  parsing). It MAY carry further fields defined by a feature, such as `maybeSent` (section 10.3).
* The server MAY answer requests out of order. Clients MUST match responses by `id`. Some
  requests wait for the user (section 8.4) or for the radio, and other responses and events can
  arrive in the meantime.

### 4.3 Bare errors

An error that has no request to answer is sent as `{"type": "error", "error": {...}}`. This
happens during the handshake (section 5) and when an authenticated client sends a frame that is
not valid JSON or not a JSON object. Unparsable frames do not close the connection by themselves.

### 4.4 Events

Events are delivered only for subscriptions (section 6.3). Each event frame names the
subscription it matched. If one radio event matches several subscriptions of the same
connection, it is sent once per subscription.

## 5. Handshake and pairing

### 5.1 Client identity

Each client generates a P-256 (secp256r1) key pair once and keeps the private key. The public key
is the client's identity to every server. A client SHOULD keep the same key across restarts; a new
key means the user has to approve the client again.

The public key is sent as **base64 of the 64-byte `X||Y`**: the affine X coordinate as 32 bytes
big-endian, followed by Y as 32 bytes big-endian. This is the SEC 1 uncompressed point without
its leading `0x04` byte.

The server MUST decode the key and check that it is exactly 64 bytes, that X and Y are each below
the field prime, and that the point satisfies the curve equation. A key that fails any check MUST
be refused (section 5.7). Servers SHOULD identify a key by its 64 decoded bytes, not by the string
the client sent.

### 5.2 Fingerprint

The fingerprint lets the user compare a key in the pairing prompt with what the client shows.

```
fingerprint = upper-case hex of the first 8 bytes of SHA-256(X||Y),
              in four groups of four characters separated by single spaces
```

The input is the 64 raw bytes, not the base64 text. The result is 19 characters. When a user or
operator types a fingerprint, implementations compare it after removing white space and folding to
upper case.

Example with the test key from `vectors/pairing.json`:

```
publicKey   4sNKerSGIKbZjuvSegPkjnBw/oCzEoj8MDy3+bIP5ooQMbcevcA2Yz4iT8w8yEJPmoz8gxjZvwKwIOhAh+ZtVQ==
SHA-256     9c5fa624034b4ec703a566ae99daa92faa2d3aad451c31980fe55935da01e962
fingerprint 9C5F A624 034B 4EC7
```

### 5.3 Sequence

```
client                                   server
  |  WebSocket upgrade (no Origin)          |
  |---------------------------------------->|
  |  {"type":"hello", client{...}}          |
  |---------------------------------------->|
  |        {"type":"pairing.challenge",...} |
  |<----------------------------------------|
  |  {"type":"pair","signature":"..."}      |
  |---------------------------------------->|
  |                (new key: user prompt, up to 2 min)
  |   {"type":"hello", protocol, device...} |
  |<----------------------------------------|
  |  requests ...                           |
```

1. The client opens the connection and sends `hello`.
2. The server answers `pairing.challenge`.
3. The client checks the challenge and sends `pair` with a signature.
4. The server verifies the signature. If the key is not paired, the host app asks the user
   (section 5.5).
5. The server sends the authenticated `hello`. From then on the connection carries requests,
   responses, events and pushes.

### 5.4 Messages

**Client `hello`:**

```json
{"type":"hello","client":{"name":"Roadbeacon","version":"0.4.0","publicKey":"4sNKerSGIKbZjuvSegPkjnBw/oCzEoj8MDy3+bIP5ooQMbcevcA2Yz4iT8w8yEJPmoz8gxjZvwKwIOhAh+ZtVQ=="}}
```

| Field | Type | Rule |
|---|---|---|
| `client.name` | string | 1 to 64 code points after trimming white space at both ends; no control characters (Unicode category Cc). The server stores and shows the trimmed name. |
| `client.version` | string | 0 to 32 code points; no control characters. |
| `client.publicKey` | string | base64 of `X\|\|Y` (section 5.1). |

**Server `pairing.challenge`:**

```json
{"type":"pairing.challenge","protocol":1,"nonce":"d3zXMrhxhqHuEyHUe4MkXA","fingerprint":"9C5F A624 034B 4EC7","message":"meshcore-local-api-pair-v1:d3zXMrhxhqHuEyHUe4MkXA"}
```

| Field | Type | Rule |
|---|---|---|
| `protocol` | integer | `1` for this specification. |
| `nonce` | string | At least 16 bytes from a cryptographically secure random generator, base64url encoded, with or without `=` padding. It MUST match `^[A-Za-z0-9_-]{16,128}={0,2}$`. A new nonce for every connection. |
| `fingerprint` | string | The fingerprint of the key in the client's `hello` (section 5.2). |
| `message` | string | The exact string the client signs: `meshcore-local-api-pair-v1:` followed by `nonce`. |

The challenge MUST have the same shape whether or not the key is already paired, so an
unauthenticated caller cannot learn which keys are paired.

**Client `pair`:**

```json
{"type":"pair","signature":"MEQCIE06E9rqT3uegWmygI+ChZttyQ7N+X+khUAMBctZo3yhAiBvyIgLiLNk8nxSrzl5qbViU7PlgN7RF/kayybjmY5q1Q=="}
```

### 5.5 Signing and verification

**The client** MUST check the challenge before signing:

* `nonce` matches the regular expression in section 5.4;
* `message` is exactly `meshcore-local-api-pair-v1:` + `nonce`, comparing bytes, with no
  surrounding white space.

If either check fails, the client MUST NOT sign and SHOULD close the connection. Otherwise it signs
the UTF-8 bytes of `message`, exactly as received, with ECDSA over P-256 using SHA-256 (the JCA name
is `SHA256withECDSA`). It MUST NOT rebuild the string from parts or re-encode the nonce.

`signature` is base64 of one of:

* the DER encoding of `Ecdsa-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }` (what Java, Android,
  Node and OpenSSL produce), or
* the 64-byte concatenation `r||s`, each 32 bytes big-endian (what Web Crypto and many embedded
  libraries produce).

**The server** MUST:

* decode `signature` from base64; a 64-byte value is `r||s`, any other length is DER;
* accept only strict DER (definite short or long form lengths as DER requires, minimal positive
  INTEGERs, nothing after the SEQUENCE);
* refuse `r` or `s` outside 1 to n-1, where n is the order of P-256;
* accept both low-S and high-S signatures (Java and other common signers do not normalize S);
* verify against the `message` it sent in this connection's challenge and nothing else;
* accept at most one `pair` frame per connection.

`vectors/pairing.json` has valid signatures in both encodings and with high S, and invalid cases
that a server MUST refuse.

### 5.6 Approval and the authenticated `hello`

If the signature is valid and the key is paired, the server continues at once. If the key is not
paired, the host app MUST ask the user before the connection continues (section 11.2 lists the
requirements for the prompt). While the prompt is open:

* The connection stays open and the client MUST NOT send any frame. A frame received while the
  prompt is open MUST close the connection with 4001.
* If the client disconnects, the request is withdrawn and the prompt closes.
* If the user does not answer within the prompt timeout (RECOMMENDED 2 minutes), the request is
  denied.

Clients SHOULD wait at least 130 seconds for the `hello` after sending `pair`.

When the user allows the key, the host app stores it with the client name and fingerprint. When
the connection is authenticated, the server sends:

```json
{"type":"hello","protocol":1,
 "client":{"name":"Roadbeacon","fingerprint":"9C5F A624 034B 4EC7"},
 "device":{"name":"Base 1","pubkey":"0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0","firmwareVerCode":11,"connected":true},
 "eventTypes":["channel.text","channel.data","direct.text","advert"],
 "limits":{"maxPayloadBytes":163,"maxMessageBytes":16384,"maxQueuedBytes":262144,"sendsPerMinute":30,"minSendGapMs":2000,"maxSubscriptions":16,"maxFilterEntries":32},
 "capabilities":["contacts","advert_send","regions","channels_join","replay","tx_path_data"],
 "server":{"name":"example-host","version":"1.2.0"}}
```

| Field | Type | Meaning |
|---|---|---|
| `protocol` | integer | `1`. |
| `client.name`, `client.fingerprint` | string | As stored for this key. |
| `device` | object | Radio summary, the same fields as in the `device` push (section 7.6). |
| `eventTypes` | array of strings | The event types this server delivers by default (section 6.3). Always includes `channel.text` and `channel.data`. |
| `limits` | object | Section 9.1. |
| `capabilities` | array of strings | Optional features this server offers on this connection (section 13). Empty array when none. |
| `server` | object, optional | `name` (string) and `version` (string) of the server implementation, for diagnostics. MAY carry more fields. Clients MUST NOT change behaviour on it; they use `capabilities`. |

A client MUST check `protocol` in the challenge or `hello` and SHOULD close the connection if it
is not a version it implements.

### 5.7 Handshake errors

Before authentication, errors are bare (section 4.3) and most of them close the connection:

| Situation | Error code | Close |
|---|---|---|
| Frame that is not valid JSON or not an object | `bad_request` | none, the connection stays |
| First frame is not `hello`, a second `hello`, `pair` before `pairing.challenge`, a second `pair`, a request before authentication | `unauthorized` | 4001 |
| `hello` without a valid `client` (missing fields, wrong types, name or version out of range) | `bad_request` | 4003 |
| `client.publicKey` not a valid P-256 point | `bad_request` | 4003 |
| `pair` without a string `signature` | `bad_request` | 4003 |
| Signature does not verify | `unauthorized` | 4003 |
| The key already has a prompt open | `pairing_pending` | 4003 |
| Prompt rate limit reached (section 9.2) | `rate_limited` | 4003 |
| The user denied, or did not answer in time | `unauthorized` | 4003 |
| No `pair` within the handshake timeout | `unauthorized` (MAY be omitted) | 4001 |
| The server already has the maximum number of authenticated connections | `too_many_clients` | 4013 |

The handshake timeout (RECOMMENDED 10 seconds) runs from the moment the connection opens until
`pair` arrives. It does not run while the user prompt is open; the prompt has its own timeout.

A client that is closed with 4003 SHOULD NOT reconnect at once. It SHOULD wait at least 60 seconds,
or until its own user asks it to retry, so that a denied client does not prompt the user again and
again.

### 5.8 Revocation and permissions

The host app MUST let the user see the list of paired clients (name, fingerprint, and when it was
paired) and remove any of them. Removing a key MUST close its open connections with code 4003 and
reason `revoked`, and MUST forget any archive interest kept for it (section 8.5). Its next
connection asks the user again.

A pairing MAY carry **permissions** that grant more than the default. This specification defines
one, `raw` (section 8.12). How the host app lets the user grant a permission is up to it; the
default for a new pairing is no extra permission. The default grant covers everything in this
document except features that name a permission.

## 6. Core methods

Every server MUST implement the methods in this section. In the tables, a parameter without
"optional" is required.

All requests in this section are valid only on an authenticated connection.

### 6.1 `device.info`

No parameters. Returns the radio's identity and state.

| Field | Type | Meaning |
|---|---|---|
| `connected` | boolean | The radio is usable: connected, with its channel list loaded. |
| `name` | string or null | The node's advertised name. |
| `pubkey` | string or null | The node's public key, 64 lowercase hex characters. |
| `firmwareVerCode` | integer or null | The companion firmware's `FIRMWARE_VER_CODE` as the radio reports it. |
| `batteryMv` | integer or null | Battery voltage in millivolts. |
| `batteryPercent` | integer or null | Battery charge, 0 to 100. |
| `radio` | object or null | `freqHz`, `bwHz`, `sf`, `cr`, `txPowerDbm` (integers, each may be null). |
| `channels` | array | As in `channels.list`. |

```json
{"id":1,"method":"device.info"}
{"id":1,"ok":true,"result":{"connected":true,"name":"Base 1","pubkey":"0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0","firmwareVerCode":11,"batteryMv":4012,"batteryPercent":null,"radio":{"freqHz":869525000,"bwHz":250000,"sf":11,"cr":5,"txPowerDbm":22},"channels":[{"index":0,"name":"Public","isPublic":true,"storageId":"7a1c0e5f9b3d2a48"},{"index":1,"name":"#roadstr","isPublic":false,"storageId":"c4d1b2a39e8f7061"}]}}
```

`device.info` MUST answer even when the radio is not usable; it then reports `connected: false`
and whatever it last knew.

### 6.2 `channels.list`

No parameters. Returns `{"channels": [...]}`, one entry per configured channel slot:

| Field | Type | Meaning |
|---|---|---|
| `index` | integer | Slot number on the radio, 0 to 255. |
| `name` | string | Channel name as configured. Hashtag channels start with `#`. |
| `isPublic` | boolean | The channel is MeshCore's public channel. |
| `storageId` | string or null | An opaque identifier the host app uses for the channel. Clients MUST NOT interpret it or expect two servers to agree on it. |

The list is empty while the radio is not usable.

### 6.3 `events.subscribe`

Creates a subscription. Events that match it are sent until the client unsubscribes or the
connection closes.

| Parameter | Type | Meaning |
|---|---|---|
| `events` | array of strings, optional | Event types to deliver. Absent or null: every type in `hello.eventTypes`. |
| `channel` | string or integer, optional | Limits channel events to one channel (section 6.6). Events not tied to a channel (`direct.text`, `advert`) are not delivered to this subscription. |
| `dataTypes` | array of integers, optional | Keeps only `channel.data` events with one of these `dataType` values. When present and non-empty, events of other types are not delivered to this subscription. At most `limits.maxFilterEntries` entries, each 1 to 65535. |
| `pubkeys` | array of strings, optional | Feature `contacts` (section 8.1). |
| `since` | string or integer, optional | Feature `replay` (section 8.5). |
| `payloadTypes` | array of integers, optional | Feature `raw_rx` (section 8.12). |

Result: `{"subscriptionId": "<string>"}`. The id is unique within the connection.

Filters combine with AND. An empty array means "no filter", the same as absent.

Rules:

* An entry in `events` that is not a known event type MUST be refused with `bad_request`. A known
  extension type that this server does not offer, or that this client is not permitted to
  receive, SHOULD be refused with `unsupported` or `forbidden`.
* Extension event types that are not in `hello.eventTypes` (such as `packet.raw`) are delivered
  only when the client names them in `events`. This keeps a client that omits `events` from
  receiving types it does not understand.
* `channel` as a string that does not resolve fails with `unknown_channel` or
  `ambiguous_channel` (section 6.6). As an integer, it MUST be 0 to 255 and does not need to exist
  yet.
* A connection may hold at most `limits.maxSubscriptions` subscriptions; one more fails with
  `rate_limited`.
* Subscriptions survive a radio disconnect and reconnect. They end only when the client
  unsubscribes or the connection closes.

The response MUST be sent before any event for the new subscription. With `since`, replayed events
follow the response and come before live events (section 8.5).

```json
{"id":2,"method":"events.subscribe","params":{"events":["channel.data"],"channel":"#roadstr","dataTypes":[336]}}
{"id":2,"ok":true,"result":{"subscriptionId":"s1"}}
```

### 6.4 `events.unsubscribe`

| Parameter | Type |
|---|---|
| `subscriptionId` | string |

Result: `{}`. An id that this connection does not hold fails with `bad_request`. After the
response, no further events are sent for that subscription.

### 6.5 Sending

Sends share these rules:

* A send is accepted only while the radio is usable. Otherwise it fails with `not_connected`.
  Servers SHOULD report `not_connected` in preference to channel lookup errors while the radio is
  away, because the channel list is empty then.
* Each connection has a send quota (section 9.1, `sendsPerMinute` and `minSendGapMs`). A send over
  the quota fails with `rate_limited`. A send that fails with `not_connected` or `radio_error`
  does not count against the quota.
* The result is `{"queued": true}` once the radio accepted the command. MAY include `sendId`
  (string), an identifier for this send that is unique within the server's run. `queued` does not
  mean delivered: MeshCore does not acknowledge channel traffic.
* The server goes through the same transmit path as the host app's own messages (quiet-wait,
  flood scope, command acknowledgement). The API cannot bypass it.
* The server SHOULD answer every send within 10 seconds. If a send cannot reach the radio in that
  time, the server SHOULD cancel it and answer `radio_error`, so that a client that gives up does
  not see its message sent later. Clients SHOULD wait at least 15 seconds for a send response.
* Optional parameters of a send that need a capability (`region`, `path`, `pathHashSize`,
  `priority`) are described in section 8. A client MUST NOT send them unless the capability is in
  `hello.capabilities`.

#### `channel.sendData`

Sends binary data to a channel (MeshCore `CMD_SEND_CHANNEL_DATA`).

| Parameter | Type | Rule |
|---|---|---|
| `channel` | string | Channel name or slot number as a string (section 6.6). |
| `dataType` | integer | 1 to 65535. Out of range: `invalid_data_type`; not an integer: `bad_request`. |
| `payload` | string | Base64 of 1 to `limits.maxPayloadBytes` bytes. Longer: `payload_too_large`. Missing, empty or not base64: `bad_request`. |
| `region` | string, optional | Feature `regions` (section 8.3). |
| `path`, `pathHashSize` | optional | Feature `tx_path_data` (section 8.7). |
| `priority` | string, optional | Feature `tx_now` (section 8.16). |

If the radio firmware cannot send channel data (MeshCore firmware older than `FIRMWARE_VER_CODE`
11), the request fails with `unsupported_firmware`.

Clients MUST send `payload` as padded standard base64. Servers MAY also accept unpadded input.

The payload is carried unchanged. Its meaning is agreed between the applications that use the same
`dataType`; type numbers are allocated in MeshCore's `docs/number_allocations.md`.

```json
{"id":3,"method":"channel.sendData","params":{"channel":"#roadstr","dataType":336,"payload":"AQIDBA=="}}
{"id":3,"ok":true,"result":{"queued":true}}
```

#### `channel.sendText`

Sends a text message to a channel, as the host app's chat screen would.

| Parameter | Type | Rule |
|---|---|---|
| `channel` | string | As above. |
| `text` | string | 1 to 2000 code points. Otherwise `bad_request`. |
| `region` | string, optional | Feature `regions`. |
| `path`, `pathHashSize` | optional | Feature `tx_path_text` (section 8.8). |

MeshCore limits the size of one text packet, including the sender name the firmware prefixes. A
server MAY refuse a text that does not fit one packet with `payload_too_large`, and MUST NOT
truncate it silently. Clients that need a predictable result SHOULD keep channel texts short
(about 150 bytes of UTF-8).

### 6.6 Channel references

Where a method takes `channel` as a string, it is either a channel name or a slot number written
in decimal. The server resolves it against the current channel list:

1. If exactly one channel has that name (compared case-sensitively, byte for byte), use it.
2. If more than one channel has that name, fail with `ambiguous_channel`.
3. Otherwise, if the string is a decimal integer and a channel has that slot number, use it.
4. Otherwise fail with `unknown_channel`.

While the radio is not usable the channel list is empty, so every string reference fails with
`unknown_channel` (or `not_connected` for sends, section 6.5). Section 7.6 describes how clients
recover.

## 7. Core events and the device push

Every server MUST deliver `channel.text` and `channel.data`. Other event types belong to optional
features and are listed in `hello.eventTypes` when the server delivers them by default.

Every event object has `type` (string) and `receivedAt` (time). Clients MUST ignore event types
they do not know.

### 7.1 `receivedAt`

`receivedAt` is when the host app received the event from the radio, or for outgoing events when
the server emitted it. It is the replay cursor (section 8.5).

* It MUST be UTC with the `Z` suffix. It SHOULD have exactly millisecond precision
  (`2026-10-26T12:00:00.000Z`).
* It SHOULD be strictly increasing across all events a server emits, also across restarts: if
  two events would get the same time, the later one gets the next millisecond. This lets a client
  resume with `since` without losing a frame that shares a timestamp with the previous one.
* Clients MUST treat it as an opaque cursor when passing it back in `since`: send the string
  unchanged.

### 7.2 `channel.data`

| Field | Type | Meaning |
|---|---|---|
| `channel` | string | Channel name. |
| `channelIndex` | integer | Slot number. |
| `dataType` | integer | 1 to 65535. |
| `payload` | string | Base64 of the received bytes, unchanged. |
| `snrDb` | number or null | Signal-to-noise ratio of the received packet in dB. Null for outgoing events. |
| `hops` | integer or null | Flood hop count as the radio reports it; 0 means heard from the sender's own radio. Null when unknown, for packets that arrived by a direct path, and for outgoing events. |
| `outgoing` | boolean | `true` for data sent through this radio (section 7.5). |
| `receivedAt` | time | Section 7.1. |

Features `rx_meta`, `rx_path`, `rx_scope` and `rx_queued` add fields (sections 8.9, 8.10, 8.14, 8.15).

```json
{"type":"event","subscriptionId":"s1","event":{"type":"channel.data","channel":"#roadstr","channelIndex":1,"dataType":336,"payload":"AQIDBA==","snrDb":-7.25,"hops":2,"outgoing":false,"receivedAt":"2026-10-26T12:00:00.000Z"}}
```

### 7.3 `channel.text`

| Field | Type | Meaning |
|---|---|---|
| `channel` | string | Channel name. |
| `channelIndex` | integer | Slot number. |
| `senderName` | string or null | Sender name as carried in the message. |
| `senderKeyHex` | string or null | Sender public key in hex, when known. The companion protocol does not carry it for channel messages, so it is usually null. |
| `text` | string | Message text without the sender prefix. |
| `sentAt` | time | Sender's timestamp. |
| `messageId` | string | Opaque identifier, stable for the same message within one server run. |
| `outgoing` | boolean | Section 7.5. |
| `receivedAt` | time | Section 7.1. |

### 7.4 Ordering and loss

Events for one subscription are delivered in the order the server emitted them. The server does
not retry delivery: an event that arrives while a connection is closed is lost to that
connection, unless the `replay` feature keeps it (section 8.5).

### 7.5 Outgoing events

Sends through the API (from any client) MUST also be delivered as events with `outgoing: true` to
every matching subscription, including the sender's own. Sends from the host app's own user
interface SHOULD be delivered the same way.

* Channel data is emitted after the radio accepted the command.
* Text is emitted when it is queued, before the radio answers, as a chat screen shows it.

Outgoing events are not archived for replay.

### 7.6 The `device` push

The server sends the radio state to every authenticated connection, without a subscription,
whenever it changes after `hello`:

```json
{"type":"device","device":{"name":"Base 1","pubkey":"0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0","firmwareVerCode":11,"connected":false},"channels":[]}
```

| Field | Type | Meaning |
|---|---|---|
| `device.name` | string or null | As in `device.info`. |
| `device.pubkey` | string or null | As in `device.info`. |
| `device.firmwareVerCode` | integer or null | As in `device.info`. |
| `device.connected` | boolean | The radio is usable. |
| `channels` | array | As returned by `channels.list`. |

Rules:

* The server MUST send a `device` push when `connected`, the node identity or the channel list
  changes. It MUST NOT send a push whose content equals the last one sent to that connection (or
  the `hello`, for the first push). It MUST NOT put values that change often (battery, noise,
  counters) into the push.
* The server MAY coalesce bursts of changes; it SHOULD send the push within one second of the
  last change.

Client recovery: if `events.subscribe` with a `channel` fails with `unknown_channel` while the
radio is not usable, the client waits for a `device` push with `connected: true` and its channel
in `channels`, then subscribes again. It does not need to reconnect or poll. Existing
subscriptions stay in place across a radio reconnect and need no action.

## 8. Optional features

Each feature in this section has a capability name. A server that implements a feature MUST list
its name in `hello.capabilities`; a client MUST NOT use a feature whose name is absent. A request
for a method of a feature the server does not offer fails with `unknown_method` (old servers) or
`unsupported`.

Some capabilities depend on the radio, for example on the firmware version. The server computes
`capabilities` when it sends `hello`. If the radio changes later and a feature is no longer
possible, the server MUST answer `unsupported` (or `unsupported_firmware`) to requests that need it
and MUST NOT degrade silently, for example by flooding a packet that was meant to go along a path.

### 8.1 `contacts`: contacts, direct messages and adverts

Adds the method `contacts.list`, the method `direct.sendText`, the event types `direct.text` and
`advert` (listed in `hello.eventTypes`), and the `pubkeys` subscription filter.

**`contacts.list`**

| Parameter | Type | Rule |
|---|---|---|
| `limit` | integer, optional | 1 to 500, default 200. Values outside the range are clamped. Not an integer: `bad_request`. |

Result: `{"contacts": [{"pubkey", "name", "type", "lastSeen"}]}` where `pubkey` is 64 lowercase
hex characters, `name` is a string or null, `type` is the MeshCore node type (integer: 1 chat,
2 repeater, 3 room server, 4 sensor), and `lastSeen` is a time or null.

**`direct.sendText`**

| Parameter | Type | Rule |
|---|---|---|
| `pubkey` | string | The contact's public key in hex. Clients SHOULD send all 64 characters. Servers MUST compare case-insensitively and MAY accept a unique prefix of at least 12 hex characters. No match, or more than one: `unknown_contact`. |
| `text` | string | 1 to 2000 code points. |

Follows the rules of section 6.5. The firmware handles encryption, acknowledgement and path
discovery. If the radio cannot send direct messages, the request fails with `unsupported`.

**`direct.text` event**

| Field | Type | Meaning |
|---|---|---|
| `pubkey` | string | Sender (or for outgoing, recipient) public key, lowercase hex. |
| `name` | string or null | Contact name, when known. |
| `text` | string | Message text. |
| `sentAt` | time | Sender's timestamp. |
| `messageId` | string | Opaque identifier. |
| `outgoing` | boolean | Section 7.5. |
| `receivedAt` | time | Section 7.1. |

Servers SHOULD drop a repeated direct message (same sender, `sentAt` and text) that the firmware
delivers twice when an acknowledgement is late.

**`advert` event**

| Field | Type | Meaning |
|---|---|---|
| `pubkey` | string | Advertising node's public key, lowercase hex. |
| `name` | string or null | Advertised name. |
| `nodeType` | integer | MeshCore node type, as in `contacts.list`. |
| `lastSeen` | time or null | Advert timestamp. |
| `receivedAt` | time | Section 7.1. |

**`pubkeys` filter** in `events.subscribe`: an array of hex public keys, at most
`limits.maxFilterEntries`. When present and non-empty, only `direct.text` and `advert` events from
those keys are delivered to the subscription. Comparison is case-insensitive.

### 8.2 `advert_send`: sending an advert

Adds `advert.send`.

| Parameter | Type | Rule |
|---|---|---|
| `flood` | boolean, optional | Default `true`: a flood advert. `false`: zero-hop, heard only by radios in range. |

Result and rules as in section 6.5.

### 8.3 `regions`: flood-scope regions

MeshCore repeaters can be configured to forward floods only within named regions (flood scope).
This feature lets a client pick a region for one send.

**`region` parameter** in `channel.sendData` and `channel.sendText`: a region name that overrides
the channel's flood scope for this message. Without it, the scope the host app would use for the
channel applies. The server MUST refuse names it does not know, so that a typo cannot send a flood
that no repeater forwards:

* A name the server knows (from `regions.list` or configured by the user in the host app) is used.
* A well-formed name it does not know fails with `unknown_region`. Well-formed: 1 to 30
  characters from `a-z`, `0-9` and `-`.
* Anything else, including the empty string and names starting with `!`, fails with
  `bad_request`.

A flood scope does not change a zero-hop or direct send (section 8.7); `region` is still validated
there.

A server that does not offer `regions` MUST refuse a `region` parameter with `unsupported` rather
than ignore it.

**`regions.list`**: no parameters. Returns the server's catalogue of suggested regions:

```json
{"regions":[{"name":"xx-city","label":"Test City","kind":"city","lat":48.70,"lon":21.25,"radiusKm":20}]}
```

| Field | Type | Meaning |
|---|---|---|
| `name` | string | Region name as repeaters use it. |
| `label` | string | Human-readable name. |
| `kind` | string | `city` or `country`; informational. Clients MUST accept other values. |
| `lat`, `lon` | number | Centre in degrees (WGS 84). |
| `radiusKm` | number | Radius of the covered circle. |

The catalogue is a suggestion. Repeaters forward a region only when their operators configured
the same name. A server MAY accept further names configured by the user that have no centre and
are not listed.

**`regions.resolve`**

| Parameter | Type | Rule |
|---|---|---|
| `lat` | number | -90 to 90. |
| `lon` | number | -180 to 180. |

Missing or non-numeric: `bad_request`. Out of range: `coordinate_range`.

Result: `{"region": {...}}` with the fields of a `regions.list` entry plus `distanceKm`, or
`{"region": null}`. The server picks the catalogue entry with the **nearest centre whose circle
contains the point**. Distance is the great-circle (haversine) distance on a sphere of radius
6371 km; a point exactly on the circle is inside. A city usually beats a country because its
centre is nearer, not because of its kind. `vectors/regions.json` has cases.

### 8.4 `channels_join`: adding a hashtag channel

Adds `channels.join`, which asks the user to add a hashtag channel to the radio. A hashtag channel's
key is derived from its name, so no secret crosses the API:

```
key = first 16 bytes of SHA-256(UTF-8 bytes of the name, including the leading "#")
```

| Parameter | Type | Rule |
|---|---|---|
| `name` | string | `#` followed by 1 to 31 characters from `a-z`, `0-9` and `-`. Otherwise `invalid_params`. |

Result: `{"index": <slot>, "name": "<name>", "created": <boolean>}`.

Behaviour:

1. If the radio is not usable: `not_connected`.
2. If a channel with this name and the derived key exists: answer at once with its slot and
   `created: false`.
3. If a channel with this name but another key exists: `channel_conflict`.
4. Otherwise the host app asks the user (section 11.2), naming the client and the channel. A
   headless host app MAY instead apply an operator policy (always allow, always deny, or an
   allowlist of names).
5. Denied, or no answer within the prompt timeout (RECOMMENDED 2 minutes): `denied`.
6. Allowed: the channel goes into the first free slot, and a `device` push with the new channel
   list follows. No free slot: `no_free_slot`.

The same prompt limits apply as for pairing (section 9.2); a key may repeat a request for the same
channel after 30 seconds. Clients SHOULD wait at least 150 seconds for the response, keep the
connection open meanwhile (disconnecting withdraws the request), ask once when
`events.subscribe` fails with `unknown_channel` while the radio is usable, and not ask again after
`denied` until their own user does something.

### 8.5 `replay`: channel data archive

The radio queues channel traffic while no host app is connected, and the host app drains that
queue when it connects. A client started later would miss it. With this feature the server keeps
a small archive of received channel data and replays it on request.

Archive rules:

* Only received `channel.data` is kept, never outgoing events.
* Only `(channel, dataType)` pairs that some paired client subscribed to with a `channel` are
  kept. A subscription with `channel` and without `dataTypes` covers every type on that channel.
  These interests are stored per client key and survive restarts of the host app.
* The archive has a bound on entries and age (section 9.3).
* Revoking a client forgets its interests and every frame that only it wanted.
* The host app SHOULD let the user clear the archive.

**`since`** in `events.subscribe`: replay archived frames received at or after this time that match
the subscription's filters **and** this client's own interests. Accepted forms:

* An RFC 3339 date-time with `Z` or a numeric offset. A date-time without an offset, or a date
  without a time, MUST be refused with `bad_request`.
* A non-negative integer: epoch seconds, or epoch milliseconds when it is greater than
  100000000000.

Anything else fails with `bad_request`. Fractions below a millisecond are truncated.

Order: the subscription response, then the replayed events oldest first, then live events, with
nothing in between. `since` is inclusive: a client that passes the `receivedAt` of the last frame
it saw gets that frame again and MUST deduplicate (for example by remembering the last
`receivedAt` and payload). Replayed events have the same shape as live ones and use the new
subscription's id.

A server that does not offer `replay` MUST ignore `since` (after the subscription is created, no
replay follows).

Replayed events SHOULD NOT count against the slow-consumer bound (section 9.1), because the
server controls their volume.

### 8.6 `replay_text`: text archive

Requires `replay`. The server also archives received `channel.text` and `direct.text` events
(within the same bounds) and replays them for `since` when the subscription includes those types.
The interest rule of section 8.5 does not apply to texts; the subscription's filters do.

### 8.7 `tx_path_data`: channel data along an explicit path

`channel.sendData` floods by default. With this feature it takes:

| Parameter | Type | Rule |
|---|---|---|
| `path` | string or null, optional | Hex: the hop hashes in the order the packet travels, first hop first. Absent or null: flood. `""`: zero-hop. |
| `pathHashSize` | integer or null, optional | 1, 2 or 3 (default 1): bytes per hop hash. |

* `"path": ""` is **zero-hop**: only radios in range of this node hear the packet and no
  repeater forwards it.
* A non-empty path is a direct send along that route.
* The decoded path length MUST be a multiple of `pathHashSize`, at most 63 hops and at most 64
  bytes. The firmware's packed `path_len` byte is `(pathHashSize - 1) << 6 | hops`.
* Anything else is `bad_request`, and nothing is sent.

```json
{"id":5,"method":"channel.sendData","params":{"channel":"#roadstr","dataType":336,"payload":"AQIDBA==","path":"","pathHashSize":1}}
```

**A client MUST NOT send `path` unless `tx_path_data` is in `hello.capabilities`.** A server
without the feature that ignores unknown parameters would flood the packet, which is wrong for a
packet meant to stay local. `vectors/validators.json` has path cases.

### 8.8 `tx_path_text`: channel text along an explicit path

The same `path` and `pathHashSize` parameters for `channel.sendText`, with the same rules as
section 8.7.

A server that implements `channel.sendText` but not this feature MUST refuse a request with a
non-null `path` with `unsupported` instead of flooding the text.

### 8.9 `rx_meta`: receive metadata

Received `channel.data`, `channel.text` and `direct.text` events carry these fields when known
(absent or null when unknown):

| Field | Type | Meaning |
|---|---|---|
| `snrDb` | number | SNR in dB (already core for `channel.data`). |
| `rssiDbm` | integer | RSSI in dBm. |
| `hops` | integer | Flood hop count (already core for `channel.data`). |
| `routeType` | string | `flood`, `direct`, `tflood` or `tdirect` (the `t` forms carry a flood-scope transport code). Clients MUST accept other values. |

A zero-hop packet has `hops: null`, `routeType: "direct"` and, with `rx_path`, `path: ""`.

A server MAY list `rx_meta` and fill the fields only for some event types or some packets (for
example not for frames the radio queued while no app was connected); clients MUST treat a missing
field as unknown.

### 8.10 `rx_path`: receive path

Received `channel.data`, `channel.text` and `direct.text` events carry, when known:

| Field | Type | Meaning |
|---|---|---|
| `path` | string | Hex: the repeater hashes in the order the packet travelled, first hop first. |
| `pathHashSize` | integer | 1, 2 or 3. |

A client that wants to answer along the same route reverses the hop order and sends with
`tx_path_data`.

The path is the one the packet carried when this radio heard it. For a flood packet that is every
repeater it passed. A direct packet loses one hash at each hop, so it arrives with an empty path
whether it was sent zero-hop or along a route; `path: ""` means heard from the sender's radio only
together with `routeType` `flood` or `tflood`, or when the client knows the sender sends direct
packets zero-hop only.

In MeshCore companion firmware the path and RSSI are not in the decrypted channel frames
(`RESP_CODE_CHANNEL_DATA_RECV`, `RESP_CODE_CHANNEL_MSG_RECV_V3`), which carry the SNR and the
packed path length (`0xFF` for a direct packet). A server takes them from `PUSH_CODE_LOG_RX_DATA`
(0x88), sent for every packet the radio hears while an app is connected, and pairs that packet
with the frame by decrypting it with the channel key.

### 8.11 `radio_stats` and related capabilities

Adds the method `radio.stats` (no parameters). Every field may be null when unknown:

| Field | Type | Meaning |
|---|---|---|
| `connected` | boolean | As in `device.info`. |
| `noiseFloorDbm` | integer | Radio noise floor. |
| `lastRssiDbm` | integer | RSSI of the last received packet. |
| `lastSnrDb` | number | SNR of the last received packet. |
| `preset` | object | `freqHz`, `bwHz`, `sf`, `cr`, `txPowerDbm`. |
| `defaultRegion` | string | The flood scope used when a send names none. |
| `airtime` | object | `tx60sMs`, `tx1hMs` (transmit time in the last minute and hour), `budgetMs`, `budgetRemainingMs` (the server's airtime cap, when it enforces one). |
| `counters` | object | `rx`, `tx`, `txErrors` and further implementation-defined counters (integers). |

The server MAY add fields (for example `mode`). Related capabilities describe what the numbers
mean:

* `airtime`: `airtime.tx60sMs` and `airtime.tx1hMs` are filled.
* `noise_floor`: `noiseFloorDbm` is filled.
* `duty_cap`: the server enforces an airtime cap. A send that would exceed it fails with `budget`.
  `airtime.budgetMs` and `airtime.budgetRemainingMs` are filled.

`radio.stats` is a method, not a push: clients poll it as needed, at most about once a minute.

### 8.12 `raw_rx` and `raw_tx`: raw packets (permission `raw`)

Raw packets are a stronger right than what a chat client sees: a client can read every packet the
radio hears, including encrypted traffic of channels the radio does not know, and can transmit any
packet. Both features therefore need the pairing permission `raw` (section 5.8) in addition to the
capability. Without the permission, requests fail with `forbidden`.

**`raw_rx`**: the event type `packet.raw`, delivered only when named in `events` (it is not in
`hello.eventTypes`):

| Field | Type | Meaning |
|---|---|---|
| `raw` | string | Hex of the whole packet as received. |
| `payloadType` | integer | MeshCore payload type, 0 to 15. |
| `duplicate` | boolean | The radio had already seen this packet hash. |
| `receivedAt` | time | Section 7.1. |
| `snrDb`, `rssiDbm`, `routeType`, `path`, `pathHashSize` | | As in sections 8.9 and 8.10, when known. |

The `events.subscribe` filter `payloadTypes` (array of integers 0 to 15, at most
`limits.maxFilterEntries`) keeps only those payload types. `channel`, `dataTypes` and `pubkeys` do
not apply to `packet.raw`. Raw packets are not archived and `since` does not replay them.

**`raw_tx`**: the method `packet.sendRaw`.

| Parameter | Type | Rule |
|---|---|---|
| `raw` | string | Hex of a complete MeshCore packet, 1 to 255 bytes. Not hex: `bad_request`; empty or longer: `payload_too_large`. |

Follows the rules of section 6.5. The server SHOULD parse the packet as the firmware would and
refuse one the firmware would drop.

### 8.13 `tx_result` (reserved)

Reserved for a future event `send.result` that reports when a send actually left the radio:
`sendId`, `status` (`sent` or `failed`), `sentAt`, `airtimeMs`, `error`. Delivered only when named
in `events` and only to the connection that sent. Companion firmware does not report this, so no
current server offers it. The name is reserved so that it is not used for something else.

### 8.14 `rx_scope`: flood scope of received packets

Received `channel.data` events (and, where the server says so, other received events) of a packet
with transport codes (`routeType` `tflood` or `tdirect`) carry, when known:

| Field | Type | Meaning |
|---|---|---|
| `transportCode` | integer | The packet's first transport code (`code[0]`, little-endian, 0 to 65535). It is derived from the flood-scope key and the packet, so it names the scope only together with the packet. |
| `scope` | string | The flood-scope name, without a leading `#`, whose key gives `transportCode` for this packet, when exactly one of the names the server knows does. Absent when none or several match. |

A client that answers in the scope a packet came in uses `scope` with the `region` parameter
(section 8.3), or tests the names it knows against `transportCode` when it has the packet. A
packet without transport codes has neither field; it was sent unscoped or direct.

### 8.15 `rx_queued`: frames from the radio's offline queue

MeshCore companion firmware keeps what it receives while no app reads it, and the app drains that
queue after it connects. Such a frame was heard at an unknown earlier time, and its `receivedAt`
is the time the server fetched it.

| Field | Type | Meaning |
|---|---|---|
| `queued` | boolean | `true` on a received event the radio held in its offline queue while no app was reading it. Absent or `false` on a live event. |

A server marks every event it drains after a connect, before the radio first reports the queue
empty, unless it knows the packet was heard live (for example from `PUSH_CODE_LOG_RX_DATA`, section
8.10). A client MUST NOT take the `receivedAt` of a `queued` event as the time the packet was on
the air. Without this capability a client cannot tell queued frames from live ones and SHOULD
treat events in the first seconds after `device.connected` turns true as of unknown age.

A server with `rx_queued` SHOULD give a live event the time the radio heard the packet as its
`receivedAt` when it has it (the raw RX push), not the time it fetched the decoded frame, within
the ordering rule of section 7.1.

### 8.16 `tx_now`: sends that must not wait

The parameter `priority` on `channel.sendData`:

| Value | Meaning |
|---|---|
| absent, null or `"normal"` | The send goes through the host's usual pacing (section 6.5). |
| `"now"` | The server skips its own back-off after received traffic and its wait for a quiet radio, and does not queue the send behind other sends' waits where it can avoid it. The firmware's own listen-before-talk still applies. |

Any other value is `bad_request`. A server applies `"now"` only to small packets: it advertises
nothing, but MeshCore Open applies it to packets of at most 40 bytes on air. A larger packet is
sent with the normal waits.

With this capability every `channel.sendData` result carries `sentAt` (time), when the radio
acknowledged the command, and, when the request had `priority`, `priority` with the value that was
applied:

```json
{"id":7,"method":"channel.sendData","params":{"channel":"#libretag","dataType":65356,"payload":"…","path":"","priority":"now"}}
{"id":7,"ok":true,"result":{"queued":true,"sentAt":"2026-11-26T12:00:12.215Z","priority":"now"}}
```

`sentAt` is when the radio took the packet, not when it finished transmitting. A client that
times a send against a deadline compares `sentAt` with its own clock.

## 9. Limits

### 9.1 Advertised limits

The server reports these in `hello.limits`. Clients MUST respect the advertised values and MUST
NOT assume the defaults.

| Field | Meaning | Recommended default |
|---|---|---|
| `maxPayloadBytes` | Largest `channel.sendData` payload. | 163 |
| `maxMessageBytes` | Largest inbound WebSocket message; larger closes with 1009. | 16384 |
| `maxQueuedBytes` | Outbound bytes queued for a connection and not yet taken by the operating system. A client that stops reading is closed with 4013 instead of growing the server's memory. | 262144 |
| `sendsPerMinute` | Sends per connection in any 60-second window. | 30 |
| `minSendGapMs` | Minimum time between two sends of one connection. | 2000 |
| `minSendGapExemptBytes` | Optional. A `channel.sendData` payload of at most this many bytes may follow the previous send closer than `minSendGapMs`; it still counts in `sendsPerMinute`. Absent: no exemption. | 32 |
| `maxSubscriptions` | Subscriptions per connection. | 16 |
| `maxFilterEntries` | Entries in each of `dataTypes`, `pubkeys`, `payloadTypes`. | 32 |

163 bytes is the bound the existing servers use for one channel data payload over BLE. MeshCore's
own radio-side limit is 165 bytes; a server whose transport carries more MAY advertise up to 165.

The send quota is in addition to the radio's own pacing (quiet-wait and firmware duty cycle).

### 9.2 Other limits

These are not advertised. Servers SHOULD use the recommended values.

| Limit | Recommended |
|---|---|
| Authenticated connections at once | 4 (one more: `too_many_clients`, 4013) |
| Connections that have not finished pairing | 2 (one more: HTTP 503) |
| Handshake timeout, from connect to `pair` | 10 s |
| User prompt timeout (pairing, `channels.join`) | 2 min |
| Open prompts per key | 1 (`pairing_pending`) |
| Open prompts overall | 3 (`rate_limited`) |
| Interval before the same key may prompt again (for pairing, or for the same channel) | 30 s (`rate_limited`) |
| Prompts started per minute, overall | 4 (`rate_limited`) |
| Sends waiting for the radio per connection | 8 (`rate_limited`) |

### 9.3 Archive

With `replay`, the archive SHOULD keep at most 200 frames and 24 hours by default. A host app MAY
let the user raise these. With `replay_text`, texts have their own bound of the same size.

## 10. Errors and close codes

### 10.1 Error codes

Codes are lowercase strings. Clients MUST treat an unknown code as a failure of that request.

| Code | Meaning | Where |
|---|---|---|
| `unauthorized` | Handshake out of order, bad signature, pairing denied or timed out. | handshake |
| `pairing_pending` | This key already has a prompt open. | handshake, `channels.join` |
| `rate_limited` | Too many sends, subscriptions, waiting sends or prompts. | any |
| `too_many_clients` | The maximum number of authenticated connections is reached. | handshake |
| `bad_request` | Missing or malformed parameter, bad JSON, invalid public key. | any |
| `unknown_method` | No such method. | any |
| `not_connected` | The radio is not usable. | sends, `channels.join` |
| `unsupported_firmware` | The radio firmware cannot do this (channel data needs `FIRMWARE_VER_CODE` 11). | `channel.sendData` |
| `unsupported` | A feature this server or radio does not offer. | any |
| `invalid_params` | `channels.join` with a name that is not a hashtag channel name. | `channels.join` |
| `invalid_data_type` | A `dataType` outside 1 to 65535. | `channel.sendData`, `events.subscribe` |
| `payload_too_large` | Payload or packet over the limit. | sends |
| `unknown_channel` | No channel with that name or slot. | channel references |
| `ambiguous_channel` | More than one channel with that name. | channel references |
| `unknown_contact` | No unique contact for that key. | `direct.sendText` |
| `unknown_region` | A well-formed region name the server does not know. | sends |
| `coordinate_range` | `lat` or `lon` out of range. | `regions.resolve` |
| `denied` | The user did not allow the request. | `channels.join` |
| `no_free_slot` | The radio has no free channel slot. | `channels.join` |
| `channel_conflict` | A channel with that name and another key exists. | `channels.join` |
| `forbidden` | The pairing lacks a permission this request needs. | `raw_rx`, `raw_tx` |
| `budget` | The airtime cap would be exceeded. | sends with `duty_cap` |
| `radio_error` | The radio refused the command or did not answer. | sends, `channels.join` |
| `internal` | Anything else. | any |

New codes are additive (section 12.1).

### 10.2 Close codes

| Code | Meaning |
|---|---|
| 1000 | Normal closure. |
| 1001 | The server is stopping. |
| 1003 | The client sent a binary frame. |
| 1009 | A message exceeded `limits.maxMessageBytes`. |
| 1011 | Internal server error. |
| 4001 | Handshake out of order or timed out. |
| 4003 | Key, signature or pairing refused, or the pairing was revoked (reason `revoked`). |
| 4013 | Slow consumer (`maxQueuedBytes` exceeded) or too many clients. Used instead of 1013, which some WebSocket libraries do not send. |

Close reasons are informational except `revoked`, which a client MAY show to its user. A server
SHOULD send the close frame and SHOULD drop the TCP connection shortly after (about one second) if
the client does not complete the closing handshake.

Client guidance: after 1001, 1006 or 1011, reconnect with backoff (for example 5 s doubling to
60 s). After 4003, see section 5.7. After 4013, reconnect and read faster.

### 10.3 `maybeSent`

When a send fails with `radio_error` after the command was written to the radio but before the
radio confirmed it, the packet may have gone out. The server SHOULD then add `"maybeSent": true` to
the error object:

```json
{"id":3,"ok":false,"error":{"code":"radio_error","message":"no answer from the radio","maybeSent":true}}
```

A client SHOULD NOT resend such a message blindly; it SHOULD treat it as possibly delivered (for
example, deduplicate on the receiving side). Without `maybeSent`, a `radio_error` means the
command was not sent.

## 11. Security considerations

### 11.1 Threat model

The server is reachable by every process on the device that can open a TCP connection to
loopback, which on a computer includes processes of other users. The protections are:

* the server exists only when the user enabled it (section 11.2);
* it is not reachable from other machines (section 3.1);
* web pages cannot reach it (`Origin` refused, section 3.2);
* no client can use it before the user approves that client's key (section 5).

An approved client can read the user's channel and direct messages and transmit on the user's
radio. That is the same power the host app has. Approval is the boundary, so the prompt says so
and every approval is revocable.

### 11.2 Host app requirements

These requirements apply to every host app, whatever its user interface.

* The API MUST be off by default. The host app MUST NOT open the port until the user enables the
  API by a deliberate action.
* For every key that is not paired, the host app MUST ask the user and MUST NOT approve
  automatically. The prompt MUST show the client's name and its fingerprint (section 5.2), MUST
  say that the client will be able to read messages and transmit on the radio, and MUST need an
  explicit action to allow. Closing the prompt or letting it time out denies. The prompt SHOULD
  say that the name is chosen by the client itself.
* If the host app is not in the foreground when a prompt starts, it SHOULD notify the user (for
  example with a system notification) and show the prompt when the user responds.
* A headless host app (a daemon) replaces the prompt with an operator action that names the
  pending request's fingerprint, or with a configured allowlist of full public keys. It MUST NOT
  offer a mode that approves whichever key connects first.
* The host app MUST list paired clients and let the user revoke each (section 5.8).
* `channels.join` MUST get the user's consent (section 8.4) or follow an operator policy that the
  operator set explicitly.
* The host app MUST store only client public keys, never ask for or receive private keys.
* Logs SHOULD NOT contain message texts, payloads, signatures or nonces.
* The API MUST NOT allow changing radio settings, contacts or keys, other than `channels.join`.

### 11.3 Key and signature handling

* The nonce MUST be fresh per connection and come from a cryptographically secure generator. The
  signed string carries a fixed prefix so that a pairing signature cannot be mistaken for a
  signature in another protocol, and the client checks the prefix before signing (section 5.5).
* A client MUST NOT sign a `message` it did not check. Otherwise a malicious server could make it
  sign arbitrary data with its identity key.
* The fingerprint is 64 bits. It is for a human comparing two strings, not a unique identifier.
  Implementations MUST identify keys by the full public key. Operator commands that approve by
  fingerprint MUST match only requests that are pending at that moment.
* The client name is self-declared. Two clients can use the same name. The host app MUST NOT use
  the name for anything but display.
* Clients SHOULD keep the private key in platform key storage where one exists, or in a file
  readable only by the client's user.

### 11.4 Server authenticity

The client does not authenticate the server. A process that binds the port before the host app
can accept connections and read whatever clients send. It cannot obtain a pairing to the real
server with a captured signature, because the nonce is chosen by the server for each connection,
but it could relay a live handshake if the real server listens elsewhere. Host apps SHOULD fail
loudly when the port is taken, and clients SHOULD show the user when the server's `device` identity
changes unexpectedly. Server authentication is out of scope for protocol 1.

### 11.5 Denial of service

The limits in section 9 bound memory, prompts and airtime per connection. A local process can
still open connections up to the limits and deny them to others; this is accepted, as the user can
disable the API or revoke the client.

## 12. Versioning and compatibility

### 12.1 Additive changes

Within protocol 1, these changes are additive and need no version change:

* a new optional field in a response, an event or `hello`;
* a new method, event type, error code, permission or capability;
* a new optional request parameter, if a client only sends it after checking a capability.

Clients MUST ignore unknown fields, event types, capabilities and pushes. Servers MUST ignore
unknown request fields, with the exception in section 4.1.

A change to the meaning of an existing field, method or code is not additive. It needs a new
capability name (if the old behaviour stays available) or a new protocol version.

### 12.2 New protocol versions

A future incompatible version uses a new path (`/api/v2`) and a new `protocol` value. A server MAY
serve several versions on their paths. A client that finds no server on the version it implements
SHOULD say so to its user rather than fall back silently.

## 13. Capability registry

### 13.1 Registered names

| Name | Feature | Section | Notes |
|---|---|---|---|
| `contacts` | `contacts.list`, `direct.sendText`, events `direct.text` and `advert`, filter `pubkeys` | 8.1 | |
| `advert_send` | `advert.send` | 8.2 | |
| `regions` | `regions.list`, `regions.resolve`, `region` on sends | 8.3 | |
| `channels_join` | `channels.join` | 8.4 | |
| `replay` | channel data archive, `since` | 8.5 | |
| `replay_text` | text archive for `since` | 8.6 | requires `replay` |
| `tx_path_data` | `path`, `pathHashSize` on `channel.sendData` | 8.7 | |
| `tx_path_text` | `path`, `pathHashSize` on `channel.sendText` | 8.8 | |
| `rx_meta` | `snrDb`, `rssiDbm`, `hops`, `routeType` on received events | 8.9 | |
| `rx_path` | `path`, `pathHashSize` on received events | 8.10 | |
| `radio_stats` | `radio.stats` | 8.11 | |
| `airtime` | airtime figures in `radio.stats` | 8.11 | |
| `noise_floor` | `noiseFloorDbm` in `radio.stats` | 8.11 | |
| `duty_cap` | server-side airtime cap, error `budget` | 8.11 | |
| `raw_rx` | event `packet.raw`, filter `payloadTypes` | 8.12 | needs permission `raw` |
| `raw_tx` | `packet.sendRaw` | 8.12 | needs permission `raw` |
| `tx_result` | event `send.result` | 8.13 | reserved |
| `rx_scope` | `transportCode`, `scope` on received events | 8.14 | |
| `rx_queued` | `queued` on received events | 8.15 | |
| `tx_now` | `priority` on `channel.sendData`, `sentAt` in its result | 8.16 | |

### 13.2 Rules for new names

* A capability name is 1 to 32 characters from `a-z`, `0-9` and `_`, starting with a letter.
* A registered name is added by a change to this table that defines the feature in section 8,
  including what a server without it does with the feature's parameters.
* A registered name never changes meaning. An incompatible revision of a feature gets a new name.
* Names starting with `x_` are for experiments and implementation-specific features and are never
  registered. They SHOULD include the implementation, as in `x_meshcored_foo`. Clients that are not
  written for that implementation SHOULD NOT depend on them.
* A feature that only adds fields to responses or events that clients can detect by their
  presence does not need a capability. A feature needs one when a client must know about it before
  sending something (a new parameter, a new method, an event type to request).

## 14. References

* RFC 2119 and RFC 8174, key words.
* RFC 3339, date and time on the internet.
* RFC 4648, base64 and base64url.
* RFC 6455, the WebSocket protocol.
* RFC 6979, deterministic ECDSA (used only to generate the test vectors).
* RFC 8259, JSON.
* SEC 1 v2 and SEC 2 v2 (Standards for Efficient Cryptography), P-256 curve and point encoding.
* FIPS 186-5, ECDSA.
* MeshCore companion protocol and `docs/number_allocations.md` in the MeshCore firmware
  repository.

## Appendix A. Implementations

Two servers implement this specification. Both pass the vectors in `vectors/` in their own test
suites.

| | MeshCore Open (fork) | meshcored |
|---|---|---|
| Platform | Android, iOS, desktop; radio over BLE, USB or TCP | Linux and macOS daemon; radio over USB serial |
| Source | `jooray/meshcore-open`, branch `test/localapi-10`, `lib/services/local_api/`; upstream PRs zjs81/meshcore-open#619 and #628 | `crates/localapi`, `crates/meshcored/src/` |
| Pairing approval | dialog with name and fingerprint, notification when in the background | `meshcored pair approve <fingerprint>`, or a key allowlist in the config |
| `hello.server.name` | `meshcore-open` | `meshcored` |

Capabilities each one lists:

| Capability | MeshCore Open | meshcored |
|---|---|---|
| `contacts` | yes | yes, when the driver has direct messages |
| `advert_send` | yes | yes |
| `regions` | yes | yes |
| `channels_join` | yes | yes |
| `replay` | yes, when the archive exists | yes |
| `replay_text` | no | yes |
| `tx_path_data` | yes | yes |
| `tx_path_text` | no | yes, firmware ver 12 and later (`CMD_SEND_RAW_PACKET`) |
| `rx_meta`, `rx_path` | yes, on `channel.data` only | yes |
| `rx_scope`, `rx_queued`, `tx_now` | yes, on `channel.data` only | no |
| `radio_stats`, `airtime`, `noise_floor`, `duty_cap` | no | yes (`duty_cap` when the cap is on) |
| `raw_rx`, `raw_tx` | no | yes, with the `raw` permission |

Behaviour that the specification leaves to the implementation and where they differ:

* meshcored returns `sendId` with `queued`, holds at most 8 waiting sends per connection and
  answers every send within 10 seconds. MeshCore Open has no waiting-send cap.
* meshcored keeps the last capability list in its state database and sends it while the radio is
  away, so a client that connects early does not get a shorter list. MeshCore Open computes the
  list from its own settings, which do not depend on the radio.
* MeshCore Open's outgoing events include messages sent from its own chat screen. meshcored has no
  chat screen.
* MeshCore Open refuses `path` on `channel.sendText` with `unsupported`, since it does not list
  `tx_path_text`.
* MeshCore Open advertises `minSendGapExemptBytes: 32`, so an acknowledgement and a command of
  one client can leave a few hundred milliseconds apart.

Clients: the libraries in `kotlin/`, `python/` and `js/` of this repository, used by Roadbeacon,
LibreTag, the nostrmesh bridges (Python and Android) and the MeshCore-BTC bot. Roadstr has its own
Kotlin client (roadstrapp/roadstr-app#15).

## Appendix B. Adding the API to a MeshCore app

A short checklist for an app that holds the radio and wants to offer this API:

1. A WebSocket server on `127.0.0.1:8787`, path `/api/v1`, off until the user turns it on. Refuse
   requests with an `Origin` header and a non-loopback `Host` (section 3).
2. The handshake and pairing of section 5, with a dialog that shows the client's name and
   fingerprint. Store only public keys, and let the user remove them.
3. The core methods and events of sections 6 and 7, sent through the app's normal send path so
   quiet-wait, flood scope and rate limits still apply.
4. Optional features from section 8 as the app can support them, each listed in
   `hello.capabilities`. A small first version can offer the core only.
5. Run the vectors in `vectors/` in the app's tests. The Dart and Rust test files in `vectors/gen/`
   show how.

## Appendix C. Example session

The client's key is the test key from `vectors/pairing.json`. All identifiers are synthetic.

```
C: {"type":"hello","client":{"name":"Roadbeacon","version":"0.4.0","publicKey":"4sNKerSGIKbZjuvSegPkjnBw/oCzEoj8MDy3+bIP5ooQMbcevcA2Yz4iT8w8yEJPmoz8gxjZvwKwIOhAh+ZtVQ=="}}
S: {"type":"pairing.challenge","protocol":1,"nonce":"d3zXMrhxhqHuEyHUe4MkXA","fingerprint":"9C5F A624 034B 4EC7","message":"meshcore-local-api-pair-v1:d3zXMrhxhqHuEyHUe4MkXA"}
C: {"type":"pair","signature":"MEQCIE06E9rqT3uegWmygI+ChZttyQ7N+X+khUAMBctZo3yhAiBvyIgLiLNk8nxSrzl5qbViU7PlgN7RF/kayybjmY5q1Q=="}
   (the user allows "Roadbeacon", 9C5F A624 034B 4EC7)
S: {"type":"hello","protocol":1,"client":{"name":"Roadbeacon","fingerprint":"9C5F A624 034B 4EC7"},"device":{"name":"Base 1","pubkey":"0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0","firmwareVerCode":11,"connected":true},"eventTypes":["channel.text","channel.data","direct.text","advert"],"limits":{"maxPayloadBytes":163,"maxMessageBytes":16384,"maxQueuedBytes":262144,"sendsPerMinute":30,"minSendGapMs":2000,"maxSubscriptions":16,"maxFilterEntries":32},"capabilities":["contacts","advert_send","regions","channels_join","replay","tx_path_data"]}
C: {"id":1,"method":"events.subscribe","params":{"events":["channel.data"],"channel":"#roadstr","dataTypes":[336],"since":"2026-10-26T11:00:00.000Z"}}
S: {"id":1,"ok":false,"error":{"code":"unknown_channel","message":"no channel named #roadstr"}}
C: {"id":2,"method":"channels.join","params":{"name":"#roadstr"}}
   (the user adds #roadstr)
S: {"type":"device","device":{"name":"Base 1","pubkey":"0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0","firmwareVerCode":11,"connected":true},"channels":[{"index":0,"name":"Public","isPublic":true,"storageId":"7a1c0e5f9b3d2a48"},{"index":1,"name":"#roadstr","isPublic":false,"storageId":"c4d1b2a39e8f7061"}]}
S: {"id":2,"ok":true,"result":{"index":1,"name":"#roadstr","created":true}}
C: {"id":3,"method":"events.subscribe","params":{"events":["channel.data"],"channel":"#roadstr","dataTypes":[336],"since":"2026-10-26T11:00:00.000Z"}}
S: {"id":3,"ok":true,"result":{"subscriptionId":"s1"}}
C: {"id":4,"method":"regions.resolve","params":{"lat":48.71,"lon":21.33}}
S: {"id":4,"ok":true,"result":{"region":{"name":"xx-city","label":"Test City","kind":"city","lat":48.70,"lon":21.25,"radiusKm":20,"distanceKm":5.974904}}}
C: {"id":5,"method":"channel.sendData","params":{"channel":"#roadstr","dataType":336,"payload":"AQIDBA==","region":"xx-city"}}
S: {"id":5,"ok":true,"result":{"queued":true}}
S: {"type":"event","subscriptionId":"s1","event":{"type":"channel.data","channel":"#roadstr","channelIndex":1,"dataType":336,"payload":"AQIDBA==","snrDb":null,"hops":null,"outgoing":true,"receivedAt":"2026-10-26T12:00:02.000Z"}}
S: {"type":"event","subscriptionId":"s1","event":{"type":"channel.data","channel":"#roadstr","channelIndex":1,"dataType":336,"payload":"BQYHCA==","snrDb":-7.25,"hops":2,"outgoing":false,"receivedAt":"2026-10-26T12:00:09.000Z"}}
```
