# meshcore-local-api for Kotlin

A Kotlin/JVM client for the MeshCore Local API, the loopback WebSocket at
`ws://127.0.0.1:8787/api/v1` through which a MeshCore host app (MeshCore Open, meshcored) lets
other apps on the same device use its radio. It has no Android imports, so it works in an
Android app (minSdk 26, for `java.util.Base64`) and on a plain JVM.

Dependencies: OkHttp 4.12, kotlinx.coroutines 1.7, kotlinx.serialization-json 1.6.

## Install

From JitPack:

```kotlin
// settings.gradle.kts
dependencyResolutionManagement {
    repositories { maven("https://jitpack.io") }
}

// build.gradle.kts
dependencies {
    implementation("com.github.jooray:meshcore-local-api:<tag>")
}
```

## Use

```kotlin
val session = MeshApiSession(
    MeshApiSession.Config(
        clientName = "My App", clientVersion = "1.0",
        channel = "#myapp", dataTypes = listOf(0xFF00),
    ),
    keyStore = prefsKeyStore,        // your KeyStore: load()/save() of one string
    scope = CoroutineScope(SupervisorJob() + Dispatchers.IO),
    cursorStore = prefsCursorStore,  // optional: replay what arrived while the app was off
    logger = androidLogger,          // optional: forward to android.util.Log
)
session.start()

scope.launch { session.state.collect { showStatus(it) } }
scope.launch { session.datagrams.collect { d -> handle(d.payload, d.hops, d.snrDb) } }

// Later, when connected:
val sent = session.sendData(payload, region = "xx-region")
if (session.canSendPath) session.sendData(payload, route = Route.ZeroHop)
println(session.fingerprint)         // what the host app's approval dialog shows
session.stop()
```

The first connection asks the user to approve the app on the host. `state` is
`WaitingForApproval` until they do, and `NotApproved` if they refuse.

## What it does

`MeshCoreApiClient` is one connection: `connect()` sends `hello`, signs the pairing challenge and
returns the server's `Hello` (capabilities, limits, device). Then `request()` and the typed calls
(`deviceInfo`, `subscribe`, `sendData`, `sendText`, `joinChannel`, `resolveRegion`, `radioStats`)
match answers by id with a timeout per method (150 s for `channels.join`, 15 s otherwise).
`events` is a Flow of typed events and `device` is a StateFlow of the latest device push.
Unknown fields and event types are ignored. A client is used once; make a new one to reconnect.

`MeshApiSession` keeps a client alive for one main channel and optional extra channels:

- It loads the key from your `KeyStore`, or creates one and saves it there. The stored string is
  `{"private":"<base64 PKCS#8>","public":"<base64 X||Y>"}`.
- It subscribes after `hello` when the radio is connected. While there is no radio, it waits for
  a `device` push with `connected: true` and subscribes then. A subscription that is already in
  place is kept, because the server keeps it across radio reconnects.
- If the main channel is missing, it asks once per connection with `channels.join`, and not again
  for 10 minutes after the user says no.
- It passes `since` from the `CursorStore`. The server replays inclusively, so the frame at the
  cursor comes back each time; the session drops it and any other frame it has already
  delivered.
- It reconnects with exponential backoff (5 s to 60 s), and waits 2 minutes after the server
  refuses the app.
- `sendData` with `Route.ZeroHop` or `Route.Direct` sends a `path` only when the server lists
  `tx_path_data`. Without it nothing is sent and the result is `unsupported`, because an older
  server ignores `path` and floods. Zero-hop sends carry no region.
- A region the server refuses shows in `SessionState.Connected.unknownRegion` until a send gets
  through.

## Pairing

The client signs the challenge's `message` only when it is exactly
`meshcore-local-api-pair-v1:<nonce>` or the older `meshcore-open-pair-v1:<nonce>` for the nonce
in that challenge. It refuses anything else and closes the connection, so a program listening on
the port cannot get it to sign a string of its choosing. The key is P-256, the public key goes out
as base64 of the raw 64-byte X||Y point, and the signature is DER from `SHA256withECDSA`.

## Threading

- OkHttp delivers frames on its own thread into a bounded inbox (1024 frames). One coroutine in
  the scope you pass reads them in arrival order, so a replay keeps its order and the cursor only
  moves forward.
- `datagrams` and `events` are emitted from that reader and suspend when their 256-entry buffer
  is full. A slow collector slows the connection down, and while it is blocked, answers to
  requests wait as well. Collect on a dispatcher that keeps up, and do heavy work elsewhere.
- Give the session a background scope with a `SupervisorJob` (`Dispatchers.IO` or `Default`).
  Do not pass a Main-thread scope: the key is created and loaded on first use, which may happen
  on it.
- `start`, `stop`, `sendData` and the flows can be used from any thread. `KeyStore` and
  `CursorStore` are called from the session's scope.

## Build

```
./gradlew test
```

Gradle 8.5 needs JDK 17 or 21 to run. The output is Java 8 bytecode.
