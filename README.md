# MeshCore Local API

A MeshCore companion radio talks to one application at a time, so whichever app holds the BLE or
USB connection is the only one that can use the mesh. The MeshCore Local API is a small loopback
WebSocket protocol that lets the app owning the radio share it: other apps on the same device pair
once with a P-256 key the user approves, subscribe to the channel traffic they need and send
through the same connection, the way Reticulum apps share `rnsd`. The aim is one protocol that
every MeshCore host app can offer, so a client works whether the user runs a mobile app, a desktop
app or a daemon.

* [SPEC.md](SPEC.md): the specification, protocol 1. A small mandatory core, optional features
  announced as capabilities, security requirements for host apps, and the differences between the
  two existing servers with what each has to change.
* [vectors/](vectors/): conformance vectors (pairing keys, fingerprints, signatures, name and
  parameter validators, region resolution) and the script that generates them.

## Client libraries

* [`kotlin/`](kotlin/): Kotlin/JVM client for Android apps and JVM services.
* [`python/`](python/): Python client (`meshcore-localapi`).
* [`js/`](js/): JavaScript client for Node (`meshcore-localapi`).

## Known implementations

Servers (they own the radio):

* MeshCore Open, community fork with the Local API, proposed upstream in
  [zjs81/meshcore-open#616](https://github.com/zjs81/meshcore-open/pull/616). Android, iOS,
  macOS, Linux and Windows.
* meshcored, a headless daemon for Linux and macOS that holds a USB-attached companion radio.

Clients:

* [Roadbeacon](https://github.com/jooray/roadbeacon), road events over the mesh.
* LibreTag (Android).
* nostrmesh, a bridge between Nostr and MeshCore.
* The MeshCore-BTC bot.

Appendix A of SPEC.md lists where the servers still differ, and appendix B what each one changes
to conform.

## License

MIT, see [LICENSE](LICENSE).
