"""Thread-based client for the MeshCore Local API (protocol 1).

One background thread owns the WebSocket: it connects, pairs, reads, and reconnects with backoff.
Requests block the calling thread until the answer, an error, a timeout, or a disconnect. Event,
device and state callbacks run on the reader thread; keep them short, and do not call `request`
from them (start a thread for that), or the reader waits on its own answer.
"""
from __future__ import annotations

import base64
import hashlib
import itertools
import json
import logging
import random
import threading
import time
from collections import OrderedDict
from datetime import datetime
from typing import Any, Callable, Iterable, Sequence

from .errors import ConnectionClosed, LocalApiError, MissingCapability, PairingError, RequestTimeout
from .identity import Cursor, CursorStore, PairingKey

log = logging.getLogger("meshcore_localapi")

DEFAULT_URL = "ws://127.0.0.1:8787/api/v1"
LOOPBACK_PREFIXES = ("ws://127.0.0.1", "ws://localhost", "ws://[::1]")
CLOSE_REFUSED = 4003
DEFAULT_TIMEOUT = 15.0
# channels.join is answered by the user in a dialog (two minutes on the server side).
METHOD_TIMEOUTS = {"channels.join": 150.0}
# Methods that exist only with a capability (SPEC section 13).
METHOD_CAPABILITIES = {
    "contacts.list": "contacts", "direct.sendText": "contacts", "advert.send": "advert_send",
    "regions.list": "regions", "regions.resolve": "regions", "channels.join": "channels_join",
    "radio.stats": "radio_stats", "packet.sendRaw": "raw_tx",
}
# Event types and subscription filters that need a capability.
EVENT_CAPABILITIES = {"direct.text": "contacts", "advert": "contacts", "packet.raw": "raw_rx"}
FILTER_CAPABILITIES = {"since": "replay", "pubkeys": "contacts", "payloadTypes": "raw_rx"}
DEFAULT_MAX_PAYLOAD = 163
MAX_PATH_BYTES = 64
MAX_PATH_HOPS = 63

# Client states, reported through `on_state` and the `state` attribute.
DISCONNECTED = "disconnected"
CONNECTING = "connecting"
PAIRING = "pairing"          # challenge signed, waiting for the user to approve the app
READY = "ready"              # paired (`hello` received)
JOINING = "joining"          # waiting for the user to add a channel (detail: the channel name)
REFUSED = "refused"          # closed with 4003: not approved, or revoked
CLOSED = "closed"            # close() was called


def parse_time(value) -> datetime | None:
    """`receivedAt` (ISO-8601) as an aware datetime, or None."""
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def event_id(event: dict) -> str:
    """A stable id for an event: `messageId` when there is one, otherwise a hash of the fields that
    identify a frame. Used to drop the events a `since` replay repeats."""
    mid = event.get("messageId")
    if isinstance(mid, (str, int)) and not isinstance(mid, bool):
        return f"m:{mid}"
    keys = ("type", "channel", "dataType", "payload", "text", "pubkey", "senderKeyHex", "receivedAt")
    blob = json.dumps([event.get(k) for k in keys], separators=(",", ":"), sort_keys=True)
    return "h:" + hashlib.sha256(blob.encode()).hexdigest()[:24]


def event_payload(event: dict) -> bytes | None:
    """The decoded `payload` of a `channel.data` event, or None if missing or not base64."""
    p = event.get("payload")
    if not isinstance(p, str):
        return None
    try:
        return base64.b64decode(p, validate=True)
    except ValueError:
        return None


def event_path(event: dict) -> tuple[list[bytes], int] | None:
    """The received path of an event (`rx_path` extension) as (hashes first hop first, hash size),
    or None when absent or malformed. Only meaningful when the server lists `rx_path`."""
    raw, hs = event.get("path"), event.get("pathHashSize", 1)
    if not isinstance(raw, str) or hs not in (1, 2, 3):
        return None
    try:
        b = bytes.fromhex(raw)
    except ValueError:
        return None
    if len(b) % hs:
        return None
    return [b[i:i + hs] for i in range(0, len(b), hs)], hs


def _close_code(ws, exc) -> int | None:
    rcvd = getattr(exc, "rcvd", None)
    if isinstance(getattr(rcvd, "code", None), int):
        return rcvd.code
    code = getattr(ws, "close_code", None) if ws is not None else None
    return code if isinstance(code, int) else None


def required_capabilities(method: str, params: dict | None) -> list[str]:
    """The capabilities a request needs, from the method and the parameters it carries."""
    p = params or {}
    need = []
    if method in METHOD_CAPABILITIES:
        need.append(METHOD_CAPABILITIES[method])
    if method in ("channel.sendData", "channel.sendText"):
        if p.get("region") is not None:
            need.append("regions")
        if p.get("path") is not None:
            need.append("tx_path_data" if method == "channel.sendData" else "tx_path_text")
    if method == "events.subscribe":
        for k, cap in FILTER_CAPABILITIES.items():
            if p.get(k) not in (None, []):
                need.append(cap)
        for t in p.get("events") or []:
            if t in EVENT_CAPABILITIES:
                need.append(EVENT_CAPABILITIES[t])
    return list(dict.fromkeys(need))


class Subscription:
    """An `events.subscribe` the client keeps in place: made after every `hello` and again after a
    `device` push with `connected: true` while it is not active.

    `cursor_key` (with a cursor store) turns on replay: the subscription sends `since` from the
    stored cursor, drops the events the replay repeats, and moves the cursor after each delivered
    event. `join` asks the user to add the channel (`channels.join`) once per connection when the
    subscribe answers `unknown_channel` while the radio is connected.
    """

    def __init__(self, params: dict, cursor_key: str | None = None, join: bool = False):
        self.params = dict(params)
        self.cursor_key = cursor_key
        self.join = join
        self.id: str | None = None       # subscriptionId on the current connection
        self.error: LocalApiError | None = None  # why the last attempt failed
        self._seen: OrderedDict[str, None] = OrderedDict()
        self._cursor: Cursor | None = None
        self._cursor_loaded = False

    @property
    def active(self) -> bool:
        return self.id is not None

    @property
    def channel(self):
        return self.params.get("channel")

    def __repr__(self):
        return f"Subscription({self.params!r}, id={self.id!r})"


class LocalApiClient:
    """A paired connection to the Local API that reconnects by itself.

    `on_event(event, subscription)`: an event (subscription is None when its id is unknown).
    `on_hello(hello)`: after every successful pairing. `on_device(message)`: a `device` push.
    `on_state(state, detail)`: state changes (see the constants in this module).
    """

    def __init__(self, url: str = DEFAULT_URL, *, key: PairingKey, name: str, version: str = "0",
                 cursor_store: CursorStore | None = None,
                 on_event: Callable[[dict, Subscription | None], Any] | None = None,
                 on_hello: Callable[[dict], Any] | None = None,
                 on_device: Callable[[dict], Any] | None = None,
                 on_state: Callable[[str, str | None], Any] | None = None,
                 request_timeout: float = DEFAULT_TIMEOUT, method_timeouts: dict[str, float] | None = None,
                 backoff_min: float = 5.0, backoff_max: float = 60.0, jitter: float = 0.2,
                 refused_retry: float = 120.0, open_timeout: float = 10.0, pairing_timeout: float = 150.0,
                 seen_limit: int = 1000, connect=None, loopback_only: bool = True):
        if loopback_only and not url.startswith(LOOPBACK_PREFIXES):
            raise ValueError("the local API is loopback only")
        if not 1 <= len(name) <= 64:
            raise ValueError("the client name must be 1 to 64 characters")
        self.url = url
        self.key = key
        self.name = name
        self.version = version[:32]
        self.cursor_store = cursor_store
        self.on_event = on_event
        self.on_hello = on_hello
        self.on_device = on_device
        self.on_state = on_state
        self.request_timeout = request_timeout
        self.method_timeouts = {**METHOD_TIMEOUTS, **(method_timeouts or {})}
        self.backoff_min, self.backoff_max, self.jitter = backoff_min, backoff_max, jitter
        self.refused_retry = refused_retry
        self.open_timeout = open_timeout
        self.pairing_timeout = pairing_timeout
        self.seen_limit = seen_limit
        self._connect = connect

        self.hello: dict | None = None
        self.device: dict | None = None
        self.channels: list | None = None
        self.capabilities: frozenset[str] = frozenset()
        self.limits: dict = {}
        self.radio_connected = False
        self.state = DISCONNECTED
        self.state_detail: str | None = None
        self.last_activity = 0.0  # unix seconds of the last frame from the server
        self.last_close_code: int | None = None

        self._ws = None
        self._paired = threading.Event()
        self._send_lock = threading.Lock()
        self._ids = itertools.count(1)
        self._pending: dict[int, list] = {}
        self._pending_lock = threading.Lock()
        self._subs: list[Subscription] = []
        self._subs_by_id: dict[str, Subscription] = {}
        self._subs_lock = threading.Lock()
        self._sub_worker_busy = False
        self._sub_again = False
        self._joined: set[str] = set()  # channels asked for on this connection
        self._generation = 0
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    # ------------------------------------------------------------------------------------ public

    @property
    def paired(self) -> bool:
        return self._paired.is_set()

    @property
    def max_payload(self) -> int:
        v = self.limits.get("maxPayloadBytes")
        return v if isinstance(v, int) and v > 0 else DEFAULT_MAX_PAYLOAD

    def has(self, capability: str) -> bool:
        return capability in self.capabilities

    def start(self) -> "LocalApiClient":
        """Starts the connection thread (connect, pair, read, reconnect)."""
        if self._thread is None:
            self._thread = threading.Thread(target=self._run, daemon=True, name="meshcore-localapi")
            self._thread.start()
        return self

    def wait_paired(self, timeout: float | None = None) -> bool:
        return self._paired.wait(timeout)

    def close(self, wait: float = 2.0) -> None:
        self._stop.set()
        ws = self._ws
        if ws is not None:
            try:
                ws.close()
            except Exception:  # noqa: BLE001
                pass
        if self._thread is not None and self._thread is not threading.current_thread():
            self._thread.join(wait)
        if self.cursor_store is not None:
            self.cursor_store.flush()
        self._set_state(CLOSED)

    def request(self, method: str, params: dict | None = None, timeout: float | None = None) -> dict:
        """Sends a request and returns its `result` (a dict, empty if the server sent none).
        Raises LocalApiError (the server's code), RequestTimeout or ConnectionClosed."""
        return self._request(method, params, timeout)

    def subscribe(self, params: dict, *, cursor_key: str | None = None, join: bool = False) -> Subscription:
        """Registers a subscription the client keeps in place across reconnects and radio changes.
        It is made at once if the client is paired and the radio is connected."""
        if cursor_key is not None and self.cursor_store is None:
            raise ValueError("cursor_key needs a cursor_store")
        sub = Subscription(params, cursor_key, join)
        with self._subs_lock:
            self._subs.append(sub)
        if self.paired:
            self._subscribe_pending()
        return sub

    def unsubscribe(self, sub: Subscription) -> None:
        with self._subs_lock:
            if sub in self._subs:
                self._subs.remove(sub)
            sid, sub.id = sub.id, None
            if sid is not None:
                self._subs_by_id.pop(sid, None)
        if sid is not None and self.paired:
            try:
                self._request("events.unsubscribe", {"subscriptionId": sid})
            except LocalApiError as e:
                log.debug("events.unsubscribe: %s", e)

    @property
    def subscriptions(self) -> list[Subscription]:
        with self._subs_lock:
            return list(self._subs)

    def send_data(self, channel: str, data_type: int, payload: bytes, *, region: str | None = None,
                  path: bytes | Sequence[bytes] | None = None, path_hash_size: int = 1,
                  timeout: float | None = None) -> dict:
        """`channel.sendData`. Without `path` the frame floods. With `path` (next hop first; empty
        for zero-hop) it is sent along that route, which needs `tx_path_data`: an older server
        ignores `path` and floods, so without the capability this raises MissingCapability and
        sends nothing."""
        if not 1 <= len(payload) <= self.max_payload:
            raise LocalApiError("payload_too_large" if payload else "bad_request",
                                f"payload is {len(payload)} bytes; the limit is {self.max_payload}",
                                method="channel.sendData")
        params: dict = {"channel": channel, "dataType": data_type, "payload": base64.b64encode(payload).decode()}
        if region is not None:
            params["region"] = region
        if path is not None:
            if "tx_path_data" not in self.capabilities:
                raise MissingCapability("tx_path_data", "channel.sendData")
            if path_hash_size not in (1, 2, 3):
                raise LocalApiError("bad_request", "pathHashSize must be 1, 2 or 3", method="channel.sendData")
            if isinstance(path, (bytes, bytearray)):
                raw = bytes(path)
            else:
                if any(len(h) != path_hash_size for h in path):
                    raise LocalApiError("bad_request", "path entry size mismatch", method="channel.sendData")
                raw = b"".join(path)
            if len(raw) % path_hash_size or len(raw) > MAX_PATH_BYTES or len(raw) // path_hash_size > MAX_PATH_HOPS:
                raise LocalApiError("bad_request", "bad path length", method="channel.sendData")
            params["path"] = raw.hex()
            params["pathHashSize"] = path_hash_size
        return self._request("channel.sendData", params, timeout)

    def send_text(self, channel: str, text: str, *, region: str | None = None, timeout: float | None = None) -> dict:
        params = {"channel": channel, "text": text}
        if region is not None:
            params["region"] = region
        return self._request("channel.sendText", params, timeout)

    # ------------------------------------------------------------------------------------ plumbing

    def _set_state(self, state: str, detail: str | None = None):
        if (state, detail) == (self.state, self.state_detail):
            return
        self.state, self.state_detail = state, detail
        if self.on_state:
            try:
                self.on_state(state, detail)
            except Exception:  # noqa: BLE001
                log.exception("on_state callback")

    def _send_json(self, obj):
        with self._send_lock:
            ws = self._ws
            if ws is None:
                raise ConnectionClosed()
            try:
                ws.send(json.dumps(obj, separators=(",", ":")))
            except Exception as e:  # noqa: BLE001
                raise ConnectionClosed(f"send failed: {e}") from e

    def _request(self, method, params=None, timeout=None, on_answer: Callable[[dict], None] | None = None) -> dict:
        if not self.paired:
            raise ConnectionClosed("not paired", method)
        for cap in required_capabilities(method, params):
            if cap not in self.capabilities:
                raise MissingCapability(cap, method)
        if timeout is None:
            timeout = self.method_timeouts.get(method, self.request_timeout)
        rid = next(self._ids)
        # [event, answer, generation, on_answer]: on_answer runs on the reader thread before the
        # next frame is read, so the replay that follows a subscription ack finds its subscription.
        slot = [threading.Event(), None, self._generation, on_answer]
        with self._pending_lock:
            self._pending[rid] = slot
        try:
            self._send_json({"id": rid, "method": method, "params": params or {}})
            if not slot[0].wait(timeout):
                raise RequestTimeout(method, timeout)
        finally:
            with self._pending_lock:
                self._pending.pop(rid, None)
        msg = slot[1]
        if msg is None:
            raise ConnectionClosed("the connection closed while waiting", method)
        if msg.get("ok") is True:
            r = msg.get("result")
            return r if isinstance(r, dict) else {}
        raise LocalApiError.from_answer(msg.get("error"), method)

    def _fail_pending(self):
        with self._pending_lock:
            slots = list(self._pending.values())
        for slot in slots:
            slot[0].set()  # answer stays None -> ConnectionClosed

    # ------------------------------------------------------------------------------------ subscriptions

    def _subscribe_pending(self):
        with self._subs_lock:
            if self._sub_worker_busy:
                self._sub_again = True
                return
            self._sub_worker_busy = True
        threading.Thread(target=self._subscribe_worker, daemon=True, name="meshcore-localapi-sub").start()

    def _subscribe_worker(self):
        while True:
            try:
                for sub in self.subscriptions:
                    if sub.active or not self.paired or self._stop.is_set():
                        continue
                    if sub.channel is not None and not self.radio_connected:
                        continue  # answered unknown_channel until the radio is back (device push)
                    self._subscribe_one(sub)
            except Exception:  # noqa: BLE001
                log.exception("subscribe worker")
            with self._subs_lock:
                if not self._sub_again:
                    self._sub_worker_busy = False
                    return
                self._sub_again = False

    def _load_cursor(self, sub: Subscription):
        if sub.cursor_key and not sub._cursor_loaded:
            sub._cursor = self.cursor_store.get_cursor(sub.cursor_key)
            sub._cursor_loaded = True

    def _subscribe_one(self, sub: Subscription):
        self._load_cursor(sub)
        params = dict(sub.params)
        if sub._cursor is not None and "replay" in self.capabilities:
            params["since"] = sub._cursor.received_at
        gen = self._generation

        def bind(msg):
            if msg.get("ok") is True and isinstance(msg.get("result"), dict):
                sid = msg["result"].get("subscriptionId")
                if isinstance(sid, (str, int)) and gen == self._generation:
                    with self._subs_lock:
                        if sub in self._subs:
                            sub.id = str(sid)
                            self._subs_by_id[str(sid)] = sub

        try:
            self._request("events.subscribe", params, None, bind)
            sub.error = None
            log.info("subscribed %s", sub.params)
            return
        except LocalApiError as e:
            sub.error = e
            if not (e.code == "unknown_channel" and sub.join and self.radio_connected
                    and "channels_join" in self.capabilities):
                log.warning("events.subscribe %s refused: %s", sub.params, e.code)
                return
        ch = sub.channel
        if not isinstance(ch, str) or not ch.startswith("#") or ch in self._joined:
            return
        self._joined.add(ch)
        self._set_state(JOINING, ch)
        log.info("asking the user to add %s", ch)
        try:
            self._request("channels.join", {"name": ch})
        except LocalApiError as e:
            sub.error = e
            log.warning("channels.join %s: %s", ch, e.code)
            return
        finally:
            if self.state == JOINING and self.paired:
                self._set_state(READY)
        try:
            self._request("events.subscribe", params, None, bind)
            sub.error = None
        except LocalApiError as e:
            sub.error = e
            log.warning("events.subscribe %s after join: %s", sub.params, e.code)

    def _deliver(self, ev: dict, sub: Subscription | None):
        if sub is not None and sub.cursor_key is not None:
            eid = event_id(ev)
            if eid in sub._seen:
                return
            t_str = ev.get("receivedAt")
            t = parse_time(t_str)
            cur = sub._cursor
            ct = parse_time(cur.received_at) if cur else None
            if t is not None and ct is not None and (t < ct or (t == ct and eid in cur.ids)):
                return
            sub._seen[eid] = None
            if len(sub._seen) > self.seen_limit:
                sub._seen.popitem(last=False)
            self._call_event(ev, sub)
            if t is not None:
                if ct is None or t > ct:
                    sub._cursor = Cursor(t_str, [eid])
                elif t == ct:
                    cur.ids = (cur.ids + [eid])[-64:]
                self.cursor_store.set_cursor(sub.cursor_key, sub._cursor)
            return
        self._call_event(ev, sub)

    def _call_event(self, ev, sub):
        if self.on_event:
            self.on_event(ev, sub)

    # ------------------------------------------------------------------------------------ frames

    def _apply_device(self, device):
        if isinstance(device, dict):
            self.device = device
            self.radio_connected = device.get("connected", True) is not False

    def _handle(self, msg: dict):
        t = msg.get("type")
        if not self.paired:
            if t == "pairing.challenge":
                signature = self.key.sign_challenge(msg)  # raises PairingError on a foreign message
                self._set_state(PAIRING)
                log.info("approve '%s' in the host app, fingerprint %s", self.name, self.key.fingerprint)
                self._send_json({"type": "pair", "signature": signature})
            elif t == "hello":
                self._on_hello(msg)
            elif t == "error":
                raise LocalApiError.from_answer(msg.get("error"))
            return  # anything else before pairing is ignored
        if t == "event":
            ev = msg.get("event")
            if isinstance(ev, dict):
                sid = msg.get("subscriptionId")
                with self._subs_lock:
                    sub = self._subs_by_id.get(str(sid)) if sid is not None else None
                self._deliver(ev, sub)
            return
        if t == "device":
            self._apply_device(msg.get("device"))
            if isinstance(msg.get("channels"), list):
                self.channels = msg["channels"]
            if self.on_device:
                self.on_device(msg)
            if self.radio_connected and any(not s.active for s in self.subscriptions):
                self._subscribe_pending()
            return
        rid = msg.get("id")
        if t is None and isinstance(rid, int):
            with self._pending_lock:
                slot = self._pending.get(rid)
            if slot is not None and slot[2] == self._generation:
                slot[1] = msg
                if slot[3] is not None:
                    try:
                        slot[3](msg)
                    except Exception:  # noqa: BLE001
                        log.exception("answer hook")
                slot[0].set()
        # unknown types and stray answers are ignored

    def _on_hello(self, msg: dict):
        caps = msg.get("capabilities")
        self.capabilities = frozenset(c for c in caps if isinstance(c, str)) if isinstance(caps, list) else frozenset()
        self.limits = msg.get("limits") if isinstance(msg.get("limits"), dict) else {}
        self.hello = msg
        self._apply_device(msg.get("device"))
        if not isinstance(msg.get("device"), dict):
            self.radio_connected = True
        self._paired.set()
        self._set_state(READY)
        log.info("local API paired; capabilities: %s; radio %s", ", ".join(sorted(self.capabilities)) or "none",
                 "connected" if self.radio_connected else "away")
        if self.on_hello:
            self.on_hello(msg)
        if self.subscriptions:
            self._subscribe_pending()

    # ------------------------------------------------------------------------------------ loop

    def _reset_connection(self):
        self._paired.clear()
        self._ws = None
        self._generation += 1
        self._joined.clear()
        with self._subs_lock:
            for s in self._subs:
                s.id = None
            self._subs_by_id.clear()
        self._fail_pending()
        if self.cursor_store is not None:
            try:
                self.cursor_store.flush()
            except Exception:  # noqa: BLE001
                log.exception("cursor flush")

    def _session(self) -> int | None:
        """One connection. Returns the close code if known."""
        connect = self._connect
        if connect is None:
            from websockets.sync.client import connect
        ws = None
        try:
            with connect(self.url, open_timeout=self.open_timeout, compression=None,
                         max_size=1 << 20) as ws:
                self._ws = ws
                self._generation += 1
                self._send_json({"type": "hello", "client": {
                    "name": self.name, "version": self.version, "publicKey": self.key.public_key_b64}})
                deadline = time.monotonic() + self.pairing_timeout
                while not self._stop.is_set():
                    timeout = None if self.paired else max(0.0, deadline - time.monotonic())
                    try:
                        raw = ws.recv(timeout=timeout)
                    except TimeoutError:
                        raise LocalApiError("timeout", "pairing was not completed in time") from None
                    self.last_activity = time.time()
                    try:
                        msg = json.loads(raw)
                    except (ValueError, TypeError):
                        continue
                    if not isinstance(msg, dict):
                        continue
                    try:
                        self._handle(msg)
                    except (PairingError, LocalApiError):
                        raise
                    except Exception:  # noqa: BLE001  (one bad frame or callback must not drop the link)
                        log.exception("local API frame")
        except (PairingError, LocalApiError) as e:
            log.warning("local API: %s", e)
            return _close_code(ws, None)
        except Exception as e:  # noqa: BLE001
            code = _close_code(ws, e)
            if not self._stop.is_set():
                log.warning("local API: %s", e)
            return code
        return _close_code(ws, None)

    def _run(self):
        backoff = self.backoff_min
        while not self._stop.is_set():
            self._set_state(CONNECTING)
            try:
                code = self._session()
            finally:
                was_paired = self.paired
                self._reset_connection()
            self.last_close_code = code
            if self._stop.is_set():
                break
            if was_paired:
                backoff = self.backoff_min
            if code == CLOSE_REFUSED:
                self._set_state(REFUSED)
                log.warning("the host app refused or revoked this client; retrying in %g s", self.refused_retry)
                self._stop.wait(self.refused_retry)
                continue
            self._set_state(DISCONNECTED)
            delay = backoff * (1 + random.uniform(-self.jitter, self.jitter))
            self._stop.wait(delay)
            if not was_paired:
                backoff = min(backoff * 2, self.backoff_max)
