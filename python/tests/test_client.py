import base64
import json
import os
import stat
import threading
import time

import pytest

from fake_server import NONCE, FakeServer
from meshcore_localapi import (READY, required_capabilities, REFUSED, ConnectionClosed, Cursor, JsonFileStore, LocalApiClient,
                               LocalApiError, MemoryStore, MissingCapability, PairingError, PairingKey,
                               RequestTimeout, event_path, load_or_create_key, pairing_message)


def until(fn, timeout=5.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        v = fn()
        if v:
            return v
        time.sleep(0.01)
    raise AssertionError("timed out")


@pytest.fixture
def key():
    return PairingKey.generate()


def client(srv, key, **kw):
    kw.setdefault("backoff_min", 0.05)
    kw.setdefault("backoff_max", 0.2)
    kw.setdefault("refused_retry", 0.1)
    return LocalApiClient(srv.url, key=key, name="test", version="1", **kw)


def ev(received_at, payload=b"x", **kw):
    return {"type": "channel.data", "channel": "#test", "dataType": 0xFF00,
            "payload": base64.b64encode(payload).decode(), "receivedAt": received_at, "outgoing": False, **kw}


# ------------------------------------------------------------------------------------ pairing

@pytest.mark.parametrize("mode", ["new"])
def test_handshake_signs_the_pairing_string(mode, key):
    with FakeServer(message_mode=mode, capabilities=["tx_path_data", "rx_meta"],
                    limits={"maxPayloadBytes": 150}) as srv:
        c = client(srv, key).start()
        assert c.wait_paired(5)
        assert srv.pairs[0]["verified"]
        assert c.state == READY and c.capabilities == {"tx_path_data", "rx_meta"}
        assert c.max_payload == 150 and c.radio_connected and c.device["name"] == "node"
        c.close()


@pytest.mark.parametrize("mode", ["legacy", "missing", "foreign", "other-nonce", "padded"])
def test_foreign_challenge_message_is_refused(mode, key):
    with FakeServer(message_mode=mode) as srv:
        c = client(srv, key).start()
        until(lambda: srv.pairs)
        assert srv.pairs[0] == {"verified": False, "message": None}  # never signed, hung up
        assert not c.paired
        c.close()


def test_pairing_message_checks():
    assert pairing_message({"nonce": NONCE, "message": "meshcore-local-api-pair-v1:" + NONCE}).endswith(NONCE)
    for bad in ({"nonce": "short"}, {"nonce": NONCE}, {"nonce": NONCE, "message": "meshcore-open-pair-v1:" + NONCE},
                {"nonce": NONCE, "message": "meshcore-local-api-pair-v1:" + NONCE + "x"},
                {"nonce": NONCE, "message": 5}, {"nonce": NONCE + ":x"}):
        with pytest.raises(PairingError):
            pairing_message(bad)


def test_refused_4003(key):
    states = []
    with FakeServer(refuse=True) as srv:
        c = client(srv, key, on_state=lambda s, d: states.append(s)).start()
        until(lambda: REFUSED in states)
        assert c.last_close_code == 4003
        c.close()


def test_loopback_only(key):
    with pytest.raises(ValueError):
        LocalApiClient("ws://192.0.2.1:8787/api/v1", key=key, name="x")


# ------------------------------------------------------------------------------------ requests

def test_request_response_and_errors(key):
    with FakeServer() as srv:
        srv.handlers["device.info"] = lambda p, ws: {"connected": True, "name": "node"}
        srv.handlers["channel.sendText"] = lambda p, ws: ("error", {"code": "radio_error", "message": "no ack",
                                                                     "maybeSent": True, "extra": 1})
        srv.handlers["channels.list"] = lambda p, ws: ("error", {"code": "not_connected"})
        srv.handlers["contacts.list"] = lambda p, ws: None  # never answered
        c = client(srv, key).start()
        assert c.wait_paired(5)
        assert c.request("device.info") == {"connected": True, "name": "node"}
        with pytest.raises(LocalApiError) as e:
            c.send_text("#test", "hi")
        assert (e.value.code, e.value.maybe_sent, e.value.method) == ("radio_error", True, "channel.sendText")
        with pytest.raises(LocalApiError) as e:
            c.request("channels.list")
        assert e.value.code == "not_connected" and not e.value.maybe_sent
        with pytest.raises(RequestTimeout) as e:
            c.request("contacts.list", timeout=0.2)
        assert e.value.code == "timeout"
        c.close()


def test_per_method_timeout_and_close_fails_pending(key):
    with FakeServer() as srv:
        srv.handlers["channels.join"] = lambda p, ws: None
        c = client(srv, key).start()
        assert c.wait_paired(5)
        assert c.method_timeouts["channels.join"] == 150
        box = {}

        def call():
            t = time.monotonic()
            try:
                c.request("channels.join", {"name": "#x"})
            except LocalApiError as e:
                box["e"], box["t"] = e, time.monotonic() - t

        th = threading.Thread(target=call)
        th.start()
        until(lambda: srv.methods("channels.join"))
        time.sleep(0.3)
        assert "e" not in box  # still waiting (15 s default would not matter here, 150 s does)
        srv.drop()
        th.join(5)
        assert isinstance(box["e"], ConnectionClosed) and box["t"] < 5
        c.close()


def test_not_connected_before_pairing(key):
    c = LocalApiClient("ws://127.0.0.1:1/api/v1", key=key, name="x")
    with pytest.raises(ConnectionClosed):
        c.request("device.info")


def test_unknown_frames_ignored(key):
    got = []
    with FakeServer() as srv:
        srv.handlers["device.info"] = lambda p, ws: {"ok": 1}
        c = client(srv, key, on_event=lambda e, s: got.append(e)).start()
        assert c.wait_paired(5)
        srv.push({"type": "future.thing", "x": 1})
        srv.push({"id": 999, "ok": True, "result": {}})
        srv.push({"type": "event", "event": {"type": "future.event", "foo": 1}})
        assert c.request("device.info") == {"ok": 1}
        until(lambda: got)
        assert got == [{"type": "future.event", "foo": 1}]
        c.close()


# ------------------------------------------------------------------------------------ subscriptions

def test_device_push_resubscribes(key):
    with FakeServer(connected=False) as srv:
        srv.handlers["events.subscribe"] = lambda p, ws: {"subscriptionId": "s1"}
        c = client(srv, key).start()
        assert c.wait_paired(5)
        sub = c.subscribe({"events": ["channel.data"], "channel": "#test"})
        time.sleep(0.2)
        assert srv.methods("events.subscribe") == [] and not sub.active  # radio away: not tried
        srv.push({"type": "device", "device": {"connected": True}, "channels": [{"index": 0, "name": "#test"}]})
        until(lambda: sub.active)
        assert c.radio_connected and c.channels == [{"index": 0, "name": "#test"}]
        assert len(srv.methods("events.subscribe")) == 1
        srv.push({"type": "device", "device": {"connected": True}, "channels": []})
        time.sleep(0.2)
        assert len(srv.methods("events.subscribe")) == 1  # active: not repeated
        c.close()


def test_failed_subscribe_waits_for_device_push(key):
    with FakeServer() as srv:
        known = set()
        srv.handlers["events.subscribe"] = lambda p, ws: {"subscriptionId": "s1"} if p["channel"] in known \
            else ("error", {"code": "unknown_channel"})
        c = client(srv, key).start()
        assert c.wait_paired(5)
        sub = c.subscribe({"channel": "#test"})
        until(lambda: sub.error is not None)
        assert sub.error.code == "unknown_channel" and not srv.methods("channels.join")  # join not asked for
        known.add("#test")
        srv.push({"type": "device", "device": {"connected": True}, "channels": [{"name": "#test"}]})
        until(lambda: sub.active)
        c.close()


def test_unknown_channel_joins_once(key):
    with FakeServer() as srv:
        known = set()

        def join(p, ws):
            known.add(p["name"])
            return {"index": 3, "name": p["name"], "created": True}

        srv.handlers["events.subscribe"] = lambda p, ws: {"subscriptionId": "s1"} if p["channel"] in known \
            else ("error", {"code": "unknown_channel"})
        srv.handlers["channels.join"] = join
        c = client(srv, key).start()
        assert c.wait_paired(5)
        sub = c.subscribe({"channel": "#test"}, join=True)
        until(lambda: sub.active)
        assert srv.methods("channels.join") == [{"name": "#test"}] and len(srv.methods("events.subscribe")) == 2
        c.close()


def test_since_replay_dedupe_and_cursor(key, tmp_path):
    t0, t1, t2 = "2026-11-13T10:00:00.000Z", "2026-11-13T10:00:05.000Z", "2026-11-13T10:00:09Z"
    archive = [ev(t0, b"a"), ev(t1, b"b"), ev(t1, b"c")]

    def subscribe(p, ws):
        frames = [{"type": "event", "subscriptionId": "s7", "event": e} for e in archive]
        return ("ok", {"subscriptionId": "s7"}, frames)

    store = JsonFileStore(tmp_path / "state.json", save_interval=0)
    store.set_cursor("test", Cursor(t0, []))
    first = PairingKey.generate()
    store.save_key(first.to_der())
    got = []
    with FakeServer() as srv:
        srv.handlers["events.subscribe"] = subscribe
        c = client(srv, load_or_create_key(store), cursor_store=store,
                   on_event=lambda e, s: got.append(base64.b64decode(e["payload"]))).start()
        sub = c.subscribe({"events": ["channel.data"], "channel": "#test"}, cursor_key="test")
        until(lambda: len(got) >= 3)
        assert srv.methods("events.subscribe")[0]["since"] == t0
        assert got == [b"a", b"b", b"c"]  # cursor had no ids: the t0 frame is new to it
        assert sub.id == "s7"
        # reconnect: the server replays from t1, inclusive; both t1 frames were seen
        srv.drop()
        until(lambda: srv.hellos == 2 and len(srv.methods("events.subscribe")) == 2)
        assert srv.methods("events.subscribe")[1]["since"] == t1
        srv.push({"type": "event", "subscriptionId": "s7", "event": ev(t2, b"d")})
        until(lambda: len(got) == 4)
        assert got[-1] == b"d"
        c.close()
    # a new process: the stored cursor is t2 with its id, so the same replay delivers nothing
    stored = json.loads((tmp_path / "state.json").read_text())
    assert stored["cursor"]["test"]["receivedAt"] == t2 and len(stored["cursor"]["test"]["ids"]) == 1
    assert stat.S_IMODE(os.stat(tmp_path / "state.json").st_mode) == 0o600
    assert load_or_create_key(JsonFileStore(tmp_path / "state.json")).public_raw == first.public_raw
    archive.append(ev(t2, b"d"))
    got2 = []
    with FakeServer() as srv:
        srv.handlers["events.subscribe"] = subscribe
        store2 = JsonFileStore(tmp_path / "state.json")
        c = client(srv, key, cursor_store=store2, on_event=lambda e, s: got2.append(e)).start()
        c.subscribe({"channel": "#test"}, cursor_key="test")
        until(lambda: srv.methods("events.subscribe"))
        time.sleep(0.3)
        assert got2 == []
        c.close()


# ------------------------------------------------------------------------------------ send

def test_path_only_with_capability(key):
    for caps in (["regions"], ["regions", "tx_path_data"]):
        with FakeServer(capabilities=caps) as srv:
            srv.handlers["channel.sendData"] = lambda p, ws: {"queued": True}
            c = client(srv, key).start()
            assert c.wait_paired(5)
            assert c.send_data("#test", 0xFF00, b"hi", region="sk") == {"queued": True}
            sent = srv.methods("channel.sendData")[-1]
            assert "path" not in sent and "pathHashSize" not in sent and sent["region"] == "sk"
            if "tx_path_data" not in caps:
                with pytest.raises(MissingCapability) as e:
                    c.send_data("#test", 0xFF00, b"hi", path=[])
                assert e.value.code == "unsupported" and len(srv.methods("channel.sendData")) == 1
            else:
                c.send_data("#test", 0xFF00, b"hi", path=[])
                assert srv.methods("channel.sendData")[-1]["path"] == ""  # zero-hop
                c.send_data("#test", 0xFF00, b"hi", path=[b"\xc3\xd4", b"\xa1\xb2"], path_hash_size=2)
                sent = srv.methods("channel.sendData")[-1]
                assert (sent["path"], sent["pathHashSize"]) == ("c3d4a1b2", 2)
                with pytest.raises(LocalApiError):
                    c.send_data("#test", 0xFF00, b"hi", path=[b"\x01"], path_hash_size=2)
            with pytest.raises(LocalApiError) as e:
                c.send_data("#test", 0xFF00, b"x" * 164)
            assert e.value.code == "payload_too_large"
            c.close()


def test_event_path():
    assert event_path({"path": "a1b2c3d4", "pathHashSize": 2}) == ([b"\xa1\xb2", b"\xc3\xd4"], 2)
    assert event_path({"path": "a1b"}) is None and event_path({}) is None


# ------------------------------------------------------------------------------------ reconnect

def test_reconnect_and_resubscribe(key):
    hellos = []
    with FakeServer() as srv:
        srv.handlers["events.subscribe"] = lambda p, ws: {"subscriptionId": "s1"}
        c = client(srv, key, on_hello=hellos.append).start()
        sub = c.subscribe({"events": ["channel.text"]})
        until(lambda: sub.active)
        srv.drop(1001)
        until(lambda: len(hellos) == 2 and sub.active)
        assert len(srv.methods("events.subscribe")) == 2 and c.paired
        c.close()


def test_reconnects_when_the_server_is_not_there_yet(key):
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    c = LocalApiClient(f"ws://127.0.0.1:{port}/api/v1", key=key, name="t", backoff_min=0.05, backoff_max=0.1)
    c.start()
    time.sleep(0.3)
    assert not c.paired
    c.close()


def test_file_store_creates_key_with_0600(tmp_path):
    p = tmp_path / "sub" / "key.json"
    k = load_or_create_key(JsonFileStore(p))
    assert stat.S_IMODE(os.stat(p).st_mode) == 0o600
    assert len(k.public_raw) == 64 and len(base64.b64decode(k.public_key_b64)) == 64
    assert len(k.fingerprint) == 19
    assert load_or_create_key(MemoryStore(k.to_der())).public_raw == k.public_raw


# ------------------------------------------------------------------------------------ capability gating

def test_required_capabilities():
    assert required_capabilities("device.info", {}) == []
    assert required_capabilities("channel.sendData", {"region": "x", "path": ""}) == ["regions", "tx_path_data"]
    assert required_capabilities("channel.sendText", {"path": "a1"}) == ["tx_path_text"]
    assert required_capabilities("channel.sendData", {"region": None, "path": None}) == []
    assert required_capabilities("events.subscribe", {"since": "t", "pubkeys": [], "events": ["advert", "packet.raw"]}) \
        == ["replay", "contacts", "raw_rx"]
    for m, cap in (("contacts.list", "contacts"), ("direct.sendText", "contacts"), ("advert.send", "advert_send"),
                   ("regions.list", "regions"), ("regions.resolve", "regions"), ("channels.join", "channels_join"),
                   ("radio.stats", "radio_stats"), ("packet.sendRaw", "raw_tx")):
        assert required_capabilities(m, {}) == [cap]


def test_features_without_capability_send_nothing(key):
    with FakeServer(capabilities=[]) as srv:
        srv.handlers["channel.sendData"] = lambda p, ws: {"queued": True}
        c = client(srv, key).start()
        assert c.wait_paired(5)
        calls = [lambda: c.send_data("#test", 1, b"x", region="sk"),
                 lambda: c.send_text("#test", "hi", region="sk"),
                 lambda: c.request("channel.sendText", {"channel": "#test", "text": "hi", "path": ""})]
        calls += [lambda m=m: c.request(m, {}) for m in ("contacts.list", "direct.sendText", "advert.send",
                                                         "regions.list", "regions.resolve", "channels.join",
                                                         "radio.stats", "packet.sendRaw")]
        calls += [lambda: c.request("events.subscribe", {"since": "2026-11-13T10:00:00Z"}),
                  lambda: c.request("events.subscribe", {"events": ["direct.text"]})]
        for call in calls:
            with pytest.raises(MissingCapability):
                call()
        assert srv.requests == []
        c.send_data("#test", 1, b"x")
        assert [m for m, _ in srv.requests] == ["channel.sendData"]
        c.close()


def test_subscribe_without_replay_or_join(key):
    with FakeServer(capabilities=[]) as srv:
        srv.handlers["events.subscribe"] = lambda p, ws: ("error", {"code": "unknown_channel"}) \
            if p.get("channel") == "#new" else {"subscriptionId": "s1"}
        store = MemoryStore()
        store.set_cursor("k", Cursor("2026-11-13T10:00:00Z", []))
        c = client(srv, key, cursor_store=store).start()
        assert c.wait_paired(5)
        sub = c.subscribe({"channel": "#test"}, cursor_key="k")
        until(lambda: sub.active)
        assert "since" not in srv.methods("events.subscribe")[0]  # no replay: since omitted
        missing = c.subscribe({"channel": "#new"}, join=True)
        until(lambda: missing.error is not None)
        time.sleep(0.2)
        assert missing.error.code == "unknown_channel" and srv.methods("channels.join") == []  # no channels_join
        contacts = c.subscribe({"pubkeys": ["ab" * 32]})
        until(lambda: contacts.error is not None)
        assert isinstance(contacts.error, MissingCapability) and contacts.error.capability == "contacts"
        assert not any("pubkeys" in p for p in srv.methods("events.subscribe"))  # never sent
        c.close()
