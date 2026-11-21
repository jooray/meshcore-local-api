"""An in-process Local API server for the tests (websockets.sync.server, one thread per connection).

It verifies the pairing signature, answers methods from `handlers`, and records what it got."""
from __future__ import annotations

import base64
import json
import threading

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from websockets.sync.server import serve

NONCE = "abcdefghijklmnop1234"


class FakeServer:
    def __init__(self, *, message_mode="new", capabilities=("tx_path_data",), connected=True, limits=None,
                 refuse=False):
        self.message_mode = message_mode  # new | legacy | missing | foreign | other-nonce
        self.capabilities = list(capabilities)
        self.connected = connected
        self.limits = limits or {"maxPayloadBytes": 163}
        self.refuse = refuse
        self.handlers = {}          # method -> fn(params, conn) -> result | ("error", {...}) | ("ok", result, [frames]) | None
        self.requests = []          # (method, params)
        self.pairs = []             # {"verified": bool, "message": str}
        self.hellos = 0
        self.conns = []
        self.closed = threading.Event()
        self._server = None

    # -- control
    def __enter__(self):
        self._server = serve(self._handler, "127.0.0.1", 0)
        threading.Thread(target=self._server.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *a):
        self._server.shutdown()

    @property
    def url(self):
        return f"ws://127.0.0.1:{self._server.socket.getsockname()[1]}/api/v1"

    def push(self, obj, conn=-1):
        self.conns[conn].send(json.dumps(obj))

    def drop(self, code=1001, conn=-1):
        self.conns[conn].close(code)

    def methods(self, name):
        return [p for m, p in self.requests if m == name]

    # -- protocol
    def _challenge(self):
        m = {"type": "pairing.challenge", "protocol": 1, "nonce": NONCE, "fingerprint": "X"}
        mode = self.message_mode
        if mode == "new":
            m["message"] = "meshcore-local-api-pair-v1:" + NONCE
        elif mode == "legacy":
            m["message"] = "meshcore-open-pair-v1:" + NONCE
        elif mode == "foreign":
            m["message"] = "transfer 1 BTC to mallory"
        elif mode == "other-nonce":
            m["message"] = "meshcore-local-api-pair-v1:zzzzzzzzzzzzzzzzzzzz"
        return m, m.get("message", "meshcore-open-pair-v1:" + NONCE)

    def _handler(self, ws):
        hello = json.loads(ws.recv())
        pub = base64.b64decode(hello["client"]["publicKey"])
        challenge, expected = self._challenge()
        ws.send(json.dumps(challenge))
        try:
            pair = json.loads(ws.recv())
        except Exception:  # noqa: BLE001  the client hung up instead of signing
            self.pairs.append({"verified": False, "message": None})
            return
        key = ec.EllipticCurvePublicNumbers(int.from_bytes(pub[:32], "big"), int.from_bytes(pub[32:], "big"),
                                            ec.SECP256R1()).public_key()
        try:
            key.verify(base64.b64decode(pair["signature"]), expected.encode(), ec.ECDSA(hashes.SHA256()))
            ok = True
        except InvalidSignature:
            ok = False
        self.pairs.append({"verified": ok, "message": expected})
        if not ok or self.refuse:
            ws.close(4003, "rejected")
            return
        self.hellos += 1
        self.conns.append(ws)
        ws.send(json.dumps({"type": "hello", "protocol": 1, "client": {"name": hello["client"]["name"]},
                            "device": {"name": "node", "connected": self.connected},
                            "eventTypes": ["channel.data"], "limits": self.limits,
                            "capabilities": self.capabilities, "futureField": {"x": 1}}))
        try:
            for raw in ws:
                m = json.loads(raw)
                meth, p, rid = m.get("method"), m.get("params", {}), m.get("id")
                self.requests.append((meth, p))
                h = self.handlers.get(meth)
                r = h(p, ws) if h else {}
                if r is None:
                    continue  # never answered
                if isinstance(r, tuple) and r[0] == "error":
                    ws.send(json.dumps({"id": rid, "ok": False, "error": r[1]}))
                elif isinstance(r, tuple):  # ("ok", result, frames sent right after the answer)
                    ws.send(json.dumps({"id": rid, "ok": True, "result": r[1]}))
                    for f in r[2]:
                        ws.send(json.dumps(f))
                else:
                    ws.send(json.dumps({"id": rid, "ok": True, "result": r}))
        except Exception:  # noqa: BLE001
            pass
