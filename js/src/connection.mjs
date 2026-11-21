import { EventEmitter } from 'node:events';
import { ApiError, ConnectionClosed, PairingError, RequestTimeout } from './errors.mjs';
import { signChallenge } from './keys.mjs';

export const DEFAULT_URL = 'ws://127.0.0.1:8787/api/v1';
export const CLOSE_REFUSED = 4003;
export const DEFAULT_TIMEOUT_MS = 15_000;
// channels.join is answered by the user in a dialog (two minutes on the server side).
export const METHOD_TIMEOUTS_MS = Object.freeze({ 'channels.join': 150_000 });
const LOOPBACK = /^ws:\/\/(127\.0\.0\.1|localhost|\[::1\])(:\d+)?(\/|$)/;

export function isLoopbackUrl(url) {
  return LOOPBACK.test(url);
}

// The global WebSocket (Node 22+), or the `ws` package on older Node.
export async function resolveWebSocket(override) {
  if (override) return override;
  if (typeof globalThis.WebSocket === 'function') return globalThis.WebSocket;
  try {
    return (await import('ws')).default;
  } catch {
    throw new Error('no WebSocket: use Node 22 or later, or install the "ws" package');
  }
}

// One connection to the Local API: the handshake, requests and pushes. No reconnect; see
// LocalApiClient for that. Emits:
//   'event'  (event, subscriptionId)  a pushed event
//   'device' (message)                the `device` push
//   'close'  ({ code, reason })       the socket is gone; nothing else is emitted after it
export class LocalApiConnection extends EventEmitter {
  constructor({ url = DEFAULT_URL, key, privateKey, publicKeyBase64, name, clientName, version, clientVersion,
    handshakeTimeoutMs = 15_000, pairTimeoutMs = 150_000, requestTimeoutMs = DEFAULT_TIMEOUT_MS,
    methodTimeoutsMs = {}, WebSocket, loopbackOnly = true, log = () => {} } = {}) {
    super();
    if (loopbackOnly && !isLoopbackUrl(url)) throw new Error(`the Local API is loopback only, got "${url}"`);
    this.url = url;
    this.privateKey = key?.privateKey ?? privateKey;
    this.publicKeyBase64 = key?.publicKeyBase64 ?? publicKeyBase64;
    if (!this.privateKey || !this.publicKeyBase64) throw new Error('a key is required');
    this.clientName = name ?? clientName ?? 'meshcore-localapi';
    this.clientVersion = String(version ?? clientVersion ?? '0').slice(0, 32);
    this.handshakeTimeoutMs = handshakeTimeoutMs;
    this.pairTimeoutMs = pairTimeoutMs;
    this.requestTimeoutMs = requestTimeoutMs;
    this.methodTimeoutsMs = { ...METHOD_TIMEOUTS_MS, ...methodTimeoutsMs };
    this.WebSocketImpl = WebSocket;
    this.log = log;
    this.ws = null;
    this.nextId = 1;
    this.pending = new Map();
    this.closed = false;
    this.hello = null;
    this.capabilities = new Set();
    this.limits = {};
    this.lastActivity = 0;
  }

  get paired() {
    return this.hello !== null && !this.closed;
  }

  // Resolves with the server's `hello` once paired. Rejects (and closes) if the socket fails, the
  // challenge is refused, or the user does not approve in time.
  async connect() {
    const WS = await resolveWebSocket(this.WebSocketImpl);
    return new Promise((resolve, reject) => {
      let settled = false;
      let timer = null;
      const fail = (err) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        reject(err);
        this.terminate();
      };
      const done = (hello) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        resolve(hello);
      };
      const armTimer = (ms, what) => {
        clearTimeout(timer);
        timer = setTimeout(() => fail(new ApiError('timeout', `${what} timed out`)), ms);
      };

      let ws;
      try {
        ws = new WS(this.url);
      } catch (e) {
        this.closed = true;
        reject(new ApiError('connect_failed', e?.message ?? String(e)));
        return;
      }
      this.ws = ws;
      armTimer(this.handshakeTimeoutMs, 'connecting');

      ws.addEventListener('open', () => {
        armTimer(this.handshakeTimeoutMs, 'the pairing challenge');
        try {
          this.#send({ type: 'hello', client: { name: this.clientName, version: this.clientVersion, publicKey: this.publicKeyBase64 } });
        } catch (e) {
          fail(e);
        }
      });
      ws.addEventListener('error', () => fail(new ApiError('connect_failed', `cannot connect to ${this.url}`)));
      ws.addEventListener('close', (ev) => {
        const info = { code: ev.code, reason: ev.reason };
        if (!settled) {
          fail(new ApiError(ev.code === CLOSE_REFUSED ? 'rejected' : 'closed',
            `closed during the handshake (${ev.code}${ev.reason ? ` ${ev.reason}` : ''})`));
        }
        this.#onClose(info);
      });
      ws.addEventListener('message', (ev) => {
        let msg;
        try {
          msg = JSON.parse(typeof ev.data === 'string' ? ev.data : Buffer.from(ev.data).toString('utf8'));
        } catch {
          return;
        }
        if (!msg || typeof msg !== 'object' || Array.isArray(msg)) return;
        this.lastActivity = Date.now();
        if (!settled) {
          switch (msg.type) {
            case 'pairing.challenge': {
              let signature;
              try {
                signature = signChallenge(this.privateKey, msg);
              } catch (e) {
                fail(e instanceof PairingError ? e : new PairingError(e?.message ?? String(e)));
                return;
              }
              this.log(`pairing challenge received; approve this app in the host app, fingerprint ${msg.fingerprint ?? ''}`.trim());
              try {
                this.#send({ type: 'pair', signature });
              } catch (e) {
                fail(e);
                return;
              }
              armTimer(this.pairTimeoutMs, 'waiting for the user to approve the pairing');
              return;
            }
            case 'hello':
              this.#onHello(msg);
              done(msg);
              return;
            case 'error':
              fail(ApiError.fromAnswer(msg.error));
              return;
            default:
              return;
          }
        }
        this.#onMessage(msg);
      });
    });
  }

  #onHello(msg) {
    this.hello = msg;
    this.capabilities = new Set(Array.isArray(msg.capabilities) ? msg.capabilities.filter(c => typeof c === 'string') : []);
    this.limits = msg.limits && typeof msg.limits === 'object' ? msg.limits : {};
  }

  #send(obj) {
    if (this.closed || this.ws?.readyState !== 1) throw new ConnectionClosed();
    this.ws.send(JSON.stringify(obj));
  }

  #onMessage(msg) {
    if (msg.type === 'event') {
      if (msg.event && typeof msg.event === 'object') this.emit('event', msg.event, msg.subscriptionId);
    } else if (msg.type === 'device') {
      this.emit('device', msg);
    } else if (msg.type === undefined && msg.id !== undefined && this.pending.has(msg.id)) {
      const p = this.pending.get(msg.id);
      this.pending.delete(msg.id);
      clearTimeout(p.timer);
      // runs before the next frame is handled, so the replay after a subscription ack finds it
      try { p.onAnswer?.(msg); } catch { /* the hook must not break the dispatch */ }
      if (msg.ok === true) p.resolve(msg.result && typeof msg.result === 'object' ? msg.result : {});
      else p.reject(ApiError.fromAnswer(msg.error, p.method));
    }
    // Anything else (unknown types, stray answers) is ignored, as the protocol asks of clients.
  }

  #onClose(info) {
    if (this.closed) return;
    this.closed = true;
    for (const p of this.pending.values()) {
      clearTimeout(p.timer);
      p.reject(new ConnectionClosed(`the connection closed (${info.code})`, p.method));
    }
    this.pending.clear();
    this.emit('close', info);
  }

  // Every request has its own timeout: a server that stops answering must not park the caller.
  // `onAnswer(message)` is called synchronously with the raw answer before the promise settles.
  request(method, params = {}, timeoutMs, { onAnswer } = {}) {
    const ms = timeoutMs ?? this.methodTimeoutsMs[method] ?? this.requestTimeoutMs;
    return new Promise((resolve, reject) => {
      if (!this.paired) {
        reject(new ConnectionClosed('not paired', method));
        return;
      }
      const id = this.nextId++;
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new RequestTimeout(method, ms));
      }, ms);
      this.pending.set(id, { resolve, reject, timer, method, onAnswer });
      try {
        this.#send({ id, method, params: params ?? {} });
      } catch (e) {
        this.pending.delete(id);
        clearTimeout(timer);
        reject(e);
      }
    });
  }

  // Drops the socket without waiting for a close handshake (a dead peer never answers it).
  terminate() {
    try {
      this.ws?.close();
    } catch { /* already gone */ }
    // `close` may never come for a half-open socket; report it ourselves.
    setTimeout(() => this.#onClose({ code: 1006, reason: 'terminated' }), 1000).unref?.();
  }

  close() {
    this.terminate();
  }
}
