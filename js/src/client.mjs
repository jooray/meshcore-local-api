import { createHash } from 'node:crypto';
import { EventEmitter } from 'node:events';
import { ApiError, ConnectionClosed, MissingCapability } from './errors.mjs';
import { CLOSE_REFUSED, DEFAULT_URL, LocalApiConnection, isLoopbackUrl } from './connection.mjs';

export const DEFAULT_MAX_PAYLOAD = 163;
const MAX_PATH_BYTES = 64;
const MAX_PATH_HOPS = 63;

// Client states, reported through the 'state' event and the `state` property.
export const State = Object.freeze({
  DISCONNECTED: 'disconnected',
  CONNECTING: 'connecting',
  READY: 'ready',       // paired (`hello` received)
  JOINING: 'joining',   // waiting for the user to add a channel (detail: the channel name)
  REFUSED: 'refused',   // closed with 4003 or `rejected`: not approved, or revoked
  STOPPED: 'stopped',
});

const sleep = (ms) => new Promise(r => setTimeout(r, ms));

// A stable id for an event: `messageId` when there is one, otherwise a hash of the fields that
// identify a frame. Used to drop the events a `since` replay repeats.
export function eventId(ev) {
  const mid = ev?.messageId;
  if (typeof mid === 'string' || (typeof mid === 'number' && Number.isFinite(mid))) return `m:${mid}`;
  const keys = ['type', 'channel', 'dataType', 'payload', 'text', 'pubkey', 'senderKeyHex', 'receivedAt'];
  const blob = JSON.stringify(keys.map(k => ev?.[k] ?? null));
  return `h:${createHash('sha256').update(blob).digest('hex').slice(0, 24)}`;
}

// The decoded payload of a `channel.data` event, or null.
export function eventPayload(ev) {
  if (typeof ev?.payload !== 'string' || !/^[A-Za-z0-9+/]*={0,2}$/.test(ev.payload)) return null;
  return Buffer.from(ev.payload, 'base64');
}

// The received path (`rx_path` extension) as { hops: Buffer[], hashSize }, or null.
export function eventPath(ev) {
  const hs = ev?.pathHashSize ?? 1;
  if (typeof ev?.path !== 'string' || ![1, 2, 3].includes(hs) || !/^([0-9a-fA-F]{2})*$/.test(ev.path)) return null;
  const raw = Buffer.from(ev.path, 'hex');
  if (raw.length % hs) return null;
  const hops = [];
  for (let i = 0; i < raw.length; i += hs) hops.push(raw.subarray(i, i + hs));
  return { hops, hashSize: hs };
}

function timeOf(s) {
  if (typeof s !== 'string') return null;
  const t = Date.parse(s);
  return Number.isNaN(t) ? null : t;
}

// An `events.subscribe` the client keeps in place: made after every `hello` and again after a
// `device` push with `connected: true` while it is not active. See LocalApiClient.subscribe.
export class Subscription {
  constructor(params, { cursorKey = null, join = false } = {}) {
    this.params = { ...params };
    this.cursorKey = cursorKey;
    this.join = join;
    this.id = null;      // subscriptionId on the current connection
    this.error = null;   // why the last attempt failed
    this.seen = new Set();
    this.cursor = null;
    this.cursorLoaded = false;
  }

  get active() { return this.id !== null; }
  get channel() { return this.params.channel; }
}

// A paired connection to the Local API that reconnects by itself. Emits:
//   'hello'  (hello)                 after every successful pairing
//   'event'  (event, subscription)   an event (subscription is null when its id is unknown)
//   'device' (message)               a `device` push
//   'state'  (state, detail)         see State
//   'disconnect' ({ code, reason })  a connection ended
export class LocalApiClient extends EventEmitter {
  constructor({ url = DEFAULT_URL, key, name, version = '0', cursorStore = null,
    backoffMinMs = 1000, backoffMaxMs = 30_000, jitter = 0.2, refusedRetryMs = 120_000,
    heartbeatMs = 0, heartbeatTimeoutMs = 10_000, seenLimit = 1000, loopbackOnly = true,
    log = () => {}, ...connectionOptions } = {}) {
    super();
    if (loopbackOnly && !isLoopbackUrl(url)) throw new Error(`the Local API is loopback only, got "${url}"`);
    if (!key?.privateKey) throw new Error('a key is required (loadOrCreateKey)');
    if (typeof name !== 'string' || name.length < 1 || name.length > 64) throw new Error('the client name must be 1 to 64 characters');
    Object.assign(this, { url, key, name, version, cursorStore, backoffMinMs, backoffMaxMs, jitter, refusedRetryMs,
      heartbeatMs, heartbeatTimeoutMs, seenLimit, loopbackOnly, log });
    this.connectionOptions = connectionOptions;
    this.connection = null;
    this.hello = null;
    this.device = null;
    this.channels = null;
    this.capabilities = new Set();
    this.limits = {};
    this.radioConnected = false;
    this.state = State.DISCONNECTED;
    this.stateDetail = null;
    this.lastClose = null;
    this.subs = [];
    this.subsById = new Map();
    this.joined = new Set();
    this.stopped = false;
    this.loopDone = null;
    this.wake = null;
    this.subWorker = null;
    this.subAgain = false;
  }

  get paired() { return this.connection?.paired === true; }

  get maxPayload() {
    const v = this.limits?.maxPayloadBytes;
    return Number.isInteger(v) && v > 0 ? v : DEFAULT_MAX_PAYLOAD;
  }

  has(capability) { return this.capabilities.has(capability); }

  get subscriptions() { return [...this.subs]; }

  start() {
    if (!this.loopDone) this.loopDone = this.#loop().catch(e => this.log(`connection loop died: ${e?.message ?? e}`));
    return this;
  }

  async stop() {
    this.stopped = true;
    this.wake?.();
    this.connection?.close();
    await Promise.race([this.loopDone, sleep(2000)]);
    this.cursorStore?.flush?.();
    this.#setState(State.STOPPED);
  }

  // Resolves true once paired, false after timeoutMs.
  waitPaired(timeoutMs = 10_000) {
    if (this.paired) return Promise.resolve(true);
    return new Promise((resolve) => {
      const t = setTimeout(() => { this.off('hello', h); resolve(false); }, timeoutMs);
      const h = () => { clearTimeout(t); resolve(true); };
      this.once('hello', h);
    });
  }

  // Sends a request on the current connection; resolves with its `result`.
  request(method, params = {}, timeoutMs) {
    if (!this.paired) return Promise.reject(new ConnectionClosed('not paired', method));
    return this.connection.request(method, params, timeoutMs);
  }

  // Registers a subscription the client keeps in place across reconnects and radio changes.
  // `cursorKey` (needs a cursorStore) turns on replay: `since` from the stored cursor, the events
  // the replay repeats are dropped, and the cursor moves after each delivered event. `join` asks
  // the user to add the channel (`channels.join`) once per connection when the subscribe answers
  // `unknown_channel` while the radio is connected.
  subscribe(params, { cursorKey = null, join = false } = {}) {
    if (cursorKey !== null && !this.cursorStore) throw new Error('cursorKey needs a cursorStore');
    const sub = new Subscription(params, { cursorKey, join });
    this.subs.push(sub);
    if (this.paired) this.#subscribePending();
    return sub;
  }

  async unsubscribe(sub) {
    this.subs = this.subs.filter(s => s !== sub);
    const sid = sub.id;
    sub.id = null;
    if (sid !== null) {
      this.subsById.delete(sid);
      if (this.paired) {
        try { await this.request('events.unsubscribe', { subscriptionId: sid }); } catch { /* gone anyway */ }
      }
    }
  }

  // `channel.sendData`. Without `path` the frame floods. With `path` (Buffer of concatenated hop
  // hashes or an array of hashes, next hop first; empty for zero-hop) it goes along that route,
  // which needs `tx_path_data`: an older server ignores `path` and floods, so without the
  // capability this rejects with MissingCapability and sends nothing.
  async sendData(channel, dataType, payload, { region, path, pathHashSize = 1, timeoutMs } = {}) {
    const method = 'channel.sendData';
    const bytes = Buffer.from(payload);
    if (bytes.length < 1 || bytes.length > this.maxPayload) {
      throw new ApiError(bytes.length ? 'payload_too_large' : 'bad_request',
        `payload is ${bytes.length} bytes; the limit is ${this.maxPayload}`, { method });
    }
    const params = { channel, dataType, payload: bytes.toString('base64') };
    if (region !== undefined && region !== null) params.region = region;
    if (path !== undefined && path !== null) {
      if (!this.capabilities.has('tx_path_data')) throw new MissingCapability('tx_path_data', method);
      if (![1, 2, 3].includes(pathHashSize)) throw new ApiError('bad_request', 'pathHashSize must be 1, 2 or 3', { method });
      let raw;
      if (Array.isArray(path)) {
        if (path.some(h => Buffer.from(h).length !== pathHashSize)) throw new ApiError('bad_request', 'path entry size mismatch', { method });
        raw = Buffer.concat(path.map(h => Buffer.from(h)));
      } else {
        raw = Buffer.from(path);
      }
      if (raw.length % pathHashSize || raw.length > MAX_PATH_BYTES || raw.length / pathHashSize > MAX_PATH_HOPS) {
        throw new ApiError('bad_request', 'bad path length', { method });
      }
      params.path = raw.toString('hex');
      params.pathHashSize = pathHashSize;
    }
    return this.request(method, params, timeoutMs);
  }

  sendText(channel, text, { region, timeoutMs } = {}) {
    const params = { channel, text };
    if (region !== undefined && region !== null) params.region = region;
    return this.request('channel.sendText', params, timeoutMs);
  }

  // ---------------------------------------------------------------------------------- internals

  #setState(state, detail = null) {
    if (state === this.state && detail === this.stateDetail) return;
    this.state = state;
    this.stateDetail = detail;
    this.emit('state', state, detail);
  }

  #applyDevice(device) {
    if (device && typeof device === 'object') {
      this.device = device;
      this.radioConnected = device.connected !== false;
    }
  }

  #subscribePending() {
    if (this.subWorker) {
      this.subAgain = true;
      return;
    }
    this.subWorker = (async () => {
      do {
        this.subAgain = false;
        for (const sub of [...this.subs]) {
          if (sub.active || !this.paired || this.stopped) continue;
          if (sub.channel !== undefined && !this.radioConnected) continue; // retried on a device push
          try {
            await this.#subscribeOne(sub, this.connection);
          } catch (e) {
            this.log(`subscribe failed: ${e?.message ?? e}`);
          }
        }
      } while (this.subAgain);
    })().finally(() => {
      this.subWorker = null;
      if (this.subAgain) this.#subscribePending();
    });
  }

  async #subscribeOne(sub, conn) {
    if (sub.cursorKey && !sub.cursorLoaded) {
      sub.cursor = await this.cursorStore.get(sub.cursorKey);
      sub.cursorLoaded = true;
    }
    const params = { ...sub.params };
    if (sub.cursor) params.since = sub.cursor.receivedAt;
    const onAnswer = (msg) => {
      const sid = msg?.ok === true ? msg.result?.subscriptionId : undefined;
      if ((typeof sid === 'string' || typeof sid === 'number') && conn === this.connection && this.subs.includes(sub)) {
        sub.id = String(sid);
        this.subsById.set(sub.id, sub);
      }
    };
    try {
      await conn.request('events.subscribe', params, undefined, { onAnswer });
      sub.error = null;
      return;
    } catch (e) {
      sub.error = e;
      if (!(e.code === 'unknown_channel' && sub.join && this.radioConnected)) {
        this.log(`events.subscribe ${JSON.stringify(sub.params)} refused: ${e.code}`);
        return;
      }
    }
    const ch = sub.channel;
    if (typeof ch !== 'string' || !ch.startsWith('#') || this.joined.has(ch)) return;
    this.joined.add(ch);
    this.#setState(State.JOINING, ch);
    try {
      await conn.request('channels.join', { name: ch });
    } catch (e) {
      sub.error = e;
      this.log(`channels.join ${ch}: ${e.code}`);
      return;
    } finally {
      if (this.state === State.JOINING && this.paired) this.#setState(State.READY);
    }
    try {
      await conn.request('events.subscribe', params, undefined, { onAnswer });
      sub.error = null;
    } catch (e) {
      sub.error = e;
    }
  }

  #onEvent(ev, subscriptionId) {
    const sub = subscriptionId !== undefined && subscriptionId !== null ? this.subsById.get(String(subscriptionId)) ?? null : null;
    if (!sub || !sub.cursorKey) {
      this.emit('event', ev, sub);
      return;
    }
    const id = eventId(ev);
    if (sub.seen.has(id)) return;
    const t = timeOf(ev.receivedAt);
    const ct = sub.cursor ? timeOf(sub.cursor.receivedAt) : null;
    if (t !== null && ct !== null && (t < ct || (t === ct && sub.cursor.ids.includes(id)))) return;
    sub.seen.add(id);
    if (sub.seen.size > this.seenLimit) sub.seen.delete(sub.seen.values().next().value);
    try {
      this.emit('event', ev, sub);
    } finally {
      if (t !== null) {
        if (ct === null || t > ct) sub.cursor = { receivedAt: ev.receivedAt, ids: [id] };
        else if (t === ct) sub.cursor.ids = [...sub.cursor.ids, id].slice(-64);
        try {
          this.cursorStore.set(sub.cursorKey, sub.cursor);
        } catch (e) {
          this.log(`cannot save the cursor: ${e?.message ?? e}`);
        }
      }
    }
  }

  #reset() {
    this.joined.clear();
    for (const s of this.subs) s.id = null;
    this.subsById.clear();
    try { this.cursorStore?.flush?.(); } catch (e) { this.log(`cannot save the cursor: ${e?.message ?? e}`); }
  }

  // One connection. Resolves with { paired, code, reason }.
  async #session() {
    const c = new LocalApiConnection({ ...this.connectionOptions, url: this.url, key: this.key, name: this.name,
      version: this.version, loopbackOnly: this.loopbackOnly, log: this.log });
    this.connection = c;
    const closed = new Promise(resolve => c.once('close', resolve));
    let hello;
    try {
      hello = await c.connect();
    } catch (e) {
      this.log(`Local API connection failed: ${e?.code ? `${e.code}: ` : ''}${e?.message ?? e}`);
      const info = await Promise.race([closed, sleep(1500).then(() => ({ code: 1006, reason: '' }))]);
      return { paired: false, code: e?.code === 'rejected' ? CLOSE_REFUSED : info.code, reason: info.reason };
    }
    if (this.stopped) {
      c.close();
      return { paired: true, ...(await closed) };
    }
    this.hello = hello;
    this.capabilities = c.capabilities;
    this.limits = c.limits;
    this.radioConnected = true;
    this.#applyDevice(hello.device);
    c.on('event', (ev, sid) => {
      try { this.#onEvent(ev, sid); } catch (e) { this.log(`event handler threw: ${e?.message ?? e}`); }
    });
    c.on('device', (m) => {
      this.#applyDevice(m.device);
      if (Array.isArray(m.channels)) this.channels = m.channels;
      try { this.emit('device', m); } catch (e) { this.log(`device handler threw: ${e?.message ?? e}`); }
      if (this.radioConnected && this.subs.some(s => !s.active)) this.#subscribePending();
    });
    this.#setState(State.READY);
    this.log(`paired; capabilities: ${[...this.capabilities].sort().join(', ') || 'none'}; radio ${this.radioConnected ? 'connected' : 'away'}`);
    try { this.emit('hello', hello); } catch (e) { this.log(`hello handler threw: ${e?.message ?? e}`); }
    if (this.subs.length) this.#subscribePending();

    let beat = null;
    if (this.heartbeatMs > 0) {
      beat = setInterval(() => {
        c.request('device.info', {}, this.heartbeatTimeoutMs).catch((e) => {
          if (e?.code === 'timeout' || e?.code === 'closed') {
            this.log(`heartbeat failed (${e.message}), reconnecting`);
            c.terminate();
          }
        });
      }, this.heartbeatMs);
      beat.unref?.();
    }
    const info = await closed;
    clearInterval(beat);
    return { paired: true, ...info };
  }

  async #loop() {
    let backoff = this.backoffMinMs;
    while (!this.stopped) {
      this.#setState(State.CONNECTING);
      const r = await this.#session();
      this.#reset();
      this.lastClose = { code: r.code, reason: r.reason };
      if (r.paired) this.emit('disconnect', this.lastClose);
      if (this.stopped) break;
      let delay;
      if (r.code === CLOSE_REFUSED) {
        this.#setState(State.REFUSED);
        delay = this.refusedRetryMs;
      } else {
        this.#setState(State.DISCONNECTED);
        if (r.paired) backoff = this.backoffMinMs;
        delay = backoff * (1 + (Math.random() * 2 - 1) * this.jitter);
        if (!r.paired) backoff = Math.min(backoff * 2, this.backoffMaxMs);
      }
      await new Promise((resolve) => {
        const t = setTimeout(resolve, delay);
        this.wake = () => { clearTimeout(t); resolve(); };
      });
      this.wake = null;
    }
  }
}
