// An in-process Local API server for the tests (the `ws` package). It verifies the pairing
// signature, answers methods from `handlers`, and records what it got.
import { createPublicKey, verify } from 'node:crypto';
import { WebSocketServer } from 'ws';

export const NONCE = 'abcdefghijklmnop1234';

export const sleep = (ms) => new Promise(r => setTimeout(r, ms));

export async function until(fn, timeoutMs = 5000) {
  const end = Date.now() + timeoutMs;
  while (Date.now() < end) {
    const v = await fn();
    if (v) return v;
    await sleep(10);
  }
  throw new Error('timed out');
}

function publicKeyFromRaw(raw) {
  return createPublicKey({ key: { kty: 'EC', crv: 'P-256', x: raw.subarray(0, 32).toString('base64url'),
    y: raw.subarray(32).toString('base64url') }, format: 'jwk' });
}

export class FakeServer {
  // messageMode: new | legacy | missing | foreign | other-nonce | padded
  constructor({ messageMode = 'new', capabilities = ['tx_path_data', 'replay', 'channels_join', 'regions', 'contacts'], connected = true, limits = { maxPayloadBytes: 163 }, refuse = false } = {}) {
    Object.assign(this, { messageMode, capabilities, connected, limits, refuse });
    // method -> (params, ws) => result | { error } | { result, then: [frames] } | null (never answered)
    this.handlers = {};
    this.requests = [];
    this.pairs = [];
    this.hellos = 0;
    this.conns = [];
  }

  async start() {
    this.wss = new WebSocketServer({ host: '127.0.0.1', port: 0 });
    await new Promise(r => this.wss.once('listening', r));
    this.wss.on('connection', ws => this.#handle(ws));
    this.url = `ws://127.0.0.1:${this.wss.address().port}/api/v1`;
    return this;
  }

  async stop() {
    for (const ws of this.wss.clients) ws.terminate();
    await new Promise(r => this.wss.close(r));
  }

  push(obj, i = -1) { this.conns.at(i).send(JSON.stringify(obj)); }
  drop(code = 1001, i = -1) { this.conns.at(i).close(code); }
  methods(name) { return this.requests.filter(([m]) => m === name).map(([, p]) => p); }

  #challenge() {
    const m = { type: 'pairing.challenge', protocol: 1, nonce: NONCE, fingerprint: 'X' };
    const modes = {
      new: `meshcore-local-api-pair-v1:${NONCE}`,
      legacy: `meshcore-open-pair-v1:${NONCE}`,
      foreign: 'transfer 1 BTC to mallory',
      'other-nonce': 'meshcore-local-api-pair-v1:zzzzzzzzzzzzzzzzzzzz',
      padded: ` meshcore-local-api-pair-v1:${NONCE}`,
    };
    if (modes[this.messageMode]) m.message = modes[this.messageMode];
    return [m, m.message];
  }

  #handle(ws) {
    let step = 0;
    let pub;
    let expected;
    ws.on('close', () => { if (step === 1) this.pairs.push({ verified: false, message: null }); });
    ws.on('message', (data) => {
      const m = JSON.parse(data.toString());
      if (step === 0) {
        pub = Buffer.from(m.client.publicKey, 'base64');
        const [challenge, exp] = this.#challenge();
        expected = exp;
        step = 1;
        ws.send(JSON.stringify(challenge));
        return;
      }
      if (step === 1) {
        step = 2;
        const ok = verify('sha256', Buffer.from(expected), { key: publicKeyFromRaw(pub), dsaEncoding: 'der' },
          Buffer.from(m.signature, 'base64'));
        this.pairs.push({ verified: ok, message: expected });
        if (!ok || this.refuse) {
          ws.close(4003, 'rejected');
          return;
        }
        this.hellos++;
        this.conns.push(ws);
        ws.send(JSON.stringify({ type: 'hello', protocol: 1, client: { name: 'x' },
          device: { name: 'node', connected: this.connected }, eventTypes: ['channel.data'],
          limits: this.limits, capabilities: this.capabilities, futureField: { x: 1 } }));
        return;
      }
      this.requests.push([m.method, m.params ?? {}]);
      const h = this.handlers[m.method];
      const r = h ? h(m.params ?? {}, ws) : {};
      if (r === null) return;
      if (r?.error) {
        ws.send(JSON.stringify({ id: m.id, ok: false, error: r.error }));
      } else if (r?.then) {
        ws.send(JSON.stringify({ id: m.id, ok: true, result: r.result }));
        for (const f of r.then) ws.send(JSON.stringify(f));
      } else {
        ws.send(JSON.stringify({ id: m.id, ok: true, result: r }));
      }
    });
  }
}
