import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, describe, test } from 'node:test';
import {
  ApiError, ConnectionClosed, JsonFileCursorStore, LocalApiClient, LocalApiConnection, MemoryCursorStore,
  MissingCapability, PairingError, RequestTimeout, State, eventPath, requiredCapabilities, generateKey, loadOrCreateKey, pairingMessage,
} from '../src/index.mjs';
import { FakeServer, NONCE, sleep, until } from './fake-server.mjs';

const dir = mkdtempSync(join(tmpdir(), 'mcla-'));
after(() => rmSync(dir, { recursive: true, force: true }));
const key = generateKey();

const ev = (receivedAt, payload, extra = {}) => ({ type: 'channel.data', channel: '#test', dataType: 0xFF00,
  payload: Buffer.from(payload).toString('base64'), receivedAt, outgoing: false, ...extra });

async function setup(serverOpts = {}, clientOpts = {}, prepare = () => {}) {
  const srv = await new FakeServer(serverOpts).start();
  prepare(srv);
  const c = new LocalApiClient({ url: srv.url, key, name: 'test', version: '1', backoffMinMs: 30, backoffMaxMs: 100,
    refusedRetryMs: 50, ...clientOpts });
  const done = async () => { await c.stop(); await srv.stop(); };
  return { srv, c, done };
}

describe('pairing', () => {
  for (const mode of ['new']) {
    test(`signs the pairing string (${mode})`, async () => {
      const { srv, c, done } = await setup({ messageMode: mode, capabilities: ['tx_path_data', 'rx_meta'], limits: { maxPayloadBytes: 150 } });
      c.start();
      assert.equal(await c.waitPaired(5000), true);
      assert.equal(srv.pairs[0].verified, true);
      assert.equal(c.state, State.READY);
      assert.deepEqual([...c.capabilities].sort(), ['rx_meta', 'tx_path_data']);
      assert.equal(c.maxPayload, 150);
      assert.equal(c.radioConnected, true);
      await done();
    });
  }

  for (const mode of ['legacy', 'missing', 'foreign', 'other-nonce', 'padded']) {
    test(`refuses a foreign challenge message (${mode})`, async () => {
      const srv = await new FakeServer({ messageMode: mode }).start();
      const conn = new LocalApiConnection({ url: srv.url, key, name: 'test' });
      await assert.rejects(conn.connect(), (e) => e instanceof PairingError && e.code === 'pairing');
      await until(() => srv.pairs.length);
      assert.deepEqual(srv.pairs[0], { verified: false, message: null });
      await srv.stop();
    });
  }

  test('pairingMessage', () => {
    assert.equal(pairingMessage({ nonce: NONCE, message: `meshcore-local-api-pair-v1:${NONCE}` }), `meshcore-local-api-pair-v1:${NONCE}`);
    for (const bad of [{ nonce: 'short' }, { nonce: NONCE }, { nonce: NONCE, message: `meshcore-open-pair-v1:${NONCE}` },
      { nonce: NONCE, message: `meshcore-local-api-pair-v1:${NONCE}x` }, { nonce: NONCE, message: 5 }, {}]) {
      assert.throws(() => pairingMessage(bad), PairingError);
    }
  });

  test('4003 sets refused and retries', async () => {
    const { srv, c, done } = await setup({ refuse: true });
    const states = [];
    c.on('state', s => states.push(s));
    c.start();
    await until(() => srv.pairs.length >= 2);
    assert.ok(states.includes(State.REFUSED));
    assert.equal(c.lastClose.code, 4003);
    await done();
  });

  test('loopback only', () => {
    assert.throws(() => new LocalApiClient({ url: 'ws://192.0.2.1:8787/api/v1', key, name: 'x' }));
  });

  test('key file is 0600 and reloads', () => {
    const f = join(dir, 'k', 'key.pem');
    const k = loadOrCreateKey(f);
    assert.equal(statSync(f).mode & 0o777, 0o600);
    assert.equal(Buffer.from(k.publicKeyBase64, 'base64').length, 64);
    assert.equal(loadOrCreateKey(f).publicKeyBase64, k.publicKeyBase64);
    assert.match(k.fingerprint, /^[0-9A-F]{4}( [0-9A-F]{4}){3}$/);
  });
});

describe('requests', () => {
  test('response, errors, timeouts', async () => {
    const { c, done } = await setup({}, {}, (srv) => {
      srv.handlers['device.info'] = () => ({ connected: true, name: 'node' });
      srv.handlers['channel.sendText'] = () => ({ error: { code: 'radio_error', message: 'no ack', maybeSent: true } });
      srv.handlers['channels.list'] = () => ({ error: { code: 'not_connected' } });
      srv.handlers['contacts.list'] = () => null;
    });
    c.start();
    await c.waitPaired();
    assert.deepEqual(await c.request('device.info'), { connected: true, name: 'node' });
    await assert.rejects(c.sendText('#test', 'hi'), (e) => e instanceof ApiError && e.code === 'radio_error'
      && e.maybeSent === true && e.method === 'channel.sendText');
    await assert.rejects(c.request('channels.list'), (e) => e.code === 'not_connected' && e.maybeSent === false);
    await assert.rejects(c.request('contacts.list', {}, 200), (e) => e instanceof RequestTimeout && e.code === 'timeout');
    await done();
  });

  test('channels.join waits long; a close fails it at once', async () => {
    const { srv, c, done } = await setup({}, {}, (s) => { s.handlers['channels.join'] = () => null; });
    c.start();
    await c.waitPaired();
    assert.equal(c.connection.methodTimeoutsMs['channels.join'], 150_000);
    const t = Date.now();
    const p = c.request('channels.join', { name: '#x' });
    await until(() => srv.methods('channels.join').length);
    srv.drop();
    await assert.rejects(p, (e) => e instanceof ConnectionClosed && e.code === 'closed');
    assert.ok(Date.now() - t < 5000);
    await done();
  });

  test('not paired', async () => {
    const c = new LocalApiClient({ url: 'ws://127.0.0.1:1/api/v1', key, name: 'x' });
    await assert.rejects(c.request('device.info'), ConnectionClosed);
  });

  test('unknown frames and fields are ignored', async () => {
    const got = [];
    const { srv, c, done } = await setup({}, {}, (s) => { s.handlers['device.info'] = () => ({ ok: 1 }); });
    c.on('event', e => got.push(e));
    c.start();
    await c.waitPaired();
    srv.push({ type: 'future.thing', x: 1 });
    srv.push({ id: 999, ok: true, result: {} });
    srv.push({ type: 'event', event: { type: 'future.event', foo: 1 } });
    assert.deepEqual(await c.request('device.info'), { ok: 1 });
    await until(() => got.length);
    assert.deepEqual(got, [{ type: 'future.event', foo: 1 }]);
    await done();
  });
});

describe('subscriptions', () => {
  test('device push with connected:true resubscribes', async () => {
    const { srv, c, done } = await setup({ connected: false }, {}, (s) => { s.handlers['events.subscribe'] = () => ({ subscriptionId: 's1' }); });
    c.start();
    await c.waitPaired();
    const sub = c.subscribe({ events: ['channel.data'], channel: '#test' });
    await sleep(150);
    assert.equal(srv.methods('events.subscribe').length, 0);
    srv.push({ type: 'device', device: { connected: true }, channels: [{ index: 0, name: '#test' }] });
    await until(() => sub.active);
    assert.deepEqual(c.channels, [{ index: 0, name: '#test' }]);
    srv.push({ type: 'device', device: { connected: true }, channels: [] });
    await sleep(150);
    assert.equal(srv.methods('events.subscribe').length, 1);
    await done();
  });

  test('unknown_channel joins once, then subscribes', async () => {
    const known = new Set();
    const { srv, c, done } = await setup({}, {}, (s) => {
      s.handlers['events.subscribe'] = (p) => known.has(p.channel) ? { subscriptionId: 's1' } : { error: { code: 'unknown_channel' } };
      s.handlers['channels.join'] = (p) => { known.add(p.name); return { index: 3, name: p.name, created: true }; };
    });
    const states = [];
    c.on('state', (s, d) => states.push([s, d]));
    c.start();
    const sub = c.subscribe({ channel: '#test' }, { join: true });
    await until(() => sub.active);
    assert.deepEqual(srv.methods('channels.join'), [{ name: '#test' }]);
    assert.ok(states.some(([s, d]) => s === State.JOINING && d === '#test'));
    await done();
  });

  test('since replay: dedupe and cursor', async () => {
    const t0 = '2026-11-13T10:00:00.000Z';
    const t1 = '2026-11-13T10:00:05.000Z';
    const t2 = '2026-11-13T10:00:09Z';
    const archive = [ev(t0, 'a'), ev(t1, 'b'), ev(t1, 'c')];
    const handler = () => ({ result: { subscriptionId: 's7' }, then: archive.map(e => ({ type: 'event', subscriptionId: 's7', event: e })) });
    const file = join(dir, 'cursor.json');
    const store = new JsonFileCursorStore(file, { saveIntervalMs: 0 });
    store.set('test', { receivedAt: t0, ids: [] });
    const got = [];
    const { srv, c, done } = await setup({}, { cursorStore: store }, (s) => { s.handlers['events.subscribe'] = handler; });
    c.on('event', e => got.push(Buffer.from(e.payload, 'base64').toString()));
    c.start();
    const sub = c.subscribe({ events: ['channel.data'], channel: '#test' }, { cursorKey: 'test' });
    await until(() => got.length >= 3);
    assert.equal(srv.methods('events.subscribe')[0].since, t0);
    assert.deepEqual(got, ['a', 'b', 'c']);
    assert.equal(sub.id, 's7');
    srv.drop();
    await until(() => srv.hellos === 2 && srv.methods('events.subscribe').length === 2);
    assert.equal(srv.methods('events.subscribe')[1].since, t1);
    srv.push({ type: 'event', subscriptionId: 's7', event: ev(t2, 'd') });
    await until(() => got.length === 4);
    assert.equal(got[3], 'd');
    await done();
    const stored = JSON.parse(readFileSync(file, 'utf8'));
    assert.equal(stored.test.receivedAt, t2);
    assert.equal(stored.test.ids.length, 1);
    assert.equal(statSync(file).mode & 0o777, 0o600);

    archive.push(ev(t2, 'd'));
    const got2 = [];
    const r2 = await setup({}, { cursorStore: new JsonFileCursorStore(file) }, (s) => { s.handlers['events.subscribe'] = handler; });
    r2.c.on('event', e => got2.push(e));
    r2.c.start();
    r2.c.subscribe({ channel: '#test' }, { cursorKey: 'test' });
    await until(() => r2.srv.methods('events.subscribe').length);
    await sleep(200);
    assert.deepEqual(got2, []);
    await r2.done();
  });

  test('memory cursor store', () => {
    const m = new MemoryCursorStore();
    m.set('a', { receivedAt: 'x', ids: ['1'] });
    assert.deepEqual(m.get('a'), { receivedAt: 'x', ids: ['1'] });
    assert.throws(() => new LocalApiClient({ key, name: 'x' }).subscribe({}, { cursorKey: 'a' }));
  });
});

describe('send', () => {
  for (const caps of [['regions'], ['regions', 'tx_path_data']]) {
    test(`path only with tx_path_data (caps: ${caps.join(',') || 'none'})`, async () => {
      const { srv, c, done } = await setup({ capabilities: caps }, {}, (s) => { s.handlers['channel.sendData'] = () => ({ queued: true }); });
      c.start();
      await c.waitPaired();
      assert.deepEqual(await c.sendData('#test', 0xFF00, Buffer.from('hi'), { region: 'sk' }), { queued: true });
      let sent = srv.methods('channel.sendData').at(-1);
      assert.equal('path' in sent, false);
      assert.equal('pathHashSize' in sent, false);
      assert.equal(sent.region, 'sk');
      if (!caps.includes('tx_path_data')) {
        await assert.rejects(c.sendData('#test', 0xFF00, Buffer.from('hi'), { path: [] }),
          (e) => e instanceof MissingCapability && e.code === 'unsupported');
        assert.equal(srv.methods('channel.sendData').length, 1);
      } else {
        await c.sendData('#test', 0xFF00, Buffer.from('hi'), { path: [] });
        assert.equal(srv.methods('channel.sendData').at(-1).path, '');
        await c.sendData('#test', 0xFF00, Buffer.from('hi'), { path: [Buffer.from('c3d4', 'hex'), Buffer.from('a1b2', 'hex')], pathHashSize: 2 });
        sent = srv.methods('channel.sendData').at(-1);
        assert.deepEqual([sent.path, sent.pathHashSize], ['c3d4a1b2', 2]);
        await assert.rejects(c.sendData('#test', 0xFF00, Buffer.from('hi'), { path: [Buffer.from([1])], pathHashSize: 2 }),
          (e) => e.code === 'bad_request');
      }
      await assert.rejects(c.sendData('#test', 0xFF00, Buffer.alloc(164)), (e) => e.code === 'payload_too_large');
      await done();
    });
  }

  test('eventPath', () => {
    const p = eventPath({ path: 'a1b2c3d4', pathHashSize: 2 });
    assert.deepEqual(p.hops.map(h => h.toString('hex')), ['a1b2', 'c3d4']);
    assert.equal(p.hashSize, 2);
    assert.equal(eventPath({ path: 'a1b' }), null);
    assert.equal(eventPath({}), null);
  });
});

describe('reconnect', () => {
  test('reconnects and resubscribes after a drop', async () => {
    const hellos = [];
    const { srv, c, done } = await setup({}, {}, (s) => { s.handlers['events.subscribe'] = () => ({ subscriptionId: 's1' }); });
    c.on('hello', h => hellos.push(h));
    c.start();
    const sub = c.subscribe({ events: ['channel.text'] });
    await until(() => sub.active);
    srv.drop(1001);
    await until(() => hellos.length === 2 && sub.active);
    assert.equal(srv.methods('events.subscribe').length, 2);
    await done();
  });

  test('keeps trying while the server is not there', async () => {
    const port = await new Promise((resolve) => {
      const s = createServer();
      s.listen(0, '127.0.0.1', () => { const { port: p } = s.address(); s.close(() => resolve(p)); });
    });
    const c = new LocalApiClient({ url: `ws://127.0.0.1:${port}/api/v1`, key, name: 't', backoffMinMs: 20, backoffMaxMs: 50 });
    const states = [];
    c.on('state', s => states.push(s));
    c.start();
    await until(() => states.filter(s => s === State.CONNECTING).length >= 2, 8000);
    assert.equal(c.paired, false);
    await c.stop();
  });
});

describe('transport', () => {
  test('works with the ws package as the WebSocket', async () => {
    const WS = (await import('ws')).default;
    const { c, done } = await setup({}, { WebSocket: WS }, (s) => { s.handlers['device.info'] = () => ({ via: 'ws' }); });
    c.start();
    assert.equal(await c.waitPaired(), true);
    assert.deepEqual(await c.request('device.info'), { via: 'ws' });
    await done();
  });
});

describe('capability gating', () => {
  test('requiredCapabilities', () => {
    assert.deepEqual(requiredCapabilities('device.info', {}), []);
    assert.deepEqual(requiredCapabilities('channel.sendData', { region: 'x', path: '' }), ['regions', 'tx_path_data']);
    assert.deepEqual(requiredCapabilities('channel.sendText', { path: 'a1' }), ['tx_path_text']);
    assert.deepEqual(requiredCapabilities('channel.sendData', { region: null, path: null }), []);
    assert.deepEqual(requiredCapabilities('events.subscribe', { since: 't', pubkeys: [], events: ['advert', 'packet.raw'] }),
      ['replay', 'contacts', 'raw_rx']);
    for (const [m, cap] of [['contacts.list', 'contacts'], ['direct.sendText', 'contacts'], ['advert.send', 'advert_send'],
      ['regions.list', 'regions'], ['regions.resolve', 'regions'], ['channels.join', 'channels_join'],
      ['radio.stats', 'radio_stats'], ['packet.sendRaw', 'raw_tx']]) {
      assert.deepEqual(requiredCapabilities(m, {}), [cap]);
    }
  });

  test('features without their capability send nothing', async () => {
    const { srv, c, done } = await setup({ capabilities: [] }, {}, (s) => { s.handlers['channel.sendData'] = () => ({ queued: true }); });
    c.start();
    await c.waitPaired();
    const calls = [
      () => c.sendData('#test', 1, Buffer.from('x'), { region: 'sk' }),
      () => c.sendText('#test', 'hi', { region: 'sk' }),
      () => c.request('channel.sendText', { channel: '#test', text: 'hi', path: '' }),
      ...['contacts.list', 'direct.sendText', 'advert.send', 'regions.list', 'regions.resolve', 'channels.join',
        'radio.stats', 'packet.sendRaw'].map(m => () => c.request(m, {})),
      () => c.request('events.subscribe', { since: '2026-11-13T10:00:00Z' }),
      () => c.request('events.subscribe', { events: ['direct.text'] }),
    ];
    for (const call of calls) await assert.rejects(call(), MissingCapability);
    assert.deepEqual(srv.requests, []);
    await c.sendData('#test', 1, Buffer.from('x'));
    assert.deepEqual(srv.requests.map(([m]) => m), ['channel.sendData']);
    await done();
  });

  test('subscribe omits since without replay and skips join without channels_join', async () => {
    const store = new MemoryCursorStore();
    store.set('k', { receivedAt: '2026-11-13T10:00:00Z', ids: [] });
    const { srv, c, done } = await setup({ capabilities: [] }, { cursorStore: store }, (s) => {
      s.handlers['events.subscribe'] = (p) => p.channel === '#new' ? { error: { code: 'unknown_channel' } } : { subscriptionId: 's1' };
    });
    c.start();
    await c.waitPaired();
    const sub = c.subscribe({ channel: '#test' }, { cursorKey: 'k' });
    await until(() => sub.active);
    assert.equal('since' in srv.methods('events.subscribe')[0], false);
    const missing = c.subscribe({ channel: '#new' }, { join: true });
    await until(() => missing.error);
    await sleep(150);
    assert.equal(missing.error.code, 'unknown_channel');
    assert.deepEqual(srv.methods('channels.join'), []);
    const contacts = c.subscribe({ pubkeys: ['ab'.repeat(32)] });
    await until(() => contacts.error);
    assert.ok(contacts.error instanceof MissingCapability && contacts.error.capability === 'contacts');
    assert.equal(srv.methods('events.subscribe').some(p => 'pubkeys' in p), false);
    await done();
  });
});
