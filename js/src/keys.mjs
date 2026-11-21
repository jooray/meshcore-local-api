import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, sign } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { PairingError } from './errors.mjs';

export const PAIRING_PREFIX = 'meshcore-local-api-pair-v1:';
export const LEGACY_PAIRING_PREFIX = 'meshcore-open-pair-v1:';
export const PAIRING_PREFIXES = [PAIRING_PREFIX, LEGACY_PAIRING_PREFIX];
const NONCE_SHAPE = /^[A-Za-z0-9_-]{16,128}={0,2}$/;

// The exact string to sign for a `pairing.challenge`, or a PairingError. The challenge's `message`
// must be one of the two pairing prefixes followed by this challenge's own `nonce`; anything else is
// refused, so a server cannot make the client sign arbitrary text. A challenge without `message`
// (older servers) gets the legacy string the protocol defines.
export function pairingMessage(challenge) {
  const nonce = challenge?.nonce;
  if (typeof nonce !== 'string' || !NONCE_SHAPE.test(nonce)) throw new PairingError('malformed pairing nonce');
  const message = challenge.message;
  if (message === undefined || message === null) return `${LEGACY_PAIRING_PREFIX}${nonce}`;
  if (typeof message === 'string' && PAIRING_PREFIXES.some(p => message === `${p}${nonce}`)) return message;
  throw new PairingError('the challenge asks to sign something other than the pairing string');
}

// Base64 of the raw 64-byte X||Y point, which is what the API calls a public key.
export function publicKeyBase64(privateKey) {
  const jwk = createPublicKey(privateKey).export({ format: 'jwk' });
  return Buffer.concat([Buffer.from(jwk.x, 'base64url'), Buffer.from(jwk.y, 'base64url')]).toString('base64');
}

// First 8 bytes of SHA-256(X||Y) as "AB12 CD34 5678 9ABC": what the user compares in the dialog.
export function fingerprint(publicKeyB64) {
  const hex = createHash('sha256').update(Buffer.from(publicKeyB64, 'base64')).digest('hex').slice(0, 16).toUpperCase();
  return hex.match(/.{4}/g).join(' ');
}

// SHA256withECDSA over the UTF-8 message, base64 of the DER signature.
export function signMessage(privateKey, message) {
  return sign('sha256', Buffer.from(message, 'utf8'), { key: privateKey, dsaEncoding: 'der' }).toString('base64');
}

// Checks the challenge (see pairingMessage) and signs it.
export function signChallenge(privateKey, challenge) {
  return signMessage(privateKey, pairingMessage(challenge));
}

// A key as the client uses it: { privateKey, publicKeyBase64, fingerprint }.
export function keyFromPem(pem) {
  const privateKey = createPrivateKey(pem);
  if (privateKey.asymmetricKeyType !== 'ec' || privateKey.asymmetricKeyDetails?.namedCurve !== 'prime256v1') {
    throw new Error('the pairing key must be a P-256 private key');
  }
  const pub = publicKeyBase64(privateKey);
  return { privateKey, publicKeyBase64: pub, fingerprint: fingerprint(pub) };
}

export function generateKey() {
  const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  return keyFromPem(privateKey.export({ type: 'pkcs8', format: 'pem' }));
}

export function keyToPem(key) {
  return key.privateKey.export({ type: 'pkcs8', format: 'pem' });
}

function writePrivate(file, text) {
  mkdirSync(dirname(file), { recursive: true });
  const tmp = `${file}.tmp`;
  writeFileSync(tmp, text, { mode: 0o600 });
  chmodSync(tmp, 0o600);
  renameSync(tmp, file);
}

// A key store keeping a PKCS#8 PEM in a file readable by the owner only.
export function fileKeyStore(file) {
  return {
    load() {
      if (!existsSync(file)) return null;
      chmodSync(file, 0o600);
      return readFileSync(file, 'utf8');
    },
    save(pem) { writePrivate(file, pem); },
  };
}

// The stored key, or a new one saved to the store. `store` is a file path (PEM, mode 0600) or an
// object with `load(): string | null` and `save(pem)` (sync or async).
export async function loadOrCreateKeyAsync(store) {
  const s = typeof store === 'string' ? fileKeyStore(store) : store;
  const pem = await s.load();
  if (pem) return keyFromPem(pem);
  const key = generateKey();
  await s.save(keyToPem(key));
  return key;
}

// Synchronous variant for a file path or a store with synchronous methods.
export function loadOrCreateKey(store) {
  const s = typeof store === 'string' ? fileKeyStore(store) : store;
  const pem = s.load();
  if (pem && typeof pem.then === 'function') throw new Error('async key store: use loadOrCreateKeyAsync');
  if (pem) return keyFromPem(pem);
  const key = generateKey();
  s.save(keyToPem(key));
  return key;
}

// ---------------------------------------------------------------------------------------------
// Cursor stores: where a `since` replay starts. A cursor is { receivedAt, ids }: the `receivedAt`
// of the last event handled and the ids of the events sharing that timestamp (`since` is
// inclusive, so those come again and are skipped).

export class MemoryCursorStore {
  constructor() { this.map = new Map(); }
  get(key) { return this.map.get(key) ?? null; }
  set(key, cursor) { this.map.set(key, { receivedAt: cursor.receivedAt, ids: [...cursor.ids] }); }
  flush() {}
}

// All cursors in one JSON file, mode 0600, written atomically: { "<key>": { receivedAt, ids } }.
// Writes are batched to one per `saveIntervalMs`, plus flush() (the client flushes on every
// disconnect and on stop).
export class JsonFileCursorStore {
  constructor(file, { saveIntervalMs = 10_000 } = {}) {
    this.file = file;
    this.saveIntervalMs = saveIntervalMs;
    this.dirty = false;
    this.savedAt = 0;
    this.data = {};
    if (existsSync(file)) {
      const d = JSON.parse(readFileSync(file, 'utf8'));
      if (d && typeof d === 'object' && !Array.isArray(d)) this.data = d;
    }
  }

  get(key) {
    const v = this.data[key];
    if (typeof v === 'string') return { receivedAt: v, ids: [] };
    if (v && typeof v.receivedAt === 'string') {
      return { receivedAt: v.receivedAt, ids: Array.isArray(v.ids) ? v.ids.filter(i => typeof i === 'string') : [] };
    }
    return null;
  }

  set(key, cursor) {
    this.data[key] = { receivedAt: cursor.receivedAt, ids: [...cursor.ids] };
    this.dirty = true;
    if (Date.now() - this.savedAt >= this.saveIntervalMs) this.flush();
  }

  flush() {
    if (!this.dirty) return;
    writePrivate(this.file, JSON.stringify(this.data));
    this.dirty = false;
    this.savedAt = Date.now();
  }
}
