import { EventEmitter } from 'node:events';
import type { KeyObject } from 'node:crypto';

export class ApiError extends Error {
  constructor(code: string, message?: string, opts?: { maybeSent?: boolean; method?: string | null; details?: object | null });
  code: string;
  maybeSent: boolean;
  method: string | null;
  details: object | null;
  static fromAnswer(error: unknown, method?: string | null): ApiError;
}
export class RequestTimeout extends ApiError { constructor(method: string, timeoutMs: number); }
export class ConnectionClosed extends ApiError { constructor(message?: string, method?: string | null); }
export class MissingCapability extends ApiError { constructor(capability: string, method?: string | null); capability: string; }
export class PairingError extends ApiError { constructor(message: string); }

export const PAIRING_PREFIX: 'meshcore-local-api-pair-v1:';

export interface PairingKey {
  privateKey: KeyObject;
  /** base64 of the raw 64-byte X||Y point */
  publicKeyBase64: string;
  /** "AB12 CD34 5678 9ABC" */
  fingerprint: string;
}
export interface KeyStore {
  load(): string | null | Promise<string | null>;
  save(pem: string): void | Promise<void>;
}
export function pairingMessage(challenge: { nonce?: unknown; message?: unknown }): string;
export function publicKeyBase64(privateKey: KeyObject): string;
export function fingerprint(publicKeyB64: string): string;
export function signMessage(privateKey: KeyObject, message: string): string;
export function signChallenge(privateKey: KeyObject, challenge: { nonce?: unknown; message?: unknown }): string;
export function keyFromPem(pem: string): PairingKey;
export function keyToPem(key: PairingKey): string;
export function generateKey(): PairingKey;
export function fileKeyStore(file: string): KeyStore;
export function loadOrCreateKey(store: string | KeyStore): PairingKey;
export function loadOrCreateKeyAsync(store: string | KeyStore): Promise<PairingKey>;

export interface Cursor { receivedAt: string; ids: string[]; }
export interface CursorStore {
  get(key: string): Cursor | null | Promise<Cursor | null>;
  set(key: string, cursor: Cursor): void;
  flush?(): void;
}
export class MemoryCursorStore implements CursorStore {
  get(key: string): Cursor | null;
  set(key: string, cursor: Cursor): void;
  flush(): void;
}
export class JsonFileCursorStore implements CursorStore {
  constructor(file: string, opts?: { saveIntervalMs?: number });
  get(key: string): Cursor | null;
  set(key: string, cursor: Cursor): void;
  flush(): void;
}

export const DEFAULT_URL: 'ws://127.0.0.1:8787/api/v1';
export const CLOSE_REFUSED: 4003;
export const DEFAULT_TIMEOUT_MS: number;
export const METHOD_TIMEOUTS_MS: Readonly<Record<string, number>>;
export const DEFAULT_MAX_PAYLOAD: 163;
export function isLoopbackUrl(url: string): boolean;
export const METHOD_CAPABILITIES: Readonly<Record<string, string>>;
export const EVENT_CAPABILITIES: Readonly<Record<string, string>>;
export const FILTER_CAPABILITIES: Readonly<Record<string, string>>;
/** The capabilities a request needs; request() rejects with MissingCapability when one is absent. */
export function requiredCapabilities(method: string, params?: object | null): string[];
export function resolveWebSocket(override?: unknown): Promise<unknown>;

export type LocalApiEvent = { type: string; receivedAt?: string; outgoing?: boolean; [field: string]: unknown };
export type Hello = {
  type: 'hello';
  protocol?: number;
  device?: { connected?: boolean; [field: string]: unknown };
  capabilities?: string[];
  limits?: Record<string, number>;
  [field: string]: unknown;
};

export interface ConnectionOptions {
  url?: string;
  key: PairingKey;
  name: string;
  version?: string;
  handshakeTimeoutMs?: number;
  pairTimeoutMs?: number;
  requestTimeoutMs?: number;
  methodTimeoutsMs?: Record<string, number>;
  /** a WebSocket constructor; default the global one, else the `ws` package */
  WebSocket?: unknown;
  loopbackOnly?: boolean;
  log?: (message: string) => void;
}

export class LocalApiConnection extends EventEmitter {
  constructor(opts: ConnectionOptions);
  readonly paired: boolean;
  hello: Hello | null;
  capabilities: Set<string>;
  limits: Record<string, number>;
  lastActivity: number;
  methodTimeoutsMs: Record<string, number>;
  connect(): Promise<Hello>;
  request<T = Record<string, unknown>>(method: string, params?: object, timeoutMs?: number,
    opts?: { onAnswer?: (message: object) => void }): Promise<T>;
  terminate(): void;
  close(): void;
  on(event: 'event', fn: (event: LocalApiEvent, subscriptionId: unknown) => void): this;
  on(event: 'device', fn: (message: object) => void): this;
  on(event: 'close', fn: (info: { code: number; reason: string }) => void): this;
}

export const State: Readonly<{
  DISCONNECTED: 'disconnected'; CONNECTING: 'connecting'; READY: 'ready'; JOINING: 'joining';
  REFUSED: 'refused'; STOPPED: 'stopped';
}>;
export type StateName = typeof State[keyof typeof State];

export class Subscription {
  params: Record<string, unknown>;
  cursorKey: string | null;
  join: boolean;
  id: string | null;
  error: ApiError | null;
  readonly active: boolean;
  readonly channel: unknown;
}

export interface ClientOptions extends ConnectionOptions {
  cursorStore?: CursorStore | null;
  backoffMinMs?: number;
  backoffMaxMs?: number;
  jitter?: number;
  refusedRetryMs?: number;
  /** 0 (default) turns the device.info heartbeat off */
  heartbeatMs?: number;
  heartbeatTimeoutMs?: number;
  seenLimit?: number;
}

export interface SendDataOptions {
  region?: string | null;
  /** next hop first; empty for zero-hop; needs `tx_path_data` */
  path?: Uint8Array | Uint8Array[] | null;
  pathHashSize?: 1 | 2 | 3;
  timeoutMs?: number;
}

export class LocalApiClient extends EventEmitter {
  constructor(opts: ClientOptions);
  readonly paired: boolean;
  readonly maxPayload: number;
  readonly subscriptions: Subscription[];
  connection: LocalApiConnection | null;
  hello: Hello | null;
  device: { connected?: boolean; [field: string]: unknown } | null;
  channels: Array<{ index?: number; name?: string; [field: string]: unknown }> | null;
  capabilities: Set<string>;
  limits: Record<string, number>;
  radioConnected: boolean;
  state: StateName;
  stateDetail: string | null;
  lastClose: { code: number; reason: string } | null;
  has(capability: string): boolean;
  start(): this;
  stop(): Promise<void>;
  waitPaired(timeoutMs?: number): Promise<boolean>;
  request<T = Record<string, unknown>>(method: string, params?: object, timeoutMs?: number): Promise<T>;
  subscribe(params: object, opts?: { cursorKey?: string | null; join?: boolean }): Subscription;
  unsubscribe(sub: Subscription): Promise<void>;
  sendData(channel: string, dataType: number, payload: Uint8Array, opts?: SendDataOptions): Promise<Record<string, unknown>>;
  sendText(channel: string, text: string, opts?: { region?: string | null; timeoutMs?: number }): Promise<Record<string, unknown>>;
  on(event: 'hello', fn: (hello: Hello) => void): this;
  on(event: 'event', fn: (event: LocalApiEvent, subscription: Subscription | null) => void): this;
  on(event: 'device', fn: (message: { device?: object; channels?: object[] }) => void): this;
  on(event: 'state', fn: (state: StateName, detail: string | null) => void): this;
  on(event: 'disconnect', fn: (info: { code: number; reason: string }) => void): this;
}

export function eventId(event: LocalApiEvent): string;
export function eventPayload(event: LocalApiEvent): Buffer | null;
export function eventPath(event: LocalApiEvent): { hops: Buffer[]; hashSize: number } | null;
