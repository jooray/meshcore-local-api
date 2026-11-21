// Client for the MeshCore Local API (protocol 1): a loopback WebSocket through which a MeshCore
// host app (MeshCore Open, meshcored) lets other apps share its radio.
export { ApiError, ConnectionClosed, MissingCapability, PairingError, RequestTimeout } from './errors.mjs';
export {
  LEGACY_PAIRING_PREFIX, PAIRING_PREFIX, PAIRING_PREFIXES, JsonFileCursorStore, MemoryCursorStore,
  fileKeyStore, fingerprint, generateKey, keyFromPem, keyToPem, loadOrCreateKey, loadOrCreateKeyAsync,
  pairingMessage, publicKeyBase64, signChallenge, signMessage,
} from './keys.mjs';
export {
  CLOSE_REFUSED, DEFAULT_TIMEOUT_MS, DEFAULT_URL, METHOD_TIMEOUTS_MS, LocalApiConnection, isLoopbackUrl, resolveWebSocket,
} from './connection.mjs';
export { DEFAULT_MAX_PAYLOAD, LocalApiClient, State, Subscription, eventId, eventPath, eventPayload } from './client.mjs';
