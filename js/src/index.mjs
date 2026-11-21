// Client for the MeshCore Local API (protocol 1): a loopback WebSocket through which a MeshCore
// host app (MeshCore Open, meshcored) lets other apps share its radio.
export { ApiError, ConnectionClosed, MissingCapability, PairingError, RequestTimeout } from './errors.mjs';
export {
  PAIRING_PREFIX, JsonFileCursorStore, MemoryCursorStore,
  fileKeyStore, fingerprint, generateKey, keyFromPem, keyToPem, loadOrCreateKey, loadOrCreateKeyAsync,
  pairingMessage, publicKeyBase64, signChallenge, signMessage,
} from './keys.mjs';
export {
  CLOSE_REFUSED, DEFAULT_TIMEOUT_MS, DEFAULT_URL, EVENT_CAPABILITIES, FILTER_CAPABILITIES, METHOD_CAPABILITIES,
  METHOD_TIMEOUTS_MS, LocalApiConnection, isLoopbackUrl, requiredCapabilities, resolveWebSocket,
} from './connection.mjs';
export { DEFAULT_MAX_PAYLOAD, LocalApiClient, State, Subscription, eventId, eventPath, eventPayload } from './client.mjs';
