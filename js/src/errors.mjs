// Errors raised by the client. Every one carries a `code`: the server's error code for an answer
// with `ok: false`, or one of the client-side codes `timeout`, `closed`, `unsupported`, `pairing`,
// `rejected`, `connect_failed`.

export class ApiError extends Error {
  constructor(code, message, { maybeSent = false, method = null, details = null } = {}) {
    super(message ?? code);
    this.name = 'ApiError';
    this.code = code;
    // true when the server says the command reached the radio but was not confirmed,
    // so it may have been transmitted (`maybeSent` in the error object)
    this.maybeSent = maybeSent;
    this.method = method;
    this.details = details;
  }

  // Builds the error from the `error` object of an answer or of a pre-pairing `error` frame.
  static fromAnswer(error, method = null) {
    if (!error || typeof error !== 'object') return new ApiError('error', 'malformed error answer', { method });
    const code = typeof error.code === 'string' ? error.code : 'error';
    const message = typeof error.message === 'string' ? error.message : undefined;
    return new ApiError(code, message, { maybeSent: error.maybeSent === true, method, details: error });
  }
}

export class RequestTimeout extends ApiError {
  constructor(method, timeoutMs) {
    super('timeout', `${method} got no answer in ${timeoutMs / 1000} s`, { method });
    this.name = 'RequestTimeout';
  }
}

export class ConnectionClosed extends ApiError {
  constructor(message = 'the connection is not open', method = null) {
    super('closed', message, { method });
    this.name = 'ConnectionClosed';
  }
}

export class MissingCapability extends ApiError {
  constructor(capability, method = null) {
    super('unsupported', `the server does not advertise ${capability}`, { method });
    this.name = 'MissingCapability';
    this.capability = capability;
  }
}

export class PairingError extends ApiError {
  constructor(message) {
    super('pairing', message);
    this.name = 'PairingError';
  }
}
