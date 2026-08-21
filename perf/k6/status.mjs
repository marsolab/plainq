// Canonical gRPC status codes. Keep all labels bounded: response text is only
// classified locally and is never emitted as a metric label.
const STATUS_NAMES = Object.freeze({
  0: 'OK',
  1: 'CANCELLED',
  2: 'UNKNOWN',
  3: 'INVALID_ARGUMENT',
  4: 'DEADLINE_EXCEEDED',
  5: 'NOT_FOUND',
  6: 'ALREADY_EXISTS',
  7: 'PERMISSION_DENIED',
  8: 'RESOURCE_EXHAUSTED',
  9: 'FAILED_PRECONDITION',
  10: 'ABORTED',
  11: 'OUT_OF_RANGE',
  12: 'UNIMPLEMENTED',
  13: 'INTERNAL',
  14: 'UNAVAILABLE',
  15: 'DATA_LOSS',
  16: 'UNAUTHENTICATED',
});

export function boundedCode(code) {
  return Number.isInteger(code) && Object.prototype.hasOwnProperty.call(STATUS_NAMES, code)
    ? String(code)
    : 'unknown';
}

export function statusName(code) {
  return Number.isInteger(code) && STATUS_NAMES[code]
    ? STATUS_NAMES[code]
    : 'UNKNOWN_STATUS';
}

export function boundedReason(code, detail) {
  if (code === 0) {
    return 'ok';
  }

  const normalized = typeof detail === 'string' ? detail.toLowerCase() : '';
  if (/sqlite_busy|database (?:table )?is locked/.test(normalized)) {
    return 'sqlite_busy';
  }
  if (/request rate exceeded|rate limit|resource exhausted/.test(normalized)) {
    return 'rate_limited';
  }
  if (/context deadline|deadline exceeded/.test(normalized)) {
    return 'deadline';
  }
  if (/not found/.test(normalized)) {
    return 'not_found';
  }

  const name = statusName(code);
  return name === 'UNKNOWN_STATUS' ? 'unknown' : name.toLowerCase();
}
