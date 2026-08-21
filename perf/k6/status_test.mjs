import assert from 'node:assert/strict';

import { boundedCode, boundedReason, statusName } from './status.mjs';

assert.equal(boundedCode(0), '0');
assert.equal(boundedCode(16), '16');
assert.equal(boundedCode(99), 'unknown');
assert.equal(boundedCode('8'), 'unknown');

assert.equal(statusName(0), 'OK');
assert.equal(statusName(8), 'RESOURCE_EXHAUSTED');
assert.equal(statusName(13), 'INTERNAL');
assert.equal(statusName(99), 'UNKNOWN_STATUS');

assert.equal(boundedReason(0, ''), 'ok');
assert.equal(boundedReason(13, 'SQLITE_BUSY: database is locked'), 'sqlite_busy');
assert.equal(boundedReason(8, 'principal request rate exceeded'), 'rate_limited');
assert.equal(boundedReason(4, 'context deadline exceeded'), 'deadline');
assert.equal(boundedReason(5, 'queue was not found'), 'not_found');
assert.equal(boundedReason(13, 'secret backend details'), 'internal');
assert.equal(boundedReason(99, 'secret backend details'), 'unknown');

console.log('bounded k6 gRPC status classification passed');
