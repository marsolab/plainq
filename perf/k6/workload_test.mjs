import assert from 'node:assert/strict';

import {
  ownsReceivedMessage,
  queueIndex,
  queueName,
  slotDelayMilliseconds,
} from './workload.mjs';

assert.equal(queueIndex(1, 20), 0);
assert.equal(queueIndex(10, 20), 9);
assert.equal(queueIndex(11, 20), 10);
assert.equal(queueIndex(20, 20), 19);
assert.throws(() => queueIndex(0, 10), /positive/);
assert.throws(() => queueIndex(1, 0), /positive/);
assert.throws(() => queueIndex(21, 20), /exceeds/);

assert.equal(queueName('baseline', 'run/with spaces', 2), 'perf-baseline-run-with-spaces-vu-3');

assert.equal(slotDelayMilliseconds(1000, 0, 10, 25), 0);
assert.equal(slotDelayMilliseconds(1001, 0, 10, 25), 249);
assert.equal(slotDelayMilliseconds(1001, 1, 10, 25), 24);
assert.equal(slotDelayMilliseconds(1249, 0, 10, 25), 1);

assert.equal(ownsReceivedMessage(['message-1'], [{ id: 'message-1' }]), true);
assert.equal(ownsReceivedMessage(['message-1'], []), false);
assert.equal(ownsReceivedMessage(['message-1'], [{ id: 'message-2' }]), false);
assert.equal(ownsReceivedMessage([], [{ id: 'message-1' }]), false);

console.log('isolated k6 lifecycle scheduling passed');
