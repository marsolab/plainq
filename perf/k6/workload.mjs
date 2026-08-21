// Pure helpers for the AB queue lifecycle. Keeping these independent from k6
// makes the isolation and scheduling contract executable in Node tests.

export function queueIndex(vuID, queueCount) {
  if (!Number.isInteger(vuID) || vuID <= 0) {
    throw new Error('VU id must be a positive integer');
  }
  if (!Number.isInteger(queueCount) || queueCount <= 0) {
    throw new Error('queue count must be a positive integer');
  }
  if (vuID > queueCount) {
    throw new Error('VU id exceeds the provisioned queue count');
  }

  return vuID - 1;
}

export function queueName(variant, runID, index) {
  const safeRunID = String(runID || 'local')
    .replace(/[^a-zA-Z0-9_-]+/g, '-')
    .replace(/^-+|-+$/g, '') || 'local';

  return `perf-${variant}-${safeRunID}-vu-${index + 1}`;
}

// Assign each VU a non-overlapping slot within a variant-local cycle. The
// latency timer starts after this wait, so the workload measures the service,
// not client-side pacing. SQLite is a single-writer backend; scheduled slots
// avoid manufacturing lock-upgrade failures that obscure the AB comparison.
export function slotDelayMilliseconds(nowMs, index, queueCount, slotMs) {
  if (!Number.isFinite(nowMs)) {
    throw new Error('current time must be finite');
  }
  if (!Number.isInteger(index) || index < 0 || index >= queueCount) {
    throw new Error('queue index must be within the queue count');
  }
  if (!Number.isInteger(queueCount) || queueCount <= 0) {
    throw new Error('queue count must be a positive integer');
  }
  if (!Number.isInteger(slotMs) || slotMs <= 0) {
    throw new Error('slot duration must be a positive integer');
  }

  const cycleMs = queueCount * slotMs;
  const position = ((Math.floor(nowMs) % cycleMs) + cycleMs) % cycleMs;
  const target = index * slotMs;

  return (target - position + cycleMs) % cycleMs;
}

export function ownsReceivedMessage(sentIDs, receivedMessages) {
  if (!Array.isArray(sentIDs) || sentIDs.length === 0 || !Array.isArray(receivedMessages)) {
    return false;
  }

  const receivedIDs = new Set(receivedMessages.map((message) => message && message.id).filter(Boolean));
  return sentIDs.every((id) => receivedIDs.has(id));
}
