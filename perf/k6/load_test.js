// PlainQ single-target gRPC load test.
//
// Drives one running PlainQ server (no baseline build, no AB comparison) with
// the same Send -> Receive -> Delete workload and the same metric names as
// ab_test.js, so the "PlainQ AB Performance" Grafana dashboard works as-is
// (the series are tagged variant=<VARIANT>, default "load").
//
// Used by `perfctl load`. Tunables come from the environment:
//   TARGET_ADDR, VARIANT, VUS, DURATION, BATCH_SIZE, MSG_BYTES.

import grpc from 'k6/net/grpc';
import encoding from 'k6/encoding';
import { check } from 'k6';
import { Counter, Trend } from 'k6/metrics';

const TARGET_ADDR = __ENV.TARGET_ADDR || 'localhost:8080';
const VARIANT = __ENV.VARIANT || 'load';
const VUS = parseInt(__ENV.VUS || '20', 10);
const DURATION = __ENV.DURATION || '2m';
const BATCH_SIZE = parseInt(__ENV.BATCH_SIZE || '1', 10);
const MSG_BYTES = parseInt(__ENV.MSG_BYTES || '256', 10);

const BODY = encoding.b64encode('x'.repeat(MSG_BYTES));

// Same metric names as the AB test so the dashboard and report tooling work.
const reqs = new Counter('plainq_reqs');
const errs = new Counter('plainq_errs');
const latency = new Trend('plainq_latency', true);

const SERVICE = 'v1.PlainQService';

const client = new grpc.Client();
client.load(['/proto'], 'v1/schema.proto');
let connected = false;

export const options = {
  scenarios: {
    load: {
      executor: 'constant-vus',
      vus: VUS,
      duration: DURATION,
      exec: 'run',
      tags: { variant: VARIANT },
    },
  },
  // Loose guard rail only; this is a raw load run, not a pass/fail gate.
  thresholds: {
    'plainq_latency{op:total}': ['p(95) < 5000'],
  },
};

export function setup() {
  client.connect(TARGET_ADDR, { plaintext: true, timeout: '15s' });

  const res = client.invoke(`${SERVICE}/CreateQueue`, {
    queue_name: `loadtest-${VARIANT}-${__ENV.RUN_ID || 'local'}`,
    visibility_timeout_seconds: 30,
    max_receive_attempts: 10,
  });

  if (res.status !== grpc.StatusOK) {
    throw new Error(`CreateQueue failed: ${JSON.stringify(res)}`);
  }

  const msg = res.message || {};
  const queueID = msg.queueId || msg.queue_id;
  client.close();

  console.log(`target=${TARGET_ADDR} queue=${queueID}`);
  return { queueID };
}

function isOK(res) {
  return !!res && res.status === grpc.StatusOK;
}

function timed(op, fn) {
  const t0 = Date.now();
  const res = fn();
  const dt = Date.now() - t0;

  const tags = { variant: VARIANT, op };

  reqs.add(1, tags);
  latency.add(dt, tags);
  if (!isOK(res)) {
    errs.add(1, tags);
  }
  check(res, { [`${op} ok`]: isOK }, tags);

  return res;
}

export function run(data) {
  if (!connected) {
    client.connect(TARGET_ADDR, { plaintext: true, timeout: '15s' });
    connected = true;
  }

  const queueID = data.queueID;
  const t0 = Date.now();
  let failed = false;

  const sendRes = timed('send', () =>
    client.invoke(`${SERVICE}/Send`, {
      queue_id: queueID,
      messages: [{ body: BODY }],
    }),
  );
  failed = failed || !isOK(sendRes);

  const recv = timed('receive', () =>
    client.invoke(`${SERVICE}/Receive`, {
      queue_id: queueID,
      batch_size: BATCH_SIZE,
    }),
  );
  failed = failed || !isOK(recv);

  const ids = [];
  if (isOK(recv) && recv.message && recv.message.messages) {
    for (const m of recv.message.messages) {
      ids.push(m.id);
    }
  }

  if (ids.length > 0) {
    const delRes = timed('delete', () =>
      client.invoke(`${SERVICE}/Delete`, {
        queue_id: queueID,
        message_ids: ids,
      }),
    );
    failed = failed || !isOK(delRes);
  }

  const tags = { variant: VARIANT, op: 'total' };
  latency.add(Date.now() - t0, tags);
  reqs.add(1, tags);
  if (failed) {
    errs.add(1, tags);
  }
}

export function handleSummary(data) {
  const runID = __ENV.RUN_ID || 'local';
  return {
    [`/results/load-summary-${runID}.json`]: JSON.stringify(data, null, 2),
    stdout: shortSummary(data),
  };
}

function shortSummary(data) {
  const m = data.metrics || {};
  const line = (name, key) => {
    const v = m[name] && m[name].values ? m[name].values[key] : undefined;
    return v === undefined ? 'n/a' : Number(v).toFixed(2);
  };

  return [
    '',
    `=== PlainQ load test (target=${TARGET_ADDR}, variant=${VARIANT}) ===`,
    `  requests (plainq_reqs) : ${line('plainq_reqs', 'count')}`,
    `  errors   (plainq_errs) : ${line('plainq_errs', 'count')}`,
    `  latency p95 (ms)       : ${line('plainq_latency', 'p(95)')}`,
    `  latency p99 (ms)       : ${line('plainq_latency', 'p(99)')}`,
    `  checks pass rate       : ${line('checks', 'rate')}`,
    '',
    'Open Grafana (:3000) to see the live dashboard for this run.',
    '',
  ].join('\n');
}
