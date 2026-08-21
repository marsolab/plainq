// PlainQ gRPC AB load test.
//
// Runs an identical queue workload (Send -> Receive -> Delete) against two
// PlainQ servers at once -- "baseline" (stable ref) and "candidate" (current
// checkout) -- using k6's native gRPC client. Every sample is tagged with a
// `variant` label (set per scenario) and an `op` label (set per call), so the
// Grafana dashboard and scripts/report.py can compare the two side by side.
//
// Metrics are streamed to VictoriaMetrics over Prometheus remote-write
// (configured via the `--out experimental-prometheus-rw` flag in the compose
// entrypoint). Custom metrics defined here surface in VictoriaMetrics as:
//
//   k6_plainq_reqs_total{variant,op}     -- request count
//   k6_plainq_errs_total{variant,op}     -- error count
//   k6_plainq_latency_p95{variant,op}    -- latency (one series per trend stat)
//   k6_plainq_rpc_status_total{variant,op,code,grpc_status,reason}
//
// Tunables come from the environment (see docker-compose.yml / run.sh):
//   BASELINE_ADDR, CANDIDATE_ADDR, VUS, DURATION, BATCH_SIZE, MSG_BYTES.

import grpc from 'k6/net/grpc';
import encoding from 'k6/encoding';
import { check, sleep } from 'k6';
import { Counter, Trend } from 'k6/metrics';
import { boundedCode, boundedReason, statusName } from './status.mjs';
import {
  ownsReceivedMessage,
  queueIndex,
  queueName,
  slotDelayMilliseconds,
} from './workload.mjs';

const BASELINE_ADDR = __ENV.BASELINE_ADDR || 'localhost:18080';
const CANDIDATE_ADDR = __ENV.CANDIDATE_ADDR || 'localhost:28080';
const VUS = parseInt(__ENV.VUS || '20', 10);
const DURATION = __ENV.DURATION || '2m';
const BATCH_SIZE = parseInt(__ENV.BATCH_SIZE || '1', 10);
const MSG_BYTES = parseInt(__ENV.MSG_BYTES || '256', 10);
const WORK_SLOT_MS = parseInt(__ENV.WORK_SLOT_MS || '25', 10);
const TOTAL_VUS = VUS * 2;

// A fixed payload of the requested size, base64-encoded for the proto `bytes`
// field (k6 represents bytes fields as base64 strings).
const BODY = encoding.b64encode('x'.repeat(MSG_BYTES));

// Custom metrics. The `variant` label is added automatically from the scenario
// tag; we add `op` per call (and `variant` too, defensively) so every series is
// fully qualified.
const reqs = new Counter('plainq_reqs');
const errs = new Counter('plainq_errs');
const rpcStatus = new Counter('plainq_rpc_status');
const latency = new Trend('plainq_latency', true);

const SERVICE = 'v1.PlainQService';

// One client per VU (k6 runs each VU in its own isolate, so module scope is
// per-VU). A VU only ever runs one scenario, hence one target address.
const client = new grpc.Client();
client.load(['/proto'], 'v1/schema.proto');
let connected = false;

export const options = {
  scenarios: {
    baseline: {
      executor: 'constant-vus',
      vus: VUS,
      duration: DURATION,
      exec: 'baseline',
      tags: { variant: 'baseline' },
    },
    candidate: {
      executor: 'constant-vus',
      vus: VUS,
      duration: DURATION,
      exec: 'candidate',
      tags: { variant: 'candidate' },
    },
  },
  // Absolute latency is only a guard rail. scripts/report.py first requires a
  // valid successful lifecycle rate, then makes the relative AB verdict.
  thresholds: {
    'plainq_latency{op:total}': ['p(95) < 2000'],
  },
};

// setup runs once. k6 allocates global VU ids across concurrent scenarios in
// an arbitrary order, so each variant provisions the complete 2*VUS id range.
// Every active VU can then select its exact id without a collision. A shared
// queue lets one VU receive another VU's message and causes competing SQLite
// read-to-write lease upgrades; neither represents one comparable lifecycle.
export function setup() {
  const targets = [
    ['baseline', BASELINE_ADDR],
    ['candidate', CANDIDATE_ADDR],
  ];

  const queues = {};

  for (const [variant, addr] of targets) {
    client.connect(addr, { plaintext: true, timeout: '15s' });

    queues[variant] = [];
    for (let index = 0; index < TOTAL_VUS; index += 1) {
      const res = client.invoke(`${SERVICE}/CreateQueue`, {
        queue_name: queueName(variant, __ENV.RUN_ID || 'local', index),
        visibility_timeout_seconds: 30,
        max_receive_attempts: 10,
      });

      if (res.status !== grpc.StatusOK) {
        throw new Error(`CreateQueue(${variant}, VU ${index + 1}) failed: ${JSON.stringify(res)}`);
      }

      const msg = res.message || {};
      queues[variant].push(msg.queueId || msg.queue_id);
    }
    client.close();
  }

  console.log(`isolated queue id slots per variant: ${TOTAL_VUS} (${VUS} active VUs)`);
  return queues;
}

export function baseline(data) {
  workload(BASELINE_ADDR, 'baseline', data.baseline);
}

export function candidate(data) {
  workload(CANDIDATE_ADDR, 'candidate', data.candidate);
}

// isOK reports whether a gRPC response completed successfully.
function isOK(res) {
  return !!res && res.status === grpc.StatusOK;
}

function responseDetail(res) {
  if (!res) {
    return '';
  }
  if (typeof res.error === 'string') {
    return res.error;
  }
  if (res.error && typeof res.error.message === 'string') {
    return res.error.message;
  }
  if (typeof res.message === 'string') {
    return res.message;
  }
  return '';
}

function recordRPCStatus(variant, op, res) {
  const code = res && res.status !== undefined ? res.status : grpc.StatusUnknown;
  rpcStatus.add(1, {
    variant,
    op,
    code: boundedCode(code),
    grpc_status: statusName(code),
    reason: boundedReason(code, responseDetail(res)),
  });
}

// timed invokes fn, records req/err/latency under {variant, op}, and asserts OK.
function timed(variant, op, fn) {
  const t0 = Date.now();
  let res;
  try {
    res = fn();
  } catch (error) {
    res = { status: grpc.StatusUnknown, error };
  }
  const dt = Date.now() - t0;

  const tags = { variant, op };

  reqs.add(1, tags);
  latency.add(dt, tags);
  recordRPCStatus(variant, op, res);
  if (!isOK(res)) {
    errs.add(1, tags);
  }
  check(res, { [`${op} ok`]: isOK }, tags);

  return res;
}

// workload performs one full message lifecycle: Send -> Receive -> Delete.
function workload(addr, variant, queues) {
  if (!connected) {
    client.connect(addr, { plaintext: true, timeout: '15s' });
    connected = true;
  }

  const index = queueIndex(__VU, queues.length);
  const delayMs = slotDelayMilliseconds(Date.now(), index, queues.length, WORK_SLOT_MS);
  if (delayMs > 0) {
    sleep(delayMs / 1000);
  }
  const queueID = queues[index];

  const t0 = Date.now();
  let failed = false;

  const sendRes = timed(variant, 'send', () =>
    client.invoke(`${SERVICE}/Send`, {
      queue_id: queueID,
      messages: [{ body: BODY }],
    }),
  );
  failed = failed || !isOK(sendRes);

  const sentIDs = isOK(sendRes) && sendRes.message
    ? (sendRes.message.messageIds || sendRes.message.message_ids || [])
    : [];

  let recv;
  if (isOK(sendRes)) {
    recv = timed(variant, 'receive', () =>
      client.invoke(`${SERVICE}/Receive`, {
        queue_id: queueID,
        batch_size: BATCH_SIZE,
      }),
    );
    failed = failed || !isOK(recv);
  }

  const ids = [];
  if (isOK(recv) && recv.message && recv.message.messages) {
    for (const m of recv.message.messages) {
      ids.push(m.id);
    }
  }
  if (isOK(recv) && !ownsReceivedMessage(sentIDs, recv.message && recv.message.messages)) {
    errs.add(1, { variant, op: 'receive' });
    failed = true;
  }

  if (ids.length > 0) {
    const delRes = timed(variant, 'delete', () =>
      client.invoke(`${SERVICE}/Delete`, {
        queue_id: queueID,
        message_ids: ids,
      }),
    );
    failed = failed || !isOK(delRes);
  }

  // Record the end-to-end lifecycle outcome under op=total. The error sample
  // is what report.py uses for its regression error-rate verdict.
  const tags = { variant, op: 'total' };
  latency.add(Date.now() - t0, tags);
  reqs.add(1, tags);
  if (failed) {
    errs.add(1, tags);
  }
}

export function handleSummary(data) {
  const runID = __ENV.RUN_ID || 'local';
  return {
    [`/results/summary-${runID}.json`]: JSON.stringify(data, null, 2),
    stdout: shortSummary(data),
  };
}

// shortSummary renders a tiny offline console summary (no remote jslib import).
function shortSummary(data) {
  const m = data.metrics || {};
  const line = (name, key) => {
    const v = m[name] && m[name].values ? m[name].values[key] : undefined;
    return v === undefined ? 'n/a' : Number(v).toFixed(2);
  };

  return [
    '',
    '=== PlainQ AB load test (aggregate over both variants) ===',
    `  requests (plainq_reqs) : ${line('plainq_reqs', 'count')}`,
    `  errors   (plainq_errs) : ${line('plainq_errs', 'count')}`,
    `  latency p95 (ms)       : ${line('plainq_latency', 'p(95)')}`,
    `  latency p99 (ms)       : ${line('plainq_latency', 'p(99)')}`,
    `  checks pass rate       : ${line('checks', 'rate')}`,
    '',
    'Per-variant comparison: run scripts/report.py or open Grafana (:3000).',
    '',
  ].join('\n');
}
