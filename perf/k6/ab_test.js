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
//
// Tunables come from the environment (see docker-compose.yml / run.sh):
//   BASELINE_ADDR, CANDIDATE_ADDR, VUS, DURATION, BATCH_SIZE, MSG_BYTES.

import grpc from 'k6/net/grpc';
import encoding from 'k6/encoding';
import { check } from 'k6';
import { Counter, Trend } from 'k6/metrics';

const BASELINE_ADDR = __ENV.BASELINE_ADDR || 'localhost:18080';
const CANDIDATE_ADDR = __ENV.CANDIDATE_ADDR || 'localhost:28080';
const VUS = parseInt(__ENV.VUS || '20', 10);
const DURATION = __ENV.DURATION || '2m';
const BATCH_SIZE = parseInt(__ENV.BATCH_SIZE || '1', 10);
const MSG_BYTES = parseInt(__ENV.MSG_BYTES || '256', 10);

// A fixed payload of the requested size, base64-encoded for the proto `bytes`
// field (k6 represents bytes fields as base64 strings).
const BODY = encoding.b64encode('x'.repeat(MSG_BYTES));

// Custom metrics. The `variant` label is added automatically from the scenario
// tag; we add `op` per call (and `variant` too, defensively) so every series is
// fully qualified.
const reqs = new Counter('plainq_reqs');
const errs = new Counter('plainq_errs');
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
  // Absolute guard rails. The real (relative) AB verdict is produced by
  // scripts/report.py from VictoriaMetrics; these just fail the run on gross
  // breakage so it can gate CI.
  thresholds: {
    'plainq_errs': ['count < 1000'],
    'plainq_latency{op:total}': ['p(95) < 500'],
    'checks': ['rate > 0.95'],
  },
};

// setup runs once. Create one dedicated queue per variant and hand the ids to
// the VU functions.
export function setup() {
  const targets = [
    ['baseline', BASELINE_ADDR],
    ['candidate', CANDIDATE_ADDR],
  ];

  const queues = {};

  for (const [variant, addr] of targets) {
    client.connect(addr, { plaintext: true, timeout: '15s' });

    const res = client.invoke(`${SERVICE}/CreateQueue`, {
      queue_name: `perf-${variant}-${__ENV.RUN_ID || 'local'}`,
      visibility_timeout_seconds: 30,
      max_receive_attempts: 10,
    });

    if (res.status !== grpc.StatusOK) {
      throw new Error(`CreateQueue(${variant}) failed: ${JSON.stringify(res)}`);
    }

    const msg = res.message || {};
    queues[variant] = msg.queueId || msg.queue_id;
    client.close();
  }

  console.log(`queues: baseline=${queues.baseline} candidate=${queues.candidate}`);
  return queues;
}

export function baseline(data) {
  workload(BASELINE_ADDR, 'baseline', data.baseline);
}

export function candidate(data) {
  workload(CANDIDATE_ADDR, 'candidate', data.candidate);
}

// timed invokes fn, records req/err/latency under {variant, op}, and asserts OK.
function timed(variant, op, fn) {
  const t0 = Date.now();
  const res = fn();
  const dt = Date.now() - t0;

  const tags = { variant, op };
  const ok = !!res && res.status === grpc.StatusOK;

  reqs.add(1, tags);
  latency.add(dt, tags);
  if (!ok) {
    errs.add(1, tags);
  }
  check(res, { [`${op} ok`]: (r) => !!r && r.status === grpc.StatusOK }, tags);

  return res;
}

// workload performs one full message lifecycle: Send -> Receive -> Delete.
function workload(addr, variant, queueID) {
  if (!connected) {
    client.connect(addr, { plaintext: true, timeout: '15s' });
    connected = true;
  }

  const t0 = Date.now();

  timed(variant, 'send', () =>
    client.invoke(`${SERVICE}/Send`, {
      queue_id: queueID,
      messages: [{ body: BODY }],
    }),
  );

  const recv = timed(variant, 'receive', () =>
    client.invoke(`${SERVICE}/Receive`, {
      queue_id: queueID,
      batch_size: BATCH_SIZE,
    }),
  );

  const ids = [];
  if (recv && recv.status === grpc.StatusOK && recv.message && recv.message.messages) {
    for (const m of recv.message.messages) {
      ids.push(m.id);
    }
  }

  if (ids.length > 0) {
    timed(variant, 'delete', () =>
      client.invoke(`${SERVICE}/Delete`, {
        queue_id: queueID,
        message_ids: ids,
      }),
    );
  }

  // Record the end-to-end lifecycle latency under op=total.
  latency.add(Date.now() - t0, { variant, op: 'total' });
  reqs.add(1, { variant, op: 'total' });
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
