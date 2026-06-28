#!/usr/bin/env bash
#
# PlainQ AB performance test orchestrator.
#
# Builds two PlainQ server images -- "candidate" (current checkout) and
# "baseline" (a stable git ref) -- brings up the VictoriaMetrics + Grafana
# stack alongside both servers, runs an identical k6 gRPC workload against
# each, then renders a comparison report from VictoriaMetrics.
#
# Usage:
#   perf/scripts/run.sh [BASELINE_REF]
#
# Environment overrides:
#   BASELINE_REF   git ref to use as the baseline      (default: origin/main)
#   VUS            virtual users per variant           (default: 20)
#   DURATION       load duration                       (default: 2m)
#   BATCH_SIZE     receive batch size (1-10)           (default: 1)
#   MSG_BYTES      message body size in bytes          (default: 256)
#   RUN_ID         label for this run                  (default: git short sha)
#   KEEP_UP        keep the stack running afterwards   (default: 1)
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PERF_DIR="${REPO_ROOT}/perf"
COMPOSE="${PERF_DIR}/docker-compose.yml"
WORKTREE="${PERF_DIR}/.baseline"
RESULTS="${PERF_DIR}/results"

BASELINE_REF="${1:-${BASELINE_REF:-origin/main}}"
VUS="${VUS:-20}"
DURATION="${DURATION:-2m}"
BATCH_SIZE="${BATCH_SIZE:-1}"
MSG_BYTES="${MSG_BYTES:-256}"
KEEP_UP="${KEEP_UP:-1}"

CANDIDATE_SHA="$(git -C "${REPO_ROOT}" rev-parse --short HEAD)"
RUN_ID="${RUN_ID:-${CANDIDATE_SHA}}"

export VUS DURATION BATCH_SIZE MSG_BYTES RUN_ID

log() { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
err() { printf '\033[1;31mERR\033[0m %s\n' "$*" >&2; }

dc() { docker compose -f "${COMPOSE}" "$@"; }

cleanup_worktree() {
  if git -C "${REPO_ROOT}" worktree list --porcelain | grep -q "${WORKTREE}"; then
    git -C "${REPO_ROOT}" worktree remove --force "${WORKTREE}" 2>/dev/null || true
  fi
  rm -rf "${WORKTREE}"
}

mkdir -p "${RESULTS}"
# k6 runs as a non-root user in its image; make the bind-mounted results dir
# writable so handleSummary can persist the JSON summary.
chmod 0777 "${RESULTS}" 2>/dev/null || true

# ---------------------------------------------------------------------------
# 1. Resolve and materialize the baseline source tree.
# ---------------------------------------------------------------------------
log "Resolving baseline ref: ${BASELINE_REF}"
git -C "${REPO_ROOT}" fetch --quiet origin 2>/dev/null || log "fetch skipped (offline?)"

if ! git -C "${REPO_ROOT}" rev-parse --verify --quiet "${BASELINE_REF}^{commit}" >/dev/null; then
  err "baseline ref '${BASELINE_REF}' not found"
  exit 1
fi
BASELINE_SHA="$(git -C "${REPO_ROOT}" rev-parse --short "${BASELINE_REF}")"

log "Candidate = ${CANDIDATE_SHA} (HEAD)   Baseline = ${BASELINE_SHA} (${BASELINE_REF})"

cleanup_worktree
log "Creating baseline worktree at ${WORKTREE}"
git -C "${REPO_ROOT}" worktree add --quiet --detach "${WORKTREE}" "${BASELINE_REF}"

# ---------------------------------------------------------------------------
# 2. Build both server images from the shared perf Dockerfile.
# ---------------------------------------------------------------------------
log "Building candidate image (plainq-perf:candidate)"
docker build -f "${PERF_DIR}/Dockerfile.plainq" \
  --build-arg VERSION=candidate --build-arg COMMIT="${CANDIDATE_SHA}" \
  -t plainq-perf:candidate "${REPO_ROOT}"

log "Building baseline image (plainq-perf:baseline)"
docker build -f "${PERF_DIR}/Dockerfile.plainq" \
  --build-arg VERSION=baseline --build-arg COMMIT="${BASELINE_SHA}" \
  -t plainq-perf:baseline "${WORKTREE}"

cleanup_worktree

# ---------------------------------------------------------------------------
# 3. Bring up the stack (infra + both servers; k6 is on-demand).
# ---------------------------------------------------------------------------
log "Starting stack (VictoriaMetrics, Grafana, baseline, candidate)"
dc up -d victoriametrics grafana plainq-baseline plainq-candidate

wait_healthy() {
  local name="$1" port="$2" tries=60
  log "Waiting for ${name} (/health on :${port})"
  until curl -fsS "http://localhost:${port}/health" >/dev/null 2>&1; do
    tries=$((tries - 1))
    if [ "${tries}" -le 0 ]; then
      err "${name} did not become healthy"
      dc logs "${name}" | tail -n 40 || true
      exit 1
    fi
    sleep 1
  done
}

wait_healthy plainq-baseline 18081
wait_healthy plainq-candidate 28081

# ---------------------------------------------------------------------------
# 4. Run the k6 AB workload.
# ---------------------------------------------------------------------------
START_TS="$(date +%s)"
log "Running k6: VUS=${VUS} DURATION=${DURATION} BATCH_SIZE=${BATCH_SIZE} MSG_BYTES=${MSG_BYTES} RUN_ID=${RUN_ID}"
dc run --rm k6
END_TS="$(date +%s)"

# ---------------------------------------------------------------------------
# 5. Render the comparison report from VictoriaMetrics.
# ---------------------------------------------------------------------------
REPORT="${RESULTS}/report-${RUN_ID}.md"
REPORT_RC=0
log "Generating comparison report"
if command -v python3 >/dev/null 2>&1; then
  set +e
  python3 "${PERF_DIR}/scripts/report.py" \
    --vm "http://localhost:8428" \
    --start "${START_TS}" --end "${END_TS}" \
    --run-id "${RUN_ID}" \
    --candidate-sha "${CANDIDATE_SHA}" --baseline-sha "${BASELINE_SHA}" \
    --out "${REPORT}"
  REPORT_RC=$?
  set -e
  echo
  cat "${REPORT}" 2>/dev/null || true
  if [ "${REPORT_RC}" -eq 1 ]; then
    err "Regression detected — see report above."
  fi
else
  err "python3 not found; skipping report. Use Grafana for results."
fi

echo
log "Grafana dashboard:  http://localhost:3000  (PlainQ AB Performance)"
log "VictoriaMetrics:    http://localhost:8428"
log "k6 summary JSON:    ${RESULTS}/summary-${RUN_ID}.json"
log "Comparison report:  ${REPORT}"

if [ "${KEEP_UP}" != "1" ]; then
  log "Tearing down stack (KEEP_UP=0)"
  dc down
else
  log "Stack left running. Stop it with: make -C perf down"
fi

# Preserve report.py's exit status so CI fails on a detected regression
# (report.py exits 1 on regression) even after teardown/footer above.
exit "${REPORT_RC}"
