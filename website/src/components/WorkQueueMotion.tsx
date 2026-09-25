import { interpolate, interpolateColors, useCurrentFrame } from "remotion";
import type { CSSProperties } from "react";
import {
  LoopPlayer,
  alongPath,
  clamp,
  motionEase,
  pulse,
  travelEase,
  useMediaQuery,
  type Point,
} from "./motionKit";
import "./WorkQueueMotion.css";

const DURATION_IN_FRAMES = 390;
const DESKTOP_COMPOSITION = { width: 1200, height: 340 };
const MOBILE_COMPOSITION = { width: 390, height: 270 };
const workers = ["worker 1", "worker 2", "worker 3"];

// One job per loop: delivered to worker 1, not acknowledged before its
// visibility timeout, returned to the queue, then acknowledged by worker 3.
const SEND = [10, 58] as const;
const DISPATCH_FIRST = [96, 146] as const;
const TIMEOUT = [146, 206] as const;
const RETURN = [212, 258] as const;
const DISPATCH_RETRY = [282, 326] as const;
const ACKED = 348;
const SETTLE = [364, 388] as const;

const BORDER = "#dfe3dc";
const ACTIVE_BORDER = "#bfc9ff";
const WARNING_BORDER = "#f1cf9c";
const SUCCESS_BORDER = "#a7dcc7";
const ACCENT = "#315cff";
const WARNING = "#d97706";
const SUCCESS = "#0e9f6e";
const MUTED = "#646a63";
const PACKET_RADIUS = 6;

type WorkQueueMotionProps = {
  compact: boolean;
};

type WorkQueueSceneProps = WorkQueueMotionProps & {
  frame: number;
};

type Routes = {
  incoming: Point[];
  toFirst: Point[];
  toRetry: Point[];
};

const desktopRoutes: Routes = {
  incoming: [[116, 173], [402, 173]],
  toFirst: [[530, 173], [724, 173], [724, 117], [816, 117]],
  toRetry: [[530, 173], [724, 173], [724, 229], [816, 229]],
};

const compactRoutes: Routes = {
  incoming: [[195, 65], [195, 85]],
  toFirst: [[195, 149], [195, 169], [76, 169], [76, 181]],
  toRetry: [[195, 149], [195, 169], [314, 169], [314, 181]],
};

const ease = (frame: number, range: readonly [number, number]) =>
  interpolate(frame, range, [0, 1], { ...clamp, easing: motionEase });

const visible = (frame: number, range: readonly [number, number]) =>
  interpolate(frame, [range[0] - 4, range[0] + 4, range[1] - 4, range[1] + 4], [0, 1, 1, 0], clamp);

function packetStyle(
  frame: number,
  route: readonly Point[],
  range: readonly [number, number],
  reverse = false,
): CSSProperties {
  const progress = interpolate(frame, range, [0, 1], { ...clamp, easing: travelEase });
  const [x, y] = alongPath(route, reverse ? 1 - progress : progress);

  return {
    translate: `${x - PACKET_RADIUS}px ${y - PACKET_RADIUS}px`,
    opacity: visible(frame, range),
  };
}

function workerState(frame: number, index: number) {
  if (index === 0) {
    const active =
      ease(frame, [DISPATCH_FIRST[1] - 8, DISPATCH_FIRST[1] + 8]) *
      (1 - ease(frame, [RETURN[0] + 20, RETURN[1] + 10]));
    const warning = ease(frame, [TIMEOUT[1] - 6, TIMEOUT[1] + 6]);
    const label =
      frame >= TIMEOUT[1] && frame < RETURN[1] + 6
        ? "timed out"
        : frame >= DISPATCH_FIRST[1] && frame < TIMEOUT[1]
          ? "processing"
          : "idle";

    return {
      active,
      tone: interpolateColors(warning, [0, 1], [ACCENT, WARNING]),
      border: interpolateColors(warning, [0, 1], [ACTIVE_BORDER, WARNING_BORDER]),
      progress: interpolate(frame, TIMEOUT, [0, 1], clamp),
      label,
    };
  }

  if (index === 2) {
    const active =
      ease(frame, [DISPATCH_RETRY[1] - 8, DISPATCH_RETRY[1] + 8]) * (1 - ease(frame, SETTLE));
    const done = ease(frame, [ACKED - 6, ACKED + 6]);
    const label =
      frame >= ACKED && frame < SETTLE[1] - 8
        ? "acked"
        : frame >= DISPATCH_RETRY[1] && frame < SETTLE[1] - 8
          ? "processing"
          : "idle";

    return {
      active,
      tone: interpolateColors(done, [0, 1], [ACCENT, SUCCESS]),
      border: interpolateColors(done, [0, 1], [ACTIVE_BORDER, SUCCESS_BORDER]),
      progress: interpolate(frame, [DISPATCH_RETRY[1], ACKED], [0, 1], clamp),
      label,
    };
  }

  return { active: 0, tone: ACCENT, border: ACTIVE_BORDER, progress: 0, label: "idle" };
}

function WorkQueueScene({ compact, frame }: WorkQueueSceneProps) {
  const routes = compact ? compactRoutes : desktopRoutes;

  const queueLevel = interpolate(
    frame,
    [
      SEND[1] - 4,
      SEND[1] + 20,
      DISPATCH_FIRST[0],
      DISPATCH_FIRST[0] + 20,
      RETURN[1] - 4,
      RETURN[1] + 20,
      DISPATCH_RETRY[0],
      DISPATCH_RETRY[0] + 20,
    ],
    [0.72, 1, 1, 0.72, 0.72, 1, 1, 0.72],
    { ...clamp, easing: motionEase },
  );
  const queueGlow = Math.max(
    interpolate(frame, [SEND[1] - 4, SEND[1] + 12, DISPATCH_FIRST[0] + 10, DISPATCH_FIRST[0] + 36], [0, 1, 1, 0], clamp),
    interpolate(frame, [RETURN[1] - 4, RETURN[1] + 12, DISPATCH_RETRY[0] + 10, DISPATCH_RETRY[0] + 36], [0, 1, 1, 0], clamp),
  );
  const retryTag = interpolate(frame, [RETURN[1] - 2, RETURN[1] + 12, SETTLE[0], SETTLE[1]], [0, 1, 1, 0], {
    ...clamp,
    easing: motionEase,
  });

  return (
    <div className={`work-queue-motion__scene${compact ? " is-compact" : ""}`}>
      <div
        className="work-queue-motion__node work-queue-motion__app"
        style={{
          borderColor: interpolateColors(
            interpolate(frame, [4, 12, 40, 64], [0, 1, 1, 0], clamp),
            [0, 1],
            [BORDER, ACTIVE_BORDER],
          ),
        }}
      >
        app
      </div>
      <span className="work-queue-motion__rail work-queue-motion__rail--in" />

      <div
        className="work-queue-motion__queue"
        style={{
          borderColor: interpolateColors(queueGlow, [0, 1], [BORDER, ACTIVE_BORDER]),
          boxShadow: `0 14px 30px rgba(49, 92, 255, ${queueGlow * 0.11})`,
        }}
      >
        <span
          className="work-queue-motion__job-bar work-queue-motion__job-bar--one"
          style={{ scale: `${queueLevel} 1` }}
        />
        <span
          className="work-queue-motion__job-bar work-queue-motion__job-bar--two"
          style={{ scale: `${queueLevel * 0.92} 1` }}
        />
        <span
          className="work-queue-motion__job-bar work-queue-motion__job-bar--three"
          style={{ scale: `${queueLevel * 0.84} 1` }}
        />
        <span className="work-queue-motion__jobs-label">jobs</span>
        <span
          className="work-queue-motion__retry"
          style={{ opacity: retryTag, translate: `0 ${(1 - retryTag) * 4}px` }}
        >
          attempt 2
        </span>
      </div>

      <span className="work-queue-motion__rail work-queue-motion__rail--out" />
      <span className="work-queue-motion__bus" />
      {workers.map((worker, index) => (
        <span
          className={`work-queue-motion__branch work-queue-motion__branch--${index}`}
          key={worker}
        />
      ))}

      <div className="work-queue-motion__workers">
        {workers.map((worker, index) => {
          const state = workerState(frame, index);

          return (
            <span
              className="work-queue-motion__worker"
              key={worker}
              style={{
                borderColor: interpolateColors(state.active, [0, 1], [BORDER, state.border]),
                backgroundColor: `rgba(49, 92, 255, ${state.active * 0.025})`,
                boxShadow: `0 8px 18px rgba(17, 19, 16, ${state.active * 0.06})`,
                color: interpolateColors(state.active, [0, 1], [MUTED, state.tone]),
              }}
            >
              <span className="work-queue-motion__worker-name">{worker}</span>
              <span className="work-queue-motion__worker-status" style={{ opacity: 0.45 + state.active * 0.55 }}>
                <span
                  className="work-queue-motion__worker-light"
                  style={{
                    backgroundColor: interpolateColors(state.active, [0, 1], ["#c4c9c1", state.tone]),
                    boxShadow:
                      state.label === "processing"
                        ? `0 0 0 ${1 + pulse(frame, 24) * 3}px rgba(49, 92, 255, 0.14)`
                        : "none",
                  }}
                />
                {state.label}
              </span>
              <span
                className="work-queue-motion__worker-progress"
                style={{
                  scale: `${state.progress} 1`,
                  opacity: state.active,
                  backgroundColor: state.tone,
                }}
              />
            </span>
          );
        })}
      </div>

      <span className="work-queue-motion__packet" style={packetStyle(frame, routes.incoming, SEND)} />
      <span className="work-queue-motion__packet" style={packetStyle(frame, routes.toFirst, DISPATCH_FIRST)} />
      <span
        className="work-queue-motion__packet is-warning"
        style={packetStyle(frame, routes.toFirst, RETURN, true)}
      />
      <span className="work-queue-motion__packet" style={packetStyle(frame, routes.toRetry, DISPATCH_RETRY)} />
    </div>
  );
}

function WorkQueueComposition({ compact }: WorkQueueMotionProps) {
  const frame = useCurrentFrame();

  return <WorkQueueScene compact={compact} frame={frame} />;
}

export default function WorkQueueMotion() {
  const compact = useMediaQuery("(max-width: 560px)");
  const prefersReducedMotion = useMediaQuery("(prefers-reduced-motion: reduce)");
  const composition = compact ? MOBILE_COMPOSITION : DESKTOP_COMPOSITION;

  return (
    <div
      className={`work-queue-motion${compact ? " is-compact" : ""}`}
      role="img"
      aria-label="An app sends one job to a queue. Worker 1 does not acknowledge it before the visibility timeout, so the job returns to the queue and worker 3 processes and acknowledges it."
    >
      {prefersReducedMotion ? (
        <div className="work-queue-motion__static">
          <WorkQueueScene compact={compact} frame={ACKED + 8} />
        </div>
      ) : (
        <LoopPlayer
          component={WorkQueueComposition}
          inputProps={{ compact }}
          durationInFrames={DURATION_IN_FRAMES}
          width={composition.width}
          height={composition.height}
          className="work-queue-motion__player"
        />
      )}
    </div>
  );
}
