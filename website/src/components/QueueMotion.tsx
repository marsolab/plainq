import { interpolate, interpolateColors, useCurrentFrame } from "remotion";
import type { CSSProperties } from "react";
import {
  LoopPlayer,
  clamp,
  motionEase,
  pulse,
  travelEase,
  useMediaQuery,
} from "./motionKit";
import "./QueueMotion.css";

const DURATION_IN_FRAMES = 300;
const DESKTOP_COMPOSITION = { width: 1200, height: 462 };
const MOBILE_COMPOSITION = { width: 390, height: 562 };

// One job_4021 lifecycle per loop. Frame 0 and frame 300 render the same
// state, so the loop restarts without a visible jump.
const SEND = [14, 62] as const;
const ENQUEUED = 60;
const DISPATCH = [112, 164] as const;
const PROCESS = [164, 222] as const;
const ACK = [222, 256] as const;
const SETTLE = [268, 296] as const;

const ACCENT = "#315cff";
const SUCCESS = "#0e9f6e";
const BORDER = "#dfe3dc";
const ACTIVE_BORDER = "#bfc9ff";
const JOB_WIDTH = 18;

type QueueMotionProps = {
  compact: boolean;
};

type QueueFlowProps = QueueMotionProps & {
  frame: number;
};

const formatCount = (value: number) => String(value).padStart(2, "0");

const ease = (frame: number, range: readonly [number, number]) =>
  interpolate(frame, range, [0, 1], { ...clamp, easing: motionEase });

const travel = (frame: number, range: readonly [number, number]) =>
  interpolate(frame, range, [0, 1], { ...clamp, easing: travelEase });

function Counter({
  frame,
  steps,
}: {
  frame: number;
  steps: readonly (readonly [number, number])[];
}) {
  let index = 0;
  while (index + 1 < steps.length && frame >= steps[index + 1][0]) index += 1;

  const [at, value] = steps[index];
  const previous = index > 0 ? steps[index - 1][1] : value;
  const progress = index > 0 ? ease(frame, [at, at + 16]) : 1;

  return (
    <strong className="queue-motion__count">
      {progress < 1 ? (
        <span style={{ translate: `0 ${-progress * 100}%`, opacity: 1 - progress }}>
          {formatCount(previous)}
        </span>
      ) : null}
      <span
        style={{
          translate: `0 ${(1 - progress) * 100}%`,
          opacity: progress,
          position: progress < 1 ? "absolute" : undefined,
        }}
      >
        {formatCount(value)}
      </span>
    </strong>
  );
}

function Packet({
  compact,
  progress,
  opacity,
  reverse = false,
  tone = "accent",
}: {
  compact: boolean;
  progress: number;
  opacity: number;
  reverse?: boolean;
  tone?: "accent" | "success";
}) {
  const offset = reverse ? 1 - progress : progress;
  const position = `calc(${offset} * (100% - 16px))`;
  const style: CSSProperties = compact
    ? { top: position, opacity }
    : { left: position, opacity };

  return (
    <span
      className={`queue-motion__packet${tone === "success" ? " is-success" : ""}`}
      style={style}
    />
  );
}

function Trace({
  compact,
  progress,
  opacity,
  reverse = false,
  tone = "accent",
}: {
  compact: boolean;
  progress: number;
  opacity: number;
  reverse?: boolean;
  tone?: "accent" | "success";
}) {
  return (
    <span
      className={`queue-motion__trace${reverse ? " is-reverse" : ""}${
        tone === "success" ? " is-success" : ""
      }`}
      style={{
        scale: compact ? `1 ${progress}` : `${progress} 1`,
        opacity,
      }}
    />
  );
}

function QueueFlow({ compact, frame }: QueueFlowProps) {
  const send = travel(frame, SEND);
  const dispatch = travel(frame, DISPATCH);
  const ack = travel(frame, ACK);
  const settle = ease(frame, SETTLE);

  const producerActive = interpolate(frame, [8, 18, 44, 70], [0, 1, 1, 0], clamp);
  const queueActive =
    interpolate(frame, [ENQUEUED - 4, ENQUEUED + 20], [0, 1], {
      ...clamp,
      easing: motionEase,
    }) *
    (1 - settle);
  const workerActive =
    ease(frame, [DISPATCH[1] - 10, DISPATCH[1] + 8]) *
    (1 - ease(frame, [ACK[0] + 22, SETTLE[0] + 8]));
  const workerDone = ease(frame, [ACK[0] + 4, ACK[0] + 18]) * (1 - settle);

  const readyWidth = interpolate(
    frame,
    [ENQUEUED, ENQUEUED + 22, DISPATCH[0], DISPATCH[0] + 22],
    [3, 4, 4, 3],
    { ...clamp, easing: motionEase },
  ) * JOB_WIDTH;
  const inFlightWidth = interpolate(
    frame,
    [DISPATCH[0], DISPATCH[0] + 22, ACK[1] - 6, ACK[1] + 16],
    [0, 1, 1, 0],
    { ...clamp, easing: motionEase },
  ) * JOB_WIDTH;

  const enqueuedEvent = ease(frame, [ENQUEUED, ENQUEUED + 18]) * (1 - settle);
  const receivedEvent = ease(frame, [DISPATCH[1], DISPATCH[1] + 18]) * (1 - settle);
  const ackEvent = ease(frame, [ACK[1] - 4, ACK[1] + 14]) * (1 - settle);

  const processProgress = interpolate(frame, PROCESS, [0, 1], clamp);
  const workerStatus =
    frame >= ACK[0] + 8 && frame < SETTLE[0] + 4
      ? "acknowledged"
      : frame >= DISPATCH[1] && frame < SETTLE[0] + 4
        ? "processing"
        : "ready";

  const events = [
    {
      value: enqueuedEvent,
      time: "09:41:02.114",
      name: "enqueued",
      detail: "attempt 1",
      tone: ACCENT,
    },
    {
      value: receivedEvent,
      time: "09:41:02.290",
      name: "received",
      detail: "worker-01",
      tone: ACCENT,
    },
    {
      value: ackEvent,
      time: "09:41:02.466",
      name: "acknowledged",
      detail: "176 ms",
      tone: SUCCESS,
    },
  ];

  return (
    <div className={`queue-motion__scene${compact ? " is-compact" : ""}`}>
      <div className="queue-motion__titlebar">
        <div className="queue-motion__title">
          <span
            className="queue-motion__status-dot"
            style={{
              boxShadow: `0 0 0 ${3 + pulse(frame, 60) * 4}px rgba(14, 159, 110, ${
                0.16 - pulse(frame, 60) * 0.08
              })`,
            }}
          />
          <span>queue / media-jobs</span>
        </div>
        <div className="queue-motion__health">healthy</div>
      </div>

      <div className="queue-motion__map">
        <div
          className="queue-motion__node queue-motion__producer"
          style={{
            borderColor: interpolateColors(producerActive, [0, 1], [BORDER, ACTIVE_BORDER]),
          }}
        >
          <span className="queue-motion__label">Producer</span>
          <strong>send()</strong>
          <code>job_4021</code>
        </div>

        <div className="queue-motion__rail queue-motion__rail--in" aria-hidden="true">
          <Trace
            compact={compact}
            progress={send}
            opacity={interpolate(frame, [SEND[0], SEND[0] + 6, SEND[1], SEND[1] + 24], [0, 1, 1, 0], clamp)}
          />
          <svg className="queue-motion__arrow" viewBox="0 0 16 16" fill="none">
            <path d="M3 8h8M8 4l4 4-4 4" />
          </svg>
          <Packet
            compact={compact}
            progress={send}
            opacity={interpolate(frame, [SEND[0] - 4, SEND[0] + 4, SEND[1] - 4, SEND[1] + 4], [0, 1, 1, 0], clamp)}
          />
        </div>

        <div
          className="queue-motion__queue"
          style={{
            borderColor: interpolateColors(queueActive, [0, 1], [BORDER, ACTIVE_BORDER]),
            boxShadow: `0 14px ${28 + queueActive * 12}px rgba(17, 19, 16, ${
              0.055 + queueActive * 0.04
            })`,
          }}
        >
          <div className="queue-motion__queue-head">
            <span>media-jobs</span>
            <span
              className="queue-motion__state"
              style={{
                scale: interpolate(
                  frame,
                  [ENQUEUED - 2, ENQUEUED + 8, ENQUEUED + 24],
                  [1, 1.08, 1],
                  { ...clamp, easing: motionEase },
                ),
              }}
            >
              ready
            </span>
          </div>
          <div className="queue-motion__numbers">
            <div>
              <Counter frame={frame} steps={[[0, 3], [ENQUEUED, 4], [DISPATCH[0], 3]]} />
              <span>ready</span>
            </div>
            <div>
              <Counter frame={frame} steps={[[0, 0], [DISPATCH[0], 1], [ACK[1], 0]]} />
              <span>in flight</span>
            </div>
            <div>
              <Counter frame={frame} steps={[[0, 0]]} />
              <span>dead</span>
            </div>
          </div>
          <div className="queue-motion__bar">
            <span className="queue-motion__bar-ready" style={{ width: `${readyWidth}%` }} />
            <span className="queue-motion__bar-flight" style={{ width: `${inFlightWidth}%` }} />
          </div>
        </div>

        {!compact ? (
          <>
            <div className="queue-motion__rail queue-motion__rail--out" aria-hidden="true">
              <Trace
                compact={compact}
                progress={dispatch}
                opacity={interpolate(
                  frame,
                  [DISPATCH[0], DISPATCH[0] + 6, DISPATCH[1], DISPATCH[1] + 24],
                  [0, 1, 1, 0],
                  clamp,
                )}
              />
              <Trace
                compact={compact}
                progress={ack}
                reverse
                tone="success"
                opacity={interpolate(frame, [ACK[0], ACK[0] + 6, ACK[1], ACK[1] + 24], [0, 1, 1, 0], clamp)}
              />
              <svg className="queue-motion__arrow" viewBox="0 0 16 16" fill="none">
                <path d="M3 8h8M8 4l4 4-4 4" />
              </svg>
              <Packet
                compact={compact}
                progress={dispatch}
                opacity={interpolate(
                  frame,
                  [DISPATCH[0] - 4, DISPATCH[0] + 4, DISPATCH[1] - 4, DISPATCH[1] + 4],
                  [0, 1, 1, 0],
                  clamp,
                )}
              />
              <Packet
                compact={compact}
                progress={ack}
                reverse
                tone="success"
                opacity={interpolate(frame, [ACK[0] - 4, ACK[0] + 4, ACK[1] - 4, ACK[1] + 4], [0, 1, 1, 0], clamp)}
              />
            </div>
            <div className="queue-motion__workers">
              <div
                className="queue-motion__node queue-motion__worker"
                style={{
                  borderColor: interpolateColors(
                    Math.max(workerActive, workerDone),
                    [0, 1],
                    [BORDER, interpolateColors(workerDone, [0, 1], [ACTIVE_BORDER, "#a7dcc7"])],
                  ),
                }}
              >
                <span
                  className="queue-motion__worker-light"
                  style={{
                    backgroundColor: interpolateColors(
                      Math.max(workerActive, workerDone),
                      [0, 1],
                      ["#a9aea7", SUCCESS],
                    ),
                    boxShadow: `0 0 0 ${workerActive * (2 + pulse(frame - PROCESS[0], 30) * 4)}px rgba(14, 159, 110, 0.12)`,
                  }}
                />
                <span>
                  <span className="queue-motion__label">Worker 01</span>
                  <strong>{workerStatus}</strong>
                </span>
                <span
                  className="queue-motion__worker-progress"
                  style={{
                    scale: `${processProgress} 1`,
                    opacity: workerActive,
                    backgroundColor: interpolateColors(workerDone, [0, 1], [ACCENT, SUCCESS]),
                  }}
                />
              </div>
              <div className="queue-motion__node queue-motion__worker">
                <span className="queue-motion__worker-light" />
                <span>
                  <span className="queue-motion__label">Worker 02</span>
                  <strong>ready</strong>
                </span>
              </div>
            </div>
          </>
        ) : null}
      </div>

      <div className="queue-motion__events">
        {events.map((event) => (
          <div
            className="queue-motion__event"
            key={event.name}
            style={{
              opacity: 0.42 + event.value * 0.58,
              backgroundColor: interpolateColors(
                event.value,
                [0, 1],
                ["rgba(255, 255, 255, 0)", event.tone === SUCCESS ? "rgba(14, 159, 110, 0.05)" : "rgba(49, 92, 255, 0.045)"],
              ),
              boxShadow: `inset 0 ${compact ? 0 : 2}px 0 ${interpolateColors(
                event.value,
                [0, 1],
                ["rgba(0, 0, 0, 0)", event.tone],
              )}`,
            }}
          >
            <time>{event.time}</time>
            <span
              className={`queue-motion__event-name${event.tone === SUCCESS ? " is-success" : ""}`}
              style={{ translate: `${(1 - event.value) * -4}px 0` }}
            >
              {event.name}
            </span>
            <code>job_4021</code>
            <span>{event.detail}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function QueueMotionComposition({ compact }: QueueMotionProps) {
  const frame = useCurrentFrame();

  return <QueueFlow compact={compact} frame={frame} />;
}

export default function QueueMotion() {
  const compact = useMediaQuery("(max-width: 620px)");
  const prefersReducedMotion = useMediaQuery("(prefers-reduced-motion: reduce)");
  const composition = compact ? MOBILE_COMPOSITION : DESKTOP_COMPOSITION;

  return (
    <div
      className="queue-motion"
      role="img"
      aria-label="A producer sends job 4021 into the media-jobs queue, a worker receives and processes it, and the queue records the acknowledgement."
    >
      {prefersReducedMotion ? (
        <QueueFlow compact={compact} frame={ACK[1] + 10} />
      ) : (
        <LoopPlayer
          component={QueueMotionComposition}
          inputProps={{ compact }}
          durationInFrames={DURATION_IN_FRAMES}
          width={composition.width}
          height={composition.height}
          className="queue-motion__player"
        />
      )}
    </div>
  );
}
