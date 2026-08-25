import { Player } from "@remotion/player";
import { Easing, interpolate, useCurrentFrame } from "remotion";
import { useEffect, useState, type CSSProperties } from "react";
import "./QueueMotion.css";

const FPS = 30;
const DURATION_IN_FRAMES = 300;
const DESKTOP_COMPOSITION = { width: 1200, height: 500 };
const MOBILE_COMPOSITION = { width: 390, height: 590 };

type QueueMotionProps = {
  compact: boolean;
};

type QueueFlowProps = QueueMotionProps & {
  frame: number;
};

const clamp = {
  extrapolateLeft: "clamp" as const,
  extrapolateRight: "clamp" as const,
};

const formatCount = (value: number) => String(value).padStart(2, "0");

function useMediaQuery(query: string) {
  const [matches, setMatches] = useState(false);

  useEffect(() => {
    const mediaQuery = window.matchMedia(query);
    const update = () => setMatches(mediaQuery.matches);

    update();
    mediaQuery.addEventListener("change", update);

    return () => mediaQuery.removeEventListener("change", update);
  }, [query]);

  return matches;
}

function QueueFlow({ compact, frame }: QueueFlowProps) {
  const queueActivation = interpolate(frame, [64, 104], [0, 1], {
    ...clamp,
    easing: Easing.spring({ damping: 200 }),
  });
  const dispatchProgress = interpolate(frame, [132, 196], [0, 1], {
    ...clamp,
    easing: Easing.bezier(0.16, 1, 0.3, 1),
  });
  const acknowledgement = interpolate(frame, [210, 248], [0, 1], {
    ...clamp,
    easing: Easing.bezier(0.16, 1, 0.3, 1),
  });
  const readyCount = Math.round(
    interpolate(frame, [0, 64, 88], [3, 3, 4], clamp),
  );
  const queueBar = interpolate(
    frame,
    [0, 64, 104, 210, 248],
    [54, 54, 72, 72, 100],
    {
      ...clamp,
      easing: Easing.bezier(0.16, 1, 0.3, 1),
    },
  );
  const eventOne = interpolate(frame, [4, 22], [0.55, 1], clamp);
  const eventTwo = interpolate(frame, [42, 74], [0.7, 1], clamp);
  const eventThree = interpolate(frame, [192, 230], [0.65, 1], clamp);

  const packetStyle: CSSProperties = compact
    ? {
        top: `${interpolate(frame, [18, 74], [0, 84], clamp)}%`,
        opacity: interpolate(frame, [12, 20, 70, 82], [0, 1, 1, 0], clamp),
      }
    : {
        left: `${interpolate(frame, [18, 74], [0, 94], clamp)}%`,
        opacity: interpolate(frame, [12, 20, 70, 82], [0, 1, 1, 0], clamp),
      };

  return (
    <div className={`queue-motion__scene${compact ? " is-compact" : ""}`}>
      <div className="queue-motion__titlebar">
        <div className="queue-motion__title">
          <span
            className="queue-motion__status-dot"
            style={{
              boxShadow: `0 0 0 ${interpolate(
                frame,
                [0, 28, 56, 84],
                [4, 7, 4, 4],
                clamp,
              )}px rgba(14, 159, 110, 0.11)`,
            }}
          />
          <span>queue / media-jobs</span>
        </div>
        <div className="queue-motion__health">healthy</div>
      </div>

      <div className="queue-motion__map">
        <div className="queue-motion__node queue-motion__producer">
          <span className="queue-motion__label">Producer</span>
          <strong>send()</strong>
          <code>job_4021</code>
        </div>

        <div className="queue-motion__rail queue-motion__rail--in" aria-hidden="true">
          <svg className="queue-motion__arrow" viewBox="0 0 16 16" fill="none">
            <path d="M3 8h8M8 4l4 4-4 4" />
          </svg>
          <span className="queue-motion__packet" style={packetStyle} />
        </div>

        <div
          className="queue-motion__queue"
          style={{
            borderColor:
              queueActivation > 0.75 ? "#bfc9ff" : "var(--color-border)",
            boxShadow: `0 14px ${interpolate(
              frame,
              [58, 104],
              [28, 38],
              clamp,
            )}px rgba(17, 19, 16, ${interpolate(
              frame,
              [58, 104],
              [0.055, 0.095],
              clamp,
            )})`,
          }}
        >
          <div className="queue-motion__queue-head">
            <span>media-jobs</span>
            <span
              className="queue-motion__state"
              style={{
                opacity: interpolate(frame, [52, 76], [0.62, 1], clamp),
                scale: interpolate(frame, [52, 76], [0.94, 1], {
                  ...clamp,
                  output: "perceptual-scale",
                }),
              }}
            >
              ready
            </span>
          </div>
          <div className="queue-motion__numbers">
            <div>
              <strong>{formatCount(readyCount)}</strong>
              <span>ready</span>
            </div>
            <div>
              <strong>01</strong>
              <span>in flight</span>
            </div>
            <div>
              <strong>00</strong>
              <span>dead</span>
            </div>
          </div>
          <div className="queue-motion__bar">
            <span style={{ width: `${queueBar}%` }} />
          </div>
        </div>

        {!compact ? (
          <>
            <div className="queue-motion__rail queue-motion__rail--out" aria-hidden="true">
              <svg className="queue-motion__arrow" viewBox="0 0 16 16" fill="none">
                <path d="M3 8h8M8 4l4 4-4 4" />
              </svg>
              <span
                className="queue-motion__packet"
                style={{
                  left: `${interpolate(frame, [132, 196], [0, 100], clamp)}%`,
                  translate: `${interpolate(frame, [132, 196], [0, -29], clamp)}px 0`,
                  opacity: interpolate(
                    frame,
                    [126, 136, 192, 204],
                    [0, 1, 1, 0],
                    clamp,
                  ),
                }}
              />
            </div>
            <div className="queue-motion__workers">
              <div
                className="queue-motion__node queue-motion__worker is-active"
                style={{
                  borderColor:
                    dispatchProgress > 0.72 ? "#bfc9ff" : "var(--color-border)",
                }}
              >
                <span
                  className="queue-motion__worker-light"
                  style={{
                    boxShadow: `0 0 0 ${interpolate(
                      frame,
                      [136, 168, 200, 232],
                      [0, 5, 3, 5],
                      clamp,
                    )}px rgba(14, 159, 110, 0.1)`,
                  }}
                />
                <span>
                  <span className="queue-motion__label">Worker 01</span>
                  <strong>processing</strong>
                </span>
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
        <div
          className="queue-motion__event"
          style={{
            opacity: eventOne,
            translate: `0 ${interpolate(frame, [0, 22], [6, 0], clamp)}px`,
          }}
        >
          <time>09:41:02.114</time>
          <span className="queue-motion__event-name">received</span>
          <code>job_4020</code>
          <span>worker-01</span>
        </div>
        <div
          className="queue-motion__event"
          style={{
            opacity: eventTwo,
            translate: `0 ${interpolate(frame, [42, 74], [8, 0], clamp)}px`,
            backgroundColor:
              queueActivation > 0.75 ? "rgba(49, 92, 255, 0.035)" : "transparent",
          }}
        >
          <time>09:41:02.290</time>
          <span className="queue-motion__event-name">enqueued</span>
          <code>job_4021</code>
          <span>attempt 1</span>
        </div>
        <div
          className="queue-motion__event"
          style={{
            opacity: eventThree,
            translate: `0 ${interpolate(frame, [192, 230], [8, 0], clamp)}px`,
            backgroundColor:
              acknowledgement > 0.75 ? "rgba(14, 159, 110, 0.035)" : "transparent",
          }}
        >
          <time>09:41:03.008</time>
          <span className="queue-motion__event-name is-success">acknowledged</span>
          <code>job_4020</code>
          <span>176 ms</span>
        </div>
      </div>
    </div>
  );
}

function QueueMotionComposition({ compact }: QueueMotionProps) {
  const frame = useCurrentFrame();

  return <QueueFlow compact={compact} frame={frame} />;
}

function QueueStatic({ compact }: QueueMotionProps) {
  return <QueueFlow compact={compact} frame={248} />;
}

export default function QueueMotion() {
  const compact = useMediaQuery("(max-width: 620px)");
  const prefersReducedMotion = useMediaQuery("(prefers-reduced-motion: reduce)");
  const composition = compact ? MOBILE_COMPOSITION : DESKTOP_COMPOSITION;

  return (
    <div
      className="queue-motion"
      role="img"
      aria-label="A producer sends job 4021 into the media-jobs queue, which becomes ready for a worker and is acknowledged."
    >
      {prefersReducedMotion ? (
        <QueueStatic compact={compact} />
      ) : (
        <div aria-hidden="true">
          <Player
            component={QueueMotionComposition}
            inputProps={{ compact }}
            durationInFrames={DURATION_IN_FRAMES}
            fps={FPS}
            compositionWidth={composition.width}
            compositionHeight={composition.height}
            numberOfSharedAudioTags={0}
            autoPlay
            initiallyMuted
            loop
            controls={false}
            clickToPlay={false}
            doubleClickToFullscreen={false}
            spaceKeyToPlayOrPause={false}
            allowFullscreen={false}
            className="queue-motion__player"
            style={{ width: "100%" }}
          />
        </div>
      )}
    </div>
  );
}
