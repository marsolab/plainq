import { Player } from "@remotion/player";
import { Easing, interpolate, useCurrentFrame } from "remotion";
import { useEffect, useState, type CSSProperties } from "react";
import "./WorkQueueMotion.css";

const FPS = 30;
const DURATION_IN_FRAMES = 300;
const DESKTOP_COMPOSITION = { width: 1200, height: 340 };
const MOBILE_COMPOSITION = { width: 390, height: 270 };

type WorkQueueMotionProps = {
  compact: boolean;
};

type WorkQueueSceneProps = WorkQueueMotionProps & {
  frame: number;
};

const clamp = {
  extrapolateLeft: "clamp" as const,
  extrapolateRight: "clamp" as const,
};

const motionEase = Easing.bezier(0.16, 1, 0.3, 1);

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

function WorkQueueScene({ compact, frame }: WorkQueueSceneProps) {
  const queueLevel = interpolate(
    frame,
    [0, 58, 86, 154, 212, 276, 300],
    [0.72, 0.72, 1, 0.56, 0.56, 1, 0.72],
    { ...clamp, easing: motionEase },
  );
  const queueGlow = interpolate(
    frame,
    [54, 82, 196, 228, 276],
    [0, 1, 0.22, 0.2, 1],
    { ...clamp, easing: motionEase },
  );
  const activeWorker = interpolate(
    frame,
    [146, 172, 216, 244],
    [0, 1, 1, 0],
    { ...clamp, easing: motionEase },
  );

  const incomingPacket: CSSProperties = compact
    ? {
        left: "190px",
        top: `${interpolate(frame, [8, 64], [59, 82], {
          ...clamp,
          easing: motionEase,
        })}px`,
        opacity: interpolate(frame, [2, 10, 58, 66], [0, 1, 1, 0], clamp),
      }
    : {
        left: `${interpolate(frame, [8, 64], [116, 392], {
          ...clamp,
          easing: motionEase,
        })}px`,
        top: "169px",
        opacity: interpolate(frame, [2, 10, 58, 66], [0, 1, 1, 0], clamp),
      };

  const dispatchPacket: CSSProperties = compact
    ? {
        left: `${interpolate(frame, [102, 160, 182], [190, 74, 74], {
          ...clamp,
          easing: motionEase,
        })}px`,
        top: `${interpolate(frame, [102, 160, 182], [151, 174, 174], {
          ...clamp,
          easing: motionEase,
        })}px`,
        opacity: interpolate(frame, [94, 104, 178, 186], [0, 1, 1, 0], clamp),
      }
    : {
        left: `${interpolate(frame, [102, 162, 182], [532, 808, 808], {
          ...clamp,
          easing: motionEase,
        })}px`,
        top: `${interpolate(frame, [102, 162, 182], [169, 169, 114], {
          ...clamp,
          easing: motionEase,
        })}px`,
        opacity: interpolate(frame, [94, 104, 178, 186], [0, 1, 1, 0], clamp),
      };

  const returnPacket: CSSProperties = compact
    ? {
        left: `${interpolate(frame, [218, 236, 278], [74, 190, 190], {
          ...clamp,
          easing: motionEase,
        })}px`,
        top: `${interpolate(frame, [218, 236, 278], [174, 151, 151], {
          ...clamp,
          easing: motionEase,
        })}px`,
        opacity: interpolate(frame, [212, 222, 272, 284], [0, 1, 1, 0], clamp),
      }
    : {
        left: `${interpolate(frame, [218, 236, 278], [808, 808, 532], {
          ...clamp,
          easing: motionEase,
        })}px`,
        top: `${interpolate(frame, [218, 236, 278], [114, 169, 169], {
          ...clamp,
          easing: motionEase,
        })}px`,
        opacity: interpolate(frame, [212, 222, 272, 284], [0, 1, 1, 0], clamp),
      };

  return (
    <div className={`work-queue-motion__scene${compact ? " is-compact" : ""}`}>
      <div className="work-queue-motion__node work-queue-motion__app">app</div>
      <span className="work-queue-motion__rail work-queue-motion__rail--in" />

      <div
        className="work-queue-motion__queue"
        style={{
          borderColor: queueGlow > 0.5 ? "#bfc9ff" : "var(--color-border)",
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
      </div>

      <span className="work-queue-motion__rail work-queue-motion__rail--out" />

      <div className="work-queue-motion__workers">
        {['worker 1', 'worker 2', 'worker 3'].map((worker, index) => (
          <span
            className={`work-queue-motion__worker${index === 0 ? " is-active" : ""}`}
            key={worker}
            style={
              index === 0
                ? {
                    borderColor:
                      activeWorker > 0.5 ? "#bfc9ff" : "var(--color-border)",
                    backgroundColor: `rgba(49, 92, 255, ${activeWorker * 0.035})`,
                    boxShadow: `0 8px 18px rgba(49, 92, 255, ${activeWorker * 0.08})`,
                    color:
                      activeWorker > 0.5
                        ? "var(--color-accent)"
                        : "var(--color-muted-foreground)",
                  }
                : undefined
            }
          >
            {worker}
          </span>
        ))}
      </div>

      <span className="work-queue-motion__packet" style={incomingPacket} />
      <span className="work-queue-motion__packet" style={dispatchPacket} />
      <span className="work-queue-motion__packet" style={returnPacket} />
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
      aria-label="An app sends one job to a queue, which delivers it to one worker and returns it to the queue when it is not acknowledged."
    >
      {prefersReducedMotion ? (
        <div className="work-queue-motion__static">
          <WorkQueueScene compact={compact} frame={190} />
        </div>
      ) : (
        <div aria-hidden="true">
          <Player
            component={WorkQueueComposition}
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
            className="work-queue-motion__player"
            style={{ width: "100%" }}
          />
        </div>
      )}
    </div>
  );
}
