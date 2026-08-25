import { Player } from "@remotion/player";
import { Easing, interpolate, useCurrentFrame } from "remotion";
import { useEffect, useState, type CSSProperties } from "react";
import "./TopicFanoutMotion.css";

const FPS = 30;
const DURATION_IN_FRAMES = 300;
const DESKTOP_COMPOSITION = { width: 1200, height: 340 };
const MOBILE_COMPOSITION = { width: 390, height: 270 };
const subscribers = ["email-q", "analytics-q", "audit-q"];

type TopicFanoutMotionProps = {
  compact: boolean;
};

type TopicFanoutSceneProps = TopicFanoutMotionProps & {
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

function ArrowHead() {
  return (
    <svg className="topic-fanout-motion__arrow" viewBox="0 0 16 16" fill="none" aria-hidden="true">
      <path d="M3 8h8M8 4l4 4-4 4" />
    </svg>
  );
}

function TopicFanoutScene({ compact, frame }: TopicFanoutSceneProps) {
  const topicGlow = interpolate(frame, [54, 86, 204, 236], [0, 1, 1, 0], {
    ...clamp,
    easing: motionEase,
  });

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
        left: `${interpolate(frame, [8, 64], [134, 392], {
          ...clamp,
          easing: motionEase,
        })}px`,
        top: "166px",
        opacity: interpolate(frame, [2, 10, 58, 66], [0, 1, 1, 0], clamp),
      };

  return (
    <div className={`topic-fanout-motion__scene${compact ? " is-compact" : ""}`}>
      <div className="topic-fanout-motion__node topic-fanout-motion__event">event</div>
      <span className="topic-fanout-motion__rail topic-fanout-motion__rail--in">
        <ArrowHead />
      </span>

      <div
        className="topic-fanout-motion__node topic-fanout-motion__topic"
        style={{
          borderColor: topicGlow > 0.5 ? "#bfc9ff" : "var(--color-border)",
          boxShadow: `0 12px 28px rgba(49, 92, 255, ${topicGlow * 0.1})`,
        }}
      >
        order.created
      </div>

      <span className="topic-fanout-motion__spine" />
      <span className="topic-fanout-motion__bus" />

      {subscribers.map((subscriber, index) => {
        const start = 104 + index * 20;
        const end = start + 66;
        const branchY = [119, 175, 231][index];
        const mobileX = [75, 195, 315][index];
        const subscriberActivity = interpolate(
          frame,
          [end - 16, end, end + 34, end + 46],
          [0, 1, 1, 0],
          { ...clamp, easing: motionEase },
        );
        const deliveryPacket: CSSProperties = compact
          ? {
              left: `${interpolate(frame, [start, start + 20, start + 44, end], [190, 190, mobileX - 6, mobileX - 6], {
                ...clamp,
                easing: motionEase,
              })}px`,
              top: `${interpolate(frame, [start, start + 20, start + 44, end], [123, 150, 150, 175], {
                ...clamp,
                easing: motionEase,
              })}px`,
              opacity: interpolate(frame, [start - 6, start, end - 5, end + 7], [0, 1, 1, 0], clamp),
            }
          : {
              left: `${interpolate(frame, [start, start + 22, start + 44, end], [586, 724, 724, 818], {
                ...clamp,
                easing: motionEase,
              })}px`,
              top: `${interpolate(frame, [start, start + 22, start + 44, end], [166, 166, branchY - 6, branchY - 6], {
                ...clamp,
                easing: motionEase,
              })}px`,
              opacity: interpolate(frame, [start - 6, start, end - 5, end + 7], [0, 1, 1, 0], clamp),
            };

        return (
          <span key={subscriber}>
            <span className={`topic-fanout-motion__branch topic-fanout-motion__branch--${index}`}>
              <ArrowHead />
            </span>
            <span
              className="topic-fanout-motion__subscriber"
              style={{
                borderColor:
                  subscriberActivity > 0.5 ? "#bfc9ff" : "var(--color-border)",
                backgroundColor: `rgba(49, 92, 255, ${subscriberActivity * 0.03})`,
                boxShadow: `0 8px 18px rgba(49, 92, 255, ${subscriberActivity * 0.07})`,
                color:
                  subscriberActivity > 0.5
                    ? "var(--color-accent)"
                    : "var(--color-muted-foreground)",
              }}
            >
              {subscriber}
            </span>
            <span className="topic-fanout-motion__packet" style={deliveryPacket} />
          </span>
        );
      })}

      <span className="topic-fanout-motion__packet" style={incomingPacket} />
    </div>
  );
}

function TopicFanoutComposition({ compact }: TopicFanoutMotionProps) {
  const frame = useCurrentFrame();

  return <TopicFanoutScene compact={compact} frame={frame} />;
}

export default function TopicFanoutMotion() {
  const compact = useMediaQuery("(max-width: 560px)");
  const prefersReducedMotion = useMediaQuery("(prefers-reduced-motion: reduce)");
  const composition = compact ? MOBILE_COMPOSITION : DESKTOP_COMPOSITION;

  return (
    <div
      className={`topic-fanout-motion${compact ? " is-compact" : ""}`}
      role="img"
      aria-label="An event is published to a topic and delivered independently to the email, analytics, and audit queues."
    >
      {prefersReducedMotion ? (
        <div className="topic-fanout-motion__static">
          <TopicFanoutScene compact={compact} frame={270} />
        </div>
      ) : (
        <div aria-hidden="true">
          <Player
            component={TopicFanoutComposition}
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
            className="topic-fanout-motion__player"
            style={{ width: "100%" }}
          />
        </div>
      )}
    </div>
  );
}
