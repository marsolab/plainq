import { interpolate, interpolateColors, useCurrentFrame } from "remotion";
import type { CSSProperties } from "react";
import {
  LoopPlayer,
  alongPath,
  clamp,
  motionEase,
  pathLength,
  travelEase,
  useMediaQuery,
  type Point,
} from "./motionKit";
import "./TopicFanoutMotion.css";

const DURATION_IN_FRAMES = 300;
const DESKTOP_COMPOSITION = { width: 1200, height: 340 };
const MOBILE_COMPOSITION = { width: 390, height: 270 };
const subscribers = ["email-q", "analytics-q", "audit-q"];

// The event is published once; the topic writes one copy per subscription,
// so the copies travel together until the bus and then split.
const PUBLISH = [8, 60] as const;
const FANOUT = [100, 158] as const;
const SETTLE = [252, 292] as const;

const BORDER = "#dfe3dc";
const ACTIVE_BORDER = "#bfc9ff";
const MUTED = "#646a63";
const ACCENT = "#315cff";
const PACKET_RADIUS = 6;

const desktopRoutes = {
  incoming: [[134, 172], [394, 172]] as Point[],
  deliveries: [116, 172, 228].map(
    (y): Point[] => [[586, 172], [724, 172], [724, y], [822, y]],
  ),
};

const compactRoutes = {
  incoming: [[195, 65], [195, 85]] as Point[],
  deliveries: [75, 195, 315].map(
    (x): Point[] => [[195, 126], [195, 156], [x, 156], [x, 181]],
  ),
};

type TopicFanoutMotionProps = {
  compact: boolean;
};

type TopicFanoutSceneProps = TopicFanoutMotionProps & {
  frame: number;
};

const ease = (frame: number, range: readonly [number, number]) =>
  interpolate(frame, range, [0, 1], { ...clamp, easing: motionEase });

// Shared distance travelled by every copy, so they overlap on the common
// segment and each one stops when its own route ends.
const fanoutDistance = (frame: number, longest: number) =>
  interpolate(frame, FANOUT, [0, longest], { ...clamp, easing: travelEase });

function arrivalFrame(length: number, longest: number) {
  for (let frame = FANOUT[0]; frame <= FANOUT[1]; frame += 1) {
    if (fanoutDistance(frame, longest) >= length) return frame;
  }

  return FANOUT[1];
}

function ArrowHead() {
  return (
    <svg className="topic-fanout-motion__arrow" viewBox="0 0 16 16" fill="none" aria-hidden="true">
      <path d="M3 8h8M8 4l4 4-4 4" />
    </svg>
  );
}

function TopicFanoutScene({ compact, frame }: TopicFanoutSceneProps) {
  const routes = compact ? compactRoutes : desktopRoutes;
  const lengths = routes.deliveries.map(pathLength);
  const longest = Math.max(...lengths);
  const distance = fanoutDistance(frame, longest);
  const settle = ease(frame, SETTLE);

  const eventActive = interpolate(frame, [2, 10, 40, 66], [0, 1, 1, 0], clamp);
  const topicGlow = interpolate(frame, [PUBLISH[1] - 6, PUBLISH[1] + 18, FANOUT[0] + 16, FANOUT[1] + 20], [0, 1, 1, 0], {
    ...clamp,
    easing: motionEase,
  });

  const publishProgress = interpolate(frame, PUBLISH, [0, 1], { ...clamp, easing: travelEase });
  const [inX, inY] = alongPath(routes.incoming, publishProgress);
  const incomingPacket: CSSProperties = {
    translate: `${inX - PACKET_RADIUS}px ${inY - PACKET_RADIUS}px`,
    opacity: interpolate(frame, [PUBLISH[0] - 4, PUBLISH[0] + 4, PUBLISH[1] - 4, PUBLISH[1] + 4], [0, 1, 1, 0], clamp),
  };

  return (
    <div className={`topic-fanout-motion__scene${compact ? " is-compact" : ""}`}>
      <div
        className="topic-fanout-motion__node topic-fanout-motion__event"
        style={{ borderColor: interpolateColors(eventActive, [0, 1], [BORDER, ACTIVE_BORDER]) }}
      >
        event
      </div>
      <span className="topic-fanout-motion__rail topic-fanout-motion__rail--in">
        <ArrowHead />
      </span>

      <div
        className="topic-fanout-motion__node topic-fanout-motion__topic"
        style={{
          borderColor: interpolateColors(topicGlow, [0, 1], [BORDER, ACTIVE_BORDER]),
          boxShadow: `0 12px 28px rgba(49, 92, 255, ${0.02 + topicGlow * 0.1})`,
        }}
      >
        order.created
        <span
          className="topic-fanout-motion__copies"
          style={{ opacity: topicGlow, translate: `0 ${(1 - topicGlow) * 3}px` }}
        >
          ×3
        </span>
      </div>

      <span className="topic-fanout-motion__spine" />
      <span className="topic-fanout-motion__bus" />

      {subscribers.map((subscriber, index) => {
        const route = routes.deliveries[index];
        const length = lengths[index];
        const arrival = arrivalFrame(length, longest);
        const activity = ease(frame, [arrival - 8, arrival + 8]) * (1 - settle);
        const [x, y] = alongPath(route, distance / length);
        const deliveryPacket: CSSProperties = {
          translate: `${x - PACKET_RADIUS}px ${y - PACKET_RADIUS}px`,
          opacity: interpolate(frame, [FANOUT[0] - 4, FANOUT[0] + 4, arrival - 3, arrival + 5], [0, 1, 1, 0], clamp),
        };

        return (
          <span key={subscriber}>
            <span className={`topic-fanout-motion__branch topic-fanout-motion__branch--${index}`}>
              <ArrowHead />
            </span>
            <span
              className="topic-fanout-motion__subscriber"
              style={{
                borderColor: interpolateColors(activity, [0, 1], [BORDER, ACTIVE_BORDER]),
                backgroundColor: `rgba(49, 92, 255, ${activity * 0.03})`,
                boxShadow: `0 8px 18px rgba(49, 92, 255, ${activity * 0.07})`,
                color: interpolateColors(activity, [0, 1], [MUTED, ACCENT]),
              }}
            >
              <span className="topic-fanout-motion__subscriber-name">{subscriber}</span>
              <span
                className="topic-fanout-motion__delivered"
                style={{ opacity: activity, translate: `${(1 - activity) * -4}px 0` }}
              >
                +1 copy
              </span>
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
          <TopicFanoutScene compact={compact} frame={FANOUT[1] + 30} />
        </div>
      ) : (
        <LoopPlayer
          component={TopicFanoutComposition}
          inputProps={{ compact }}
          durationInFrames={DURATION_IN_FRAMES}
          width={composition.width}
          height={composition.height}
          className="topic-fanout-motion__player"
        />
      )}
    </div>
  );
}
