import { Player, type PlayerRef } from "@remotion/player";
import { Easing } from "remotion";
import { useEffect, useRef, useState, type ComponentType } from "react";

export const FPS = 30;

export const clamp = {
  extrapolateLeft: "clamp" as const,
  extrapolateRight: "clamp" as const,
};

export const motionEase = Easing.bezier(0.16, 1, 0.3, 1);
export const travelEase = Easing.bezier(0.45, 0, 0.2, 1);

export type Point = readonly [number, number];

export function useMediaQuery(query: string) {
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

const segmentLengths = (points: readonly Point[]) =>
  points.slice(1).map((point, index) => {
    const [x0, y0] = points[index];
    return Math.hypot(point[0] - x0, point[1] - y0);
  });

export function pathLength(points: readonly Point[]) {
  return segmentLengths(points).reduce((sum, length) => sum + length, 0);
}

// Walks a polyline by arc length so a packet keeps one continuous speed
// profile through corners instead of stopping at every waypoint.
export function alongPath(points: readonly Point[], progress: number): Point {
  const segments = segmentLengths(points);
  const total = segments.reduce((sum, length) => sum + length, 0);
  let remaining = Math.min(Math.max(progress, 0), 1) * total;

  for (let index = 0; index < segments.length; index += 1) {
    const length = segments[index];

    if (remaining <= length || index === segments.length - 1) {
      const t = length === 0 ? 0 : Math.min(remaining / length, 1);
      const [x0, y0] = points[index];
      const [x1, y1] = points[index + 1];

      return [x0 + (x1 - x0) * t, y0 + (y1 - y0) * t];
    }

    remaining -= length;
  }

  return points[points.length - 1];
}

// 0 → 1 → 0 wave with the given period, used for seamless idle pulses.
export function pulse(frame: number, period: number) {
  return 0.5 - 0.5 * Math.cos((2 * Math.PI * frame) / period);
}

type LoopPlayerProps<Props extends Record<string, unknown>> = {
  component: ComponentType<Props>;
  inputProps: Props;
  durationInFrames: number;
  width: number;
  height: number;
  className: string;
};

// Autoplaying, looping Remotion player that only renders frames while it is
// on screen.
export function LoopPlayer<Props extends Record<string, unknown>>({
  component,
  inputProps,
  durationInFrames,
  width,
  height,
  className,
}: LoopPlayerProps<Props>) {
  const containerRef = useRef<HTMLDivElement>(null);
  const playerRef = useRef<PlayerRef>(null);

  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;

    const observer = new IntersectionObserver(
      ([entry]) => {
        const player = playerRef.current;
        if (!player) return;

        if (entry.isIntersecting) {
          player.play();
        } else {
          player.pause();
        }
      },
      { rootMargin: "120px 0px" },
    );

    observer.observe(container);

    return () => observer.disconnect();
  }, [width, height]);

  return (
    <div ref={containerRef} aria-hidden="true">
      <Player
        ref={playerRef}
        component={component}
        inputProps={inputProps}
        durationInFrames={durationInFrames}
        fps={FPS}
        compositionWidth={width}
        compositionHeight={height}
        numberOfSharedAudioTags={0}
        autoPlay
        initiallyMuted
        loop
        controls={false}
        clickToPlay={false}
        doubleClickToFullscreen={false}
        spaceKeyToPlayOrPause={false}
        allowFullscreen={false}
        className={className}
        style={{ width: "100%" }}
      />
    </div>
  );
}
