import { motion, useInView, useReducedMotion } from "motion/react";
import { useEffect, useRef, useState } from "react";
import { useMediaQuery } from "./motionKit";
import "./StorageTopologyMotion.css";

const backends = [
  { name: "SQLite", note: "one node · one local file", tone: "blue" },
  { name: "Turso", note: "hosted SQLite · one node", tone: "violet" },
  { name: "PostgreSQL", note: "shared backend · many instances", tone: "green" },
];

// A deployment talks to exactly one backend, so the signal visits one
// backend per cycle instead of lighting all of them at once.
const CYCLE_MS = 3200;
const ease = [0.16, 1, 0.3, 1] as const;

const sweep = (delay: number, axis: "scaleX" | "scaleY") => ({
  initial: { [axis]: 0, opacity: 1 },
  animate: { [axis]: [0, 1, 1], opacity: [1, 1, 0] },
  transition: { delay, duration: 1.2, times: [0, 0.4, 1], ease },
});

export default function StorageTopologyMotion() {
  const reduceMotion = useReducedMotion() ?? false;
  const stacked = useMediaQuery("(max-width: 600px)");
  const ref = useRef<HTMLDivElement>(null);
  const inView = useInView(ref, { margin: "120px 0px" });
  const [cycle, setCycle] = useState(0);
  const active = cycle % backends.length;
  const animating = !reduceMotion;

  useEffect(() => {
    if (!animating || !inView) return;

    const id = window.setInterval(() => setCycle((value) => value + 1), CYCLE_MS);

    return () => window.clearInterval(id);
  }, [animating, inView]);

  return (
    <div
      ref={ref}
      className="storage-topology"
      role="img"
      aria-label="PlainQ routes its queue API to one storage backend: SQLite, Turso, or PostgreSQL."
    >
      <div className="storage-topology__grid">
        <motion.div
          key={animating ? `core-${cycle}` : "core"}
          className="storage-topology__core plainq-core"
          animate={
            animating
              ? {
                  boxShadow: [
                    "0 10px 26px rgba(49,92,255,.09)",
                    "0 0 0 3px rgba(49,92,255,.10), 0 12px 30px rgba(49,92,255,.14)",
                    "0 10px 26px rgba(49,92,255,.09)",
                  ],
                }
              : undefined
          }
          transition={{ duration: 0.9, ease }}
        >
          <span className="core-mark">Q</span>
          <span>
            <strong>PlainQ</strong>
            <small>queue API</small>
          </span>
        </motion.div>

        <div className="storage-topology__trunk storage-trunk" aria-hidden="true">
          {animating ? (
            <motion.span
              key={`trunk-${cycle}-${stacked}`}
              className="storage-trunk__signal"
              {...sweep(0.05, stacked ? "scaleY" : "scaleX")}
            />
          ) : null}
          <svg className="storage-trunk__arrow" viewBox="0 0 8 8" aria-hidden="true">
            <path d="M1 1L6 4L1 7" />
          </svg>
        </div>

        <div className="storage-topology__backends backend-list">
          {animating && !stacked && active !== 1 ? (
            <motion.span
              key={`bus-${cycle}`}
              className={`backend-list__bus-signal ${active === 0 ? "is-up" : "is-down"}`}
              aria-hidden="true"
              {...sweep(0.4, "scaleY")}
            />
          ) : null}

          {backends.map((backend, index) => {
            const isActive = animating && index === active;

            return (
              <motion.div
                className="backend-node"
                key={backend.name}
                initial={false}
                animate={{
                  borderColor: isActive ? "#bfc9ff" : "#dfe3dc",
                  boxShadow: isActive
                    ? "0 0 0 1px rgba(255,255,255,.9), 0 12px 30px rgba(49,92,255,.13)"
                    : "0 0 0 0 rgba(255,255,255,0), 0 0 0 rgba(49,92,255,0)",
                }}
                transition={{ delay: isActive ? (stacked ? 0.45 : 0.75) : 0, duration: 0.5, ease }}
              >
                <span className="backend-node__connector" aria-hidden="true">
                  <span className="backend-node__connector-line" />
                  {isActive ? (
                    <motion.span
                      key={`branch-${cycle}`}
                      className="backend-node__connector-signal"
                      {...sweep(index === 1 ? 0.4 : 0.6, "scaleX")}
                    />
                  ) : null}
                  <svg className="backend-node__connector-arrow" viewBox="0 0 8 8" aria-hidden="true">
                    <path d="M1 1L6 4L1 7" />
                  </svg>
                </span>
                <motion.span
                  className={`backend-light ${backend.tone}`}
                  initial={false}
                  animate={{ scale: isActive ? [1, 1.6, 1] : 1 }}
                  transition={{ delay: isActive ? 0.8 : 0, duration: 0.6, ease }}
                />
                <span>
                  <strong>{backend.name}</strong>
                  <small>{backend.note}</small>
                </span>
              </motion.div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
