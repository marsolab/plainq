import { motion, useReducedMotion } from "motion/react";
import "./StorageTopologyMotion.css";

const backends = [
  { name: "SQLite", note: "one node · one local file", tone: "blue" },
  { name: "Turso", note: "hosted SQLite · one node", tone: "violet" },
  { name: "PostgreSQL", note: "shared backend · many instances", tone: "green" },
];

const signalKeyframes = {
  transition: {
    duration: 3.8,
    ease: "easeInOut" as const,
    repeat: Infinity,
    times: [0, 0.08, 0.36, 0.56, 1],
  },
};

const trunkSignal = {
  scaleX: [0, 0, 1, 1, 0],
  opacity: [0, 0, 1, 1, 0],
};

const branchSignal = {
  scaleX: [0, 0, 0, 1, 0],
  opacity: [0, 0, 0, 1, 0],
};

const nodeSignal = {
  boxShadow: [
    "0 10px 26px rgba(49,92,255,.09)",
    "0 10px 26px rgba(49,92,255,.09)",
    "0 0 0 1px rgba(255,255,255,.9), 0 12px 30px rgba(49,92,255,.13)",
    "0 0 0 1px rgba(255,255,255,.9), 0 12px 30px rgba(49,92,255,.13)",
    "0 10px 26px rgba(49,92,255,.09)",
  ],
};

export default function StorageTopologyMotion() {
  const prefersReducedMotion = useReducedMotion();
  const reduceMotion = prefersReducedMotion ?? false;

  return (
    <div
      className="storage-topology"
      role="img"
      aria-label="PlainQ routes its queue API to SQLite, Turso, and PostgreSQL storage backends."
    >
      <div className="storage-topology__grid">
        <motion.div
          className="storage-topology__core plainq-core"
          animate={
            reduceMotion
              ? undefined
              : {
                  boxShadow: [
                    "0 10px 26px rgba(49,92,255,.09)",
                    "0 10px 26px rgba(49,92,255,.09)",
                    "0 0 0 1px rgba(255,255,255,.95), 0 12px 30px rgba(49,92,255,.14)",
                    "0 0 0 1px rgba(255,255,255,.95), 0 12px 30px rgba(49,92,255,.14)",
                    "0 10px 26px rgba(49,92,255,.09)",
                  ],
                }
          }
          transition={signalKeyframes.transition}
        >
          <span className="core-mark">Q</span>
          <span>
            <strong>PlainQ</strong>
            <small>queue API</small>
          </span>
        </motion.div>

        <div className="storage-topology__trunk storage-trunk" aria-hidden="true">
          <motion.span
            className="storage-trunk__signal"
            initial={{ scaleX: 0, opacity: 0 }}
            animate={reduceMotion ? { scaleX: 0, opacity: 0 } : trunkSignal}
            transition={signalKeyframes.transition}
          />
          <svg className="storage-trunk__arrow" viewBox="0 0 8 8" aria-hidden="true">
            <path d="M1 1L6 4L1 7" />
            <motion.path
              d="M1 1L6 4L1 7"
              className="storage-trunk__arrow-signal"
              initial={{ opacity: 0 }}
              animate={reduceMotion ? { opacity: 0 } : { opacity: trunkSignal.opacity }}
              transition={signalKeyframes.transition}
            />
          </svg>
        </div>

        <div className="storage-topology__backends backend-list">
          {backends.map((backend) => (
            <motion.div
              className="backend-node"
              key={backend.name}
              animate={reduceMotion ? undefined : nodeSignal}
              transition={signalKeyframes.transition}
            >
              <span className="backend-node__connector" aria-hidden="true">
                <span className="backend-node__connector-line" />
                <motion.span
                  className="backend-node__connector-signal"
                  initial={{ scaleX: 0, opacity: 0 }}
                  animate={reduceMotion ? { scaleX: 0, opacity: 0 } : branchSignal}
                  transition={signalKeyframes.transition}
                />
                <svg className="backend-node__connector-arrow" viewBox="0 0 8 8" aria-hidden="true">
                  <path d="M1 1L6 4L1 7" />
                  <motion.path
                    d="M1 1L6 4L1 7"
                    className="backend-node__connector-arrow-signal"
                    initial={{ opacity: 0 }}
                    animate={reduceMotion ? { opacity: 0 } : { opacity: branchSignal.opacity }}
                    transition={signalKeyframes.transition}
                  />
                </svg>
              </span>
              <span className={`backend-light ${backend.tone}`} />
              <span>
                <strong>{backend.name}</strong>
                <small>{backend.note}</small>
              </span>
            </motion.div>
          ))}
        </div>
      </div>
    </div>
  );
}
