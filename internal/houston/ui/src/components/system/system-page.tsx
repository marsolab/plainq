"use client";

import * as React from "react";
import { Info } from "lucide-react";

import { api } from "@/lib/api-client";
import { formatClock } from "@/lib/format";
import { AppShell, type ServiceHealth } from "@/components/layout/app-shell";
import { ScopeBadge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Banner } from "@/components/ui/feedback";
import { PageHeader } from "@/components/ui/page-header";
import { Panel, PanelFooter, PanelTitleBar } from "@/components/ui/panel";
import { Skeleton } from "@/components/ui/skeleton";
import { Micro, MonoValue } from "@/components/ui/value";
import type { StatusTone } from "@/components/ui/status";

import { FactRow, HealthRow } from "./fact-row";
import { STARTUP_CONFIG } from "./mock-data";
import { ConnectionLostStrip } from "./error-state";

/** The reconnect cadence a lost connection retries on. */
const RECONNECT_INTERVAL_MS = 10_000;

/** 40px title bars, so panels sitting side by side line up across the grid. */
const PANEL_HEADER = "h-10 items-center py-0";

/**
 * What the last probe established. `unreachable` is reserved for a request
 * that never got an answer; a server that replies with an error — a 403 on
 * queue reads, a 400, a 500 — has answered, and that is not an outage.
 */
type ProbeOutcome = "reachable" | "unreachable" | "check-failed";

interface HealthSnapshot {
  outcome: ProbeOutcome;
  checkedAt: Date;
}

interface ProbeFailure {
  /** The request never reached the server, as opposed to being refused by it. */
  transport: boolean;
  message: string;
  /** Consecutive failures since the last success — the count shown to the operator. */
  attempt: number;
}

interface ComponentHealth {
  label: string;
  tone: StatusTone;
  state: string;
}

/**
 * PlainQ has no health endpoint, so the smallest real read stands in for one:
 * a one-row queue listing exercises the API and the datastore behind it. That
 * is the extent of what can be claimed — garbage collection and telemetry
 * expose no probe at all, and are reported as unreported rather than guessed.
 */
function componentsFor(outcome: ProbeOutcome): ComponentHealth[] {
  const probed: ComponentHealth[] =
    outcome === "reachable"
      ? [
          { label: "API", tone: "healthy", state: "Healthy" },
          { label: "Datastore", tone: "healthy", state: "Healthy" },
        ]
      : outcome === "unreachable"
        ? [
            { label: "API", tone: "degraded", state: "Unreachable" },
            { label: "Datastore", tone: "warning", state: "Unknown — API unreachable" },
          ]
        : [
            // The server answered, so neither component is down; the probe
            // simply established nothing about them.
            { label: "API", tone: "neutral", state: "Unknown — check failed" },
            { label: "Datastore", tone: "neutral", state: "Unknown — check failed" },
          ];

  return [
    ...probed,
    { label: "Garbage collection", tone: "neutral", state: "Not reported" },
    { label: "Telemetry", tone: "neutral", state: "Not reported" },
  ];
}

/**
 * The sidebar and the Health panel read from one snapshot, so they can never
 * disagree. Anything short of a probe that just succeeded is `unknown` — stale
 * good news is no longer a claim this page stands behind.
 */
function shellHealthFor(snapshot: HealthSnapshot | null, failing: boolean): ServiceHealth {
  if (!snapshot) return "unknown";
  if (snapshot.outcome === "unreachable") return "degraded";
  if (snapshot.outcome === "reachable") return failing ? "unknown" : "healthy";
  return "unknown";
}

export function SystemPage() {
  const [snapshot, setSnapshot] = React.useState<HealthSnapshot | null>(null);
  const [failure, setFailure] = React.useState<ProbeFailure | null>(null);
  const [loading, setLoading] = React.useState(true);
  const [checking, setChecking] = React.useState(false);

  const check = React.useCallback(async () => {
    setChecking(true);
    try {
      await api.queues.list({ limit: 1 });
      setSnapshot({ outcome: "reachable", checkedAt: new Date() });
      setFailure(null);
    } catch (error) {
      // `fetch` rejects with a TypeError only when the request never got an
      // answer. Every other rejection came off a response the server sent, so
      // it is a refused check rather than a lost service.
      const transport = error instanceof TypeError;
      setFailure((prev) => ({
        transport,
        message: error instanceof Error ? error.message : "Request failed",
        attempt: (prev?.attempt ?? 0) + 1,
      }));
      // A failed refresh keeps the last good answer instead of blanking it.
      // Only a first attempt that never succeeded is allowed to report down.
      setSnapshot((prev) =>
        prev?.outcome === "reachable"
          ? prev
          : { outcome: transport ? "unreachable" : "check-failed", checkedAt: new Date() },
      );
    } finally {
      setChecking(false);
      setLoading(false);
    }
  }, []);

  React.useEffect(() => {
    void check();
  }, [check]);

  // Only a dropped connection is worth a timer: each failure schedules the next
  // attempt, so the counter shown is the real number of tries. A refused
  // request returns the same refusal forever and waits for the operator.
  React.useEffect(() => {
    if (!failure?.transport) return;
    const timer = window.setTimeout(() => void check(), RECONNECT_INTERVAL_MS);
    return () => window.clearTimeout(timer);
  }, [failure, check]);

  const lostConnection = failure?.transport ? failure : null;
  const refusedCheck = failure && !failure.transport ? failure : null;
  const stale = failure !== null && snapshot?.outcome === "reachable";
  const components = snapshot ? componentsFor(snapshot.outcome) : [];

  return (
    <AppShell
      currentPath="/system"
      title="System"
      health={shellHealthFor(snapshot, failure !== null)}
      updatedAt={snapshot?.checkedAt ?? null}
      onRefresh={() => void check()}
      refreshing={checking}
    >
      <div className="flex flex-col gap-4">
        <PageHeader title="System" className="mb-0" />

        <Banner tone="warning">
          Startup configuration is not readable from the server: PlainQ exposes no sanitized
          configuration endpoint. The panels below describe the shape of a PlainQ configuration,
          not this instance's settings.
        </Banner>

        {lostConnection ? (
          <ConnectionLostStrip
            attempt={lostConnection.attempt}
            action={
              <Button variant="outline" size="sm" onClick={() => void check()} loading={checking}>
                Retry now
              </Button>
            }
          />
        ) : null}

        <div className="flex items-center gap-2.5 border border-border bg-muted px-3 py-2.5 text-xs text-strong">
          <Info className="size-3.5 shrink-0" aria-hidden />
          <span>
            Configuration is managed at startup. Change flags or environment variables and restart
            PlainQ to apply updates.
          </span>
        </div>

        <div className="grid grid-cols-1 items-start gap-4 lg:grid-cols-2">
          <Panel>
            <PanelTitleBar
              title="Health"
              className={PANEL_HEADER}
              action={
                <>
                  {stale ? <ScopeBadge>Stale</ScopeBadge> : null}
                  {snapshot ? <Micro>last check {formatClock(snapshot.checkedAt)}</Micro> : null}
                </>
              }
            />

            <div className="py-1">
              {loading
                ? [0, 1, 2, 3].map((row) => (
                    <div
                      key={row}
                      className="flex items-center justify-between gap-4 border-t border-muted px-4 py-2 first:border-t-0"
                    >
                      <Skeleton className="h-3.5 w-28" />
                      <Skeleton className="h-3.5 w-16" />
                    </div>
                  ))
                : components.map((component) => (
                    <HealthRow
                      key={component.label}
                      label={component.label}
                      tone={component.tone}
                    >
                      {component.state}
                    </HealthRow>
                  ))}
            </div>

            <PanelFooter>
              {refusedCheck ? (
                <p className="text-[11px] leading-relaxed text-strong">
                  The check did not complete:{" "}
                  <MonoValue className="text-[11px]">{refusedCheck.message}</MonoValue>. The server
                  answered, so this is not an outage — nothing is claimed about the components
                  above until a check succeeds.
                </p>
              ) : (
                <p className="text-[11px] leading-relaxed text-subtle">
                  API and datastore health are inferred from a live queue read. Garbage collection
                  and telemetry expose no probe, so PlainQ reports nothing for them.
                </p>
              )}
            </PanelFooter>
          </Panel>

          {STARTUP_CONFIG.map((group) => (
            <Panel key={group.title}>
              <PanelTitleBar
                title={group.title}
                className={PANEL_HEADER}
                action={<ScopeBadge>Not live</ScopeBadge>}
              />
              <div className="py-1">
                {group.facts.map((fact) => (
                  <FactRow key={fact.label} label={fact.label} subdued={fact.withheld}>
                    {fact.value}
                  </FactRow>
                ))}
              </div>
            </Panel>
          ))}
        </div>
      </div>
    </AppShell>
  );
}
