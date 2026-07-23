"use client";

import * as React from "react";
import { RefreshCw } from "lucide-react";

import { Button, buttonVariants } from "@/components/ui/button";
import { Status } from "@/components/ui/status";
import { Micro, MonoValue } from "@/components/ui/value";
import { Mark } from "@/components/layout/wordmark";
import { probeService } from "./auth-transport";
import { AuthPage } from "./auth-shell";

/**
 * S01 — the boot state. Nothing renders until the service and the session are
 * known, because a sign-in form drawn over an unreachable service is a lie and
 * a dashboard skeleton drawn before the route decision is a worse one.
 *
 * The decisions the gate makes, each from a signal the server actually emits:
 *   unreachable              → full-page offline state, retry re-runs the probe
 *   5xx                      → degraded state, retry or System status
 *   needs onboarding         → /setup, which is where a first run belongs
 *   already set up, on /setup→ /login with the "already configured" notice
 *   credential held          → straight into the app, never the form
 *   no credential            → the auth screen renders
 *
 * A held credential is not the same as a valid one. The server exposes no
 * endpoint that checks a token, so the gate claims only what it knows — this
 * browser has something to present — and the first rejected request routes back
 * here with the expired notice and the intended destination intact.
 */

type GateState =
  | { phase: "checking" }
  | { phase: "offline"; endpoint: string }
  | { phase: "degraded"; ref?: string }
  | { phase: "open" };

interface StartupGateProps {
  /**
   * Where a visitor who already holds a session belongs. Read at redirect
   * time so a destination parsed out of the URL never re-triggers the probe.
   */
  resolveDestination?: () => string;
  /**
   * True on /setup — the one screen that renders *because* the server needs
   * onboarding, and so must not be redirected to itself.
   */
  isSetupRoute?: boolean;
  children: React.ReactNode;
}

export function StartupGate({
  resolveDestination = () => "/",
  isSetupRoute = false,
  children,
}: StartupGateProps) {
  const [state, setState] = React.useState<GateState>({ phase: "checking" });
  const [attempt, setAttempt] = React.useState(0);

  const destinationRef = React.useRef(resolveDestination);
  destinationRef.current = resolveDestination;

  React.useEffect(() => {
    let live = true;
    setState({ phase: "checking" });

    probeService().then((service) => {
      if (!live) return;

      if (service.kind === "unreachable") {
        setState({ phase: "offline", endpoint: service.endpoint });
        return;
      }
      if (service.kind === "degraded") {
        setState({ phase: "degraded", ref: service.ref });
        return;
      }

      // Each redirect stays on the connecting state while the browser
      // navigates: no screen may flash for someone who does not belong on it.
      if (service.needsSetup === true) {
        if (isSetupRoute) {
          setState({ phase: "open" });
          return;
        }
        window.location.replace("/setup");
        return;
      }

      if (isSetupRoute) {
        // Only the server's own "there is already an administrator" sends the
        // operator on. No answer means no claim, so the form stays and the
        // submission gets the real one.
        if (service.needsSetup === false) {
          window.location.replace("/login?reason=configured");
          return;
        }
        setState({ phase: "open" });
        return;
      }

      if (service.session) {
        window.location.replace(destinationRef.current());
        return;
      }

      setState({ phase: "open" });
    });

    return () => {
      live = false;
    };
  }, [attempt, isSetupRoute]);

  const retry = () => setAttempt((value) => value + 1);

  if (state.phase === "open") return <>{children}</>;

  return (
    <AuthPage>
      {state.phase === "checking" ? <ConnectingState /> : null}
      {state.phase === "offline" ? (
        <OfflineState endpoint={state.endpoint} onRetry={retry} />
      ) : null}
      {state.phase === "degraded" ? (
        <DegradedState reference={state.ref} onRetry={retry} />
      ) : null}
    </AuthPage>
  );
}

function BootState({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex flex-col items-center gap-3.5 text-center">{children}</div>
  );
}

function ConnectingState() {
  return (
    <BootState>
      <Mark size={36} />
      <div className="text-sm font-semibold">Connecting to PlainQ</div>
      <Micro>checking service and session…</Micro>
      <ScanBar />
    </BootState>
  );
}

function OfflineState({ endpoint, onRetry }: { endpoint: string; onRetry: () => void }) {
  return (
    <BootState>
      <Mark size={36} />
      <div className="text-sm font-semibold">Can&apos;t reach PlainQ</div>
      <p className="max-w-[320px] text-xs leading-relaxed text-muted-foreground">
        No response from{" "}
        <MonoValue className="text-[11px] text-strong">{endpoint}</MonoValue>. Check
        that the service is running and the address is correct.
      </p>
      <Button onClick={onRetry}>
        <RefreshCw aria-hidden />
        Retry connection
      </Button>
      <Micro className="border border-border bg-surface px-2.5 py-1.5 text-[10px] text-subtle">
        $ plainq serve --http :8080
      </Micro>
    </BootState>
  );
}

function DegradedState({
  reference,
  onRetry,
}: {
  reference?: string;
  onRetry: () => void;
}) {
  return (
    <BootState>
      <Status tone="degraded" className="text-sm font-semibold text-foreground">
        Service degraded
      </Status>
      <p className="max-w-[320px] text-xs leading-relaxed text-muted-foreground">
        The datastore is unavailable. Queue operations are paused until it recovers.
      </p>
      <div className="flex items-center gap-2">
        <Button variant="outline" onClick={onRetry}>
          Retry
        </Button>
        <a href="/system" className={buttonVariants({ variant: "ghost" })}>
          System status →
        </a>
      </div>
      {/* Only shown when the server actually returned a code to quote. */}
      {reference ? (
        <Micro className="text-[10px] text-subtle">ref {reference}</Micro>
      ) : null}
    </BootState>
  );
}

const SCAN_CSS = `
.houston-scan { animation: houston-scan 1.4s ease-in-out infinite; }
@keyframes houston-scan {
  from { transform: translateX(-48px); }
  to { transform: translateX(140px); }
}
@media (prefers-reduced-motion: reduce) {
  .houston-scan { animation: none; transform: translateX(28px); }
}
`;

/** Indeterminate: the probe has no progress to report, so none is implied. */
function ScanBar() {
  return (
    <div
      className="relative h-[2px] w-[140px] overflow-hidden bg-border"
      role="presentation"
    >
      <span className="houston-scan absolute top-0 left-0 block h-[2px] w-12 bg-primary" />
      <style>{SCAN_CSS}</style>
    </div>
  );
}
