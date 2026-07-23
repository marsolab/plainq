import * as React from "react";
import { Lock, type LucideIcon } from "lucide-react";

import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Banner } from "@/components/ui/feedback";
import { StatusMarker, type StatusTone } from "@/components/ui/status";
import { MonoValue } from "@/components/ui/value";

/**
 * Failure states, S24.
 *
 * Every failure gets a deliberate outcome: what happened, what it does *not*
 * claim, and the one action that moves the operator forward. A generic "an
 * error occurred" page is the one thing this file exists to prevent, so the
 * presets below stay specific and each carries its own recovery.
 */

interface ErrorStateProps extends Omit<React.ComponentProps<"div">, "title"> {
  /** The status numeral. Only for route-level errors — never on inline ones. */
  code?: string;
  icon?: LucideIcon;
  /** Square marker ahead of the title, where the outcome itself has a tone. */
  tone?: StatusTone;
  title: React.ReactNode;
  description?: React.ReactNode;
  actions?: React.ReactNode;
  /** Support reference the operator can quote back. Never a stack trace. */
  reference?: string;
  /** The caveat: what the state does not promise, or who can lift it. */
  footnote?: React.ReactNode;
}

function ErrorState({
  code,
  icon: Icon,
  tone,
  title,
  description,
  actions,
  reference,
  footnote,
  className,
  ...props
}: ErrorStateProps) {
  return (
    <div
      data-slot="error-state"
      className={cn("flex flex-col items-start gap-2.5 p-5", className)}
      {...props}
    >
      {code ? <span className="font-mono text-xl font-semibold tabular">{code}</span> : null}

      <div className="flex items-center gap-2">
        {Icon ? <Icon className="size-[15px] shrink-0" aria-hidden /> : null}
        {tone ? <StatusMarker tone={tone} /> : null}
        <span className="text-[13px] font-semibold">{title}</span>
      </div>

      {description ? (
        <p className="text-xs leading-relaxed text-muted-foreground">{description}</p>
      ) : null}

      {actions || reference ? (
        <div className="flex flex-wrap items-center gap-2">
          {actions}
          {reference ? (
            <span className="font-mono text-[10px] text-subtle">ref {reference}</span>
          ) : null}
        </div>
      ) : null}

      {footnote ? <p className="text-[11px] text-subtle">{footnote}</p> : null}
    </div>
  );
}

/** A route that does not exist. Nothing was redirected, and we say so. */
function RouteNotFound({ className }: { className?: string }) {
  return (
    <ErrorState
      className={className}
      code="404"
      title="This page doesn't exist"
      description="The address may be mistyped. Nothing was silently redirected."
      actions={
        <>
          <Button asChild>
            <a href="/">Queues</a>
          </Button>
          <Button variant="outline" asChild>
            <a href="/system">System</a>
          </Button>
        </>
      }
    />
  );
}

/**
 * The route was right; the thing behind it is gone. Keep the ID visible — it
 * is what the operator pastes into a log query to find out what happened.
 */
function ResourceNotFound({
  resource,
  id,
  backHref,
  backLabel,
  className,
}: {
  /** Sentence-case singular, e.g. "Queue". */
  resource: string;
  id: string;
  backHref: string;
  backLabel: string;
  className?: string;
}) {
  return (
    <ErrorState
      className={className}
      title={`${resource} not found`}
      description={
        <>
          <MonoValue className="text-[11px]">{id}</MonoValue> no longer exists. It may have been
          deleted while you were viewing it.
        </>
      }
      actions={
        <Button variant="outline" asChild>
          <a href={backHref}>{backLabel}</a>
        </Button>
      }
    />
  );
}

/**
 * 403 with the context kept. The operator stays where they were; they are told
 * what the action needs and what they hold, so the gap is legible rather than
 * mysterious. Never bounce them to a login screen for a permission problem.
 */
function PermissionDenied({
  title,
  requirement,
  roles,
  backHref,
  backLabel = "Back",
  className,
}: {
  title: React.ReactNode;
  /** What the action needs, in full: "Purging requires the Purge permission…". */
  requirement: React.ReactNode;
  /** What the operator actually holds. */
  roles?: string[];
  backHref?: string;
  backLabel?: string;
  className?: string;
}) {
  return (
    <ErrorState
      className={className}
      icon={Lock}
      title={title}
      description={
        <>
          {requirement}
          {roles && roles.length > 0 ? ` Your roles: ${roles.join(", ")}.` : null}
        </>
      }
      actions={
        backHref ? (
          <Button variant="outline" asChild>
            <a href={backHref}>{backLabel}</a>
          </Button>
        ) : null
      }
    />
  );
}

/**
 * 409 on deleting a queue that still holds messages. Two ways out, both
 * explicit: empty it first, or delete it as-is — and the second is a separate
 * decision, never folded into the first.
 */
function ConflictNotEmpty({
  queueName,
  onPurge,
  onForceDelete,
  className,
}: {
  queueName: string;
  onPurge?: () => void;
  /**
   * Omitted while the transport has no force-delete: the button stays visible
   * with the reason attached rather than disappearing and leaving the operator
   * to wonder whether it exists.
   */
  onForceDelete?: () => void;
  className?: string;
}) {
  return (
    <ErrorState
      className={className}
      title={`${queueName} isn't empty`}
      description="The queue still holds messages. Purge it first, or use force delete if you must remove it as-is."
      actions={
        <>
          <Button variant="outline" onClick={onPurge} disabled={!onPurge}>
            Purge first
          </Button>
          <Button
            variant="destructive-outline"
            onClick={onForceDelete}
            blockedReason={
              onForceDelete ? undefined : "PlainQ does not expose a force delete for queues."
            }
          >
            Force delete…
          </Button>
        </>
      }
      footnote="Force delete is a second explicit step, administrators only — integration-dependent."
    />
  );
}

/**
 * 500 in context. The operator's input is never discarded on a server fault,
 * and the reference is the only thing said about the cause — the detail belongs
 * in the server log, not on the operator's screen.
 */
function UnexpectedError({
  title,
  description,
  reference,
  retryLabel = "Retry",
  onRetry,
  retrying = false,
  className,
}: {
  title: React.ReactNode;
  description: React.ReactNode;
  reference?: string;
  retryLabel?: string;
  onRetry?: () => void;
  retrying?: boolean;
  className?: string;
}) {
  return (
    <ErrorState
      className={className}
      title={title}
      description={description}
      reference={reference}
      actions={
        onRetry ? (
          <Button onClick={onRetry} loading={retrying}>
            {retryLabel}
          </Button>
        ) : null
      }
    />
  );
}

/**
 * A destructive request that timed out. The result is genuinely unknown, so
 * this claims neither success nor failure and offers a refresh instead of a
 * retry — retrying a purge that may have run is how operators lose data twice.
 */
function DestructiveTimeout({
  operation,
  target,
  onRefresh,
  refreshLabel = "Refresh",
  refreshing = false,
  className,
}: {
  /** Sentence-case noun for the action, e.g. "Purge". */
  operation: string;
  target: string;
  onRefresh?: () => void;
  refreshLabel?: string;
  refreshing?: boolean;
  className?: string;
}) {
  return (
    <ErrorState
      className={className}
      tone="warning"
      title={`${operation} result unknown`}
      description={`The request to ${operation.toLowerCase()} ${target} timed out. It may or may not have completed — refresh to see the queue's actual state before retrying.`}
      actions={
        onRefresh ? (
          <Button variant="outline" onClick={onRefresh} loading={refreshing}>
            {refreshLabel}
          </Button>
        ) : null
      }
    />
  );
}

/**
 * The connection dropped after the page had already loaded. Data on screen is
 * still the last true answer, so it stays — labelled STALE by whatever renders
 * it — and only mutations are withheld until the link is back.
 */
function ConnectionLostStrip({
  attempt,
  action,
  className,
  ...props
}: React.ComponentProps<"div"> & { attempt?: number; action?: React.ReactNode }) {
  return (
    <div
      role="status"
      className={cn(
        "flex items-center gap-2 border border-border bg-muted px-3 py-2 text-xs text-strong",
        className,
      )}
      {...props}
    >
      <StatusMarker
        tone="neutral"
        className="border-muted-foreground bg-muted-foreground"
      />
      <span>
        Connection lost. Reconnecting…{" "}
        {attempt && attempt > 0 ? (
          <MonoValue className="text-[11px]">attempt {attempt}</MonoValue>
        ) : null}
      </span>
      {action ? <span className="ml-auto shrink-0">{action}</span> : null}
    </div>
  );
}

/**
 * A core subsystem is down: queue operations cannot proceed. Red, and the only
 * tone allowed to gate mutations.
 */
function CoreOutageBanner({
  children,
  action,
  className,
}: {
  children: React.ReactNode;
  action?: React.ReactNode;
  className?: string;
}) {
  return (
    <Banner tone="error" action={action} className={className}>
      <span className="font-semibold">Core: </span>
      {children}
    </Banner>
  );
}

/**
 * An optional subsystem is down — telemetry, metrics. Amber, and amber never
 * blocks anything: degraded charts must not look like a degraded queue.
 */
function OptionalOutageBanner({
  children,
  action,
  className,
}: {
  children: React.ReactNode;
  action?: React.ReactNode;
  className?: string;
}) {
  return (
    <Banner tone="warning" action={action} className={className}>
      <span className="font-semibold">Optional: </span>
      {children}
    </Banner>
  );
}

export {
  ErrorState,
  RouteNotFound,
  ResourceNotFound,
  PermissionDenied,
  ConflictNotEmpty,
  UnexpectedError,
  DestructiveTimeout,
  ConnectionLostStrip,
  CoreOutageBanner,
  OptionalOutageBanner,
};
