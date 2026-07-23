import { formatDuration } from "@/lib/format";

interface LifecycleDiagramProps {
  visibilitySeconds: number;
  maxReceiveAttempts: number;
  retentionSeconds: number;
  /** Name of the dead-letter queue, or null when eviction does not use one. */
  deadLetterLabel: string | null;
  evictionPolicyLabel: string;
}

/**
 * VISIBLE → IN-FLIGHT → ACKNOWLEDGED, drawn with *this* queue's numbers rather
 * than a generic illustration: the visibility timeout, the attempt ceiling and
 * the eviction destination are the three settings that decide what an operator
 * sees, so the diagram states them inline.
 *
 * The lifecycle tints match `LifecycleLegend` in `components/ui/empty-state`;
 * they are the send and acknowledge hues at low opacity, never new colours.
 */
export function LifecycleDiagram({
  visibilitySeconds,
  maxReceiveAttempts,
  retentionSeconds,
  deadLetterLabel,
  evictionPolicyLabel,
}: LifecycleDiagramProps) {
  const visibility = formatDuration(visibilitySeconds);
  const retention = formatDuration(retentionSeconds);
  const evicted = deadLetterLabel ?? evictionPolicyLabel;

  const summary =
    `A visible message is received, which hides it for ${visibility} and raises its ` +
    `attempt count. Acknowledging it completes processing. If it is not acknowledged ` +
    `in time it becomes visible again, and after ${maxReceiveAttempts} receive attempts ` +
    `it goes to ${evicted}. Unconsumed messages expire after ${retention} of retention.`;

  return (
    <svg
      viewBox="0 0 1128 188"
      role="img"
      aria-label={summary}
      className="block h-auto w-full max-w-[1128px]"
    >
      <rect x="40" y="16" width="160" height="42" className="fill-surface stroke-foreground" />
      <text x="120" y="36" textAnchor="middle" className="fill-foreground text-[13px] font-semibold">
        Visible
      </text>
      <text x="120" y="50" textAnchor="middle" className="fill-muted-foreground font-mono text-[10px]">
        ready to receive
      </text>

      <line x1="200" y1="37" x2="432" y2="37" className="stroke-foreground" />
      <polygon points="432,33 440,37 432,41" className="fill-foreground" />
      <text x="320" y="28" textAnchor="middle" className="fill-foreground text-[11px] font-medium">
        Receive
      </text>

      <rect x="440" y="16" width="160" height="42" className="fill-send/10 stroke-send" />
      <text x="520" y="36" textAnchor="middle" className="fill-send-text text-[13px] font-semibold">
        In-flight
      </text>
      <text x="520" y="50" textAnchor="middle" className="fill-send-text font-mono text-[10px]">
        invisible for {visibility}
      </text>

      <line x1="600" y1="37" x2="832" y2="37" className="stroke-foreground" />
      <polygon points="832,33 840,37 832,41" className="fill-foreground" />
      <text x="720" y="28" textAnchor="middle" className="fill-foreground text-[11px] font-medium">
        Acknowledge
      </text>

      <rect x="840" y="16" width="160" height="42" className="fill-acknowledge/10 stroke-acknowledge" />
      <text x="920" y="36" textAnchor="middle" className="fill-acknowledge-text text-[13px] font-semibold">
        Acknowledged
      </text>
      <text x="920" y="50" textAnchor="middle" className="fill-acknowledge-text font-mono text-[10px]">
        processing complete
      </text>

      <g className="stroke-muted-foreground" strokeDasharray="4 3">
        <line x1="520" y1="58" x2="520" y2="104" />
        <line x1="520" y1="104" x2="128" y2="104" />
        <line x1="128" y1="104" x2="128" y2="66" />
      </g>
      <polygon points="124,66 128,58 132,66" className="fill-muted-foreground" />
      <text x="330" y="97" textAnchor="middle" className="fill-muted-foreground text-[11px]">
        not acknowledged within {visibility} → visible again, receive attempt +1
      </text>

      <g className="stroke-warning-text" strokeDasharray="4 3">
        <line x1="520" y1="104" x2="520" y2="146" />
        <line x1="520" y1="146" x2="832" y2="146" />
      </g>
      <polygon points="832,142 840,146 832,150" className="fill-warning-text" />
      <text x="676" y="139" textAnchor="middle" className="fill-warning-text text-[11px]">
        after {maxReceiveAttempts} receive attempts → {deadLetterLabel ? "moved to dead-letter queue" : evictionPolicyLabel.toLowerCase()}
      </text>

      <rect x="840" y="125" width="160" height="42" className="fill-warning-surface stroke-warning" />
      <text x="920" y="145" textAnchor="middle" className="fill-warning-text text-[13px] font-semibold">
        {deadLetterLabel ?? evictionPolicyLabel}
      </text>
      <text x="920" y="159" textAnchor="middle" className="fill-warning-text font-mono text-[10px]">
        {deadLetterLabel ? "dead-letter queue" : "eviction policy"}
      </text>

      <text x="40" y="180" className="fill-subtle font-mono text-[10px]">
        unconsumed messages expire after {retention} retention
      </text>
    </svg>
  );
}
