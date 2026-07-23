import { EVICTION_POLICY_LABELS } from "@/lib/constants";
import type { EvictionPolicy } from "@/lib/types";

export const DROP: EvictionPolicy = "EVICTION_POLICY_DROP";
export const DEAD_LETTER: EvictionPolicy = "EVICTION_POLICY_DEAD_LETTER";

/**
 * One label table for the whole app: `EVICTION_POLICY_LABELS`. The create
 * dialog reads it through `getEvictionPolicyOptions`, the queue table reads it
 * here, so a policy is never spelled two ways on two screens. An unknown
 * policy falls through as the raw enum rather than being hidden.
 */
export function evictionLabel(policy: EvictionPolicy | string): string {
  return EVICTION_POLICY_LABELS[policy] ?? policy;
}
