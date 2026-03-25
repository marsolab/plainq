export const API_BASE = "/api/v1";

export const EVICTION_POLICY_LABELS: Record<string, string> = {
  EVICTION_POLICY_UNSPECIFIED: "Unspecified",
  EVICTION_POLICY_DROP: "Drop",
  EVICTION_POLICY_DEAD_LETTER: "Dead Letter",
  EVICTION_POLICY_REORDER: "Reorder",
};

export const PAGE_SIZES = [10, 20, 50, 100] as const;

export const DEFAULT_PAGE_SIZE = 10;
