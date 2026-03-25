export type EvictionPolicy =
  | "EVICTION_POLICY_UNSPECIFIED"
  | "EVICTION_POLICY_DROP"
  | "EVICTION_POLICY_DEAD_LETTER"
  | "EVICTION_POLICY_REORDER";

export interface Queue {
  queueId: string;
  queueName: string;
  createdAt: string;
  maxReceiveAttempts: number;
  retentionPeriodSeconds: number;
  visibilityTimeoutSeconds: number;
  evictionPolicy: EvictionPolicy;
  deadLetterQueueId?: string;
}

export interface QueueListResponse {
  queues: Queue[];
  nextCursor: string;
  hasMore: boolean;
}

export interface User {
  id: string;
  email: string;
  name: string;
  role: string;
  createdAt: string;
}

export interface AuthTokens {
  accessToken: string;
  refreshToken: string;
}

export interface ApiError {
  message: string;
  code?: string;
}
