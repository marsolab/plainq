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


export interface Subscription {
  subscriptionId: string;
  topicId: string;
  queueId: string;
  queueName?: string;
  createdAt: string;
}

export interface Topic {
  topicId: string;
  topicName: string;
  createdAt: string;
  subscriptions?: Subscription[];
}

export interface TopicListResponse {
  topics: Topic[];
}

/** A message as returned by a browse (peek) request. `body` is decoded to text
 * by the API client. */
export interface PeekMessage {
  id: string;
  body: string;
  createdAt: string;
  visibleAt: string;
  retries: number;
  inFlight: boolean;
}

export interface PeekResponse {
  messages: PeekMessage[];
  total: number;
}

/** A message as returned by a receive (consume) request. */
export interface ReceiveMessage {
  id: string;
  body: string;
}

export interface ReceiveResponse {
  messages: ReceiveMessage[];
}

export interface SendResponse {
  messageIds: string[];
}

export interface DeleteResponse {
  successful: string[];
  failed?: { messageId: string; error: string }[];
}

export interface PublishResponse {
  topicId: string;
  queueIds: string[];
  messageIds: string[];
  deliveredCount: number;
}
