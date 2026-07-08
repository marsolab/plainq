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

export interface TimeRange {
  from: number;
  to: number;
}

export interface MetricDataPoint {
  timestamp: number;
  value: number;
  min?: number;
  max?: number;
  avg?: number;
  sum?: number;
  count?: number;
}

export interface MetricsChartResponse {
  metricName: string;
  queueId?: string;
  topicId?: string;
  timeRange?: TimeRange;
  resolution?: string;
  dataPoints: MetricDataPoint[];
}

export interface MultiMetricsChartResponse {
  metrics: MetricsChartResponse[];
  timeRange: TimeRange;
}

export interface QueueMetricsSummary {
  queueId: string;
  totalSent: number;
  totalReceived: number;
  totalDeleted: number;
  avgSendRate: number;
  avgReceiveRate: number;
  avgDeleteRate: number;
  maxSendRate: number;
  maxReceiveRate: number;
  maxDeleteRate: number;
  currentInFlight: number;
  currentSendRate: number;
  currentReceiveRate: number;
  currentDeleteRate: number;
  timeRange: TimeRange;
}

export interface TopicMetricsSummary {
  topicId: string;
  totalPublished: number;
  totalDeliveries: number;
  avgPublishRate: number;
  avgDeliveryRate: number;
  maxPublishRate: number;
  maxDeliveryRate: number;
  subscriptions: number | null;
  currentPublishRate: number;
  currentDeliveryRate: number;
  timeRange: TimeRange;
}

export interface TopicMetricsRow {
  topicId: string;
  publishRate: number;
  deliveryRate: number;
  messagesPublished: number;
  deliveries: number;
  subscriptionsCurrent: number | null;
  subscriptionsCreated: number;
  subscriptionsDeleted: number;
  updatedAt: number;
}

export interface TopicMetricsOverview {
  systemMetrics: {
    publishRate: number;
    deliveryRate: number;
    messagesPublished: number;
    deliveries: number;
    subscriptionsCurrent: number | null;
    subscriptionsCreated: number;
    subscriptionsDeleted: number;
  };
  topicMetrics: TopicMetricsRow[];
  timeRange: TimeRange;
  updatedAt: number;
}

export interface InFlightMetricsResponse {
  current: number;
  queueId?: string;
  history: MetricDataPoint[];
  timeRange: TimeRange;
}

export interface DashboardOverviewResponse {
  systemMetrics: Record<string, number>;
  queueMetrics: Array<Record<string, string | number>>;
  timeRange: TimeRange;
  updatedAt: number;
}
