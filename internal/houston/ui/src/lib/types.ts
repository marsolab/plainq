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

export interface ApiError {
  message: string;
  code?: string;
}

/*
 * Access, directory and system DTOs.
 *
 * These endpoints are plain Go handlers serialising structs with snake_case
 * JSON tags, unlike the queue and metrics routes, which go through protojson
 * and arrive camelCase. The names below are the wire shape exactly as the
 * server sends it — renaming them here would put a second, silent contract
 * between the two.
 */

/** A role as RBAC stores it. */
export interface RoleDTO {
  role_id: string;
  role_name: string;
  created_at: string;
}

/** A role plus how many accounts hold it, as the role list returns. */
export interface RoleWithUsageDTO extends RoleDTO {
  user_count: number;
}

/** One (queue, role) grant row. */
export interface QueuePermissionDTO {
  queue_id: string;
  role_id: string;
  can_send: boolean;
  can_receive: boolean;
  can_purge: boolean;
  can_delete: boolean;
  created_at: string;
  updated_at: string;
}

/**
 * One row of a queue's permission matrix. `granted` is false when the server
 * stores no row for the role — "nothing granted", which is not the same claim
 * as an explicit deny.
 */
export interface QueueRolePermissionDTO {
  role: RoleDTO;
  user_count: number;
  permission: QueuePermissionDTO;
  granted: boolean;
}

/** A role's whole grant set. */
export interface RolePermissionsDTO {
  role: RoleDTO;
  grants: QueuePermissionDTO[];
}

/** One grant in a bulk permission save. */
export interface QueueGrantInput {
  queue_id: string;
  can_send: boolean;
  can_receive: boolean;
  can_purge: boolean;
  can_delete: boolean;
}

export interface DirectoryRoleDTO {
  role_id: string;
  role_name: string;
}

export interface DirectoryTeamDTO {
  team_id: string;
  org_id: string;
  team_name: string;
  team_code: string;
}

/**
 * One account as the directory reports it. The server builds this from an
 * explicit list of safe columns; there is no password field to omit here
 * because there is none in the response.
 */
export interface DirectoryUserDTO {
  user_id: string;
  email: string;
  verified: boolean;
  org_id?: string;
  org_code?: string;
  org_name?: string;
  oauth_provider?: string;
  is_oauth_user: boolean;
  last_sync_at?: string;
  created_at: string;
  updated_at: string;
  roles: DirectoryRoleDTO[];
  teams: DirectoryTeamDTO[];
}

export interface DirectoryPageDTO {
  users: DirectoryUserDTO[];
  next_cursor: string;
  has_more: boolean;
  /** Every account matching the filter, not just this page. A real count(*). */
  total: number;
}

export interface OrganizationDTO {
  org_id: string;
  org_code: string;
  org_name: string;
  org_domain?: string;
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

export interface OrganizationsResponse {
  organizations: OrganizationDTO[];
  /** The caller's own organization, empty when they belong to none. */
  user_org: string;
  multi_tenancy_enabled: boolean;
  default_org_code?: string;
}

export interface TeamDTO {
  team_id: string;
  org_id: string;
  team_name: string;
  team_code: string;
  description?: string;
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

/**
 * A provider with its credential material removed. `redacted_keys` names the
 * configuration keys the server holds and withheld — which is how the UI can
 * say a client secret is set without ever receiving one. Redacted keys are
 * absent from `config` entirely rather than masked.
 */
export interface ProviderDTO {
  provider_id: string;
  provider_name: string;
  org_id?: string;
  config: Record<string, string>;
  redacted_keys: string[];
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

/** What a provider has actually synchronized, keyed by stored provider name. */
export interface ProviderSyncStatDTO {
  provider_name: string;
  user_count: number;
  last_sync_at?: string;
}

export interface ProviderListResponse {
  providers: ProviderDTO[];
  sync_stats: ProviderSyncStatDTO[];
}

export interface ProviderInput {
  provider_name: string;
  config: Record<string, string>;
  is_active?: boolean;
}

/**
 * One setting of the running instance. A fact either carries a value or says
 * why it does not: `redacted` marks something the server holds and refuses to
 * return, which is a different fact from a setting that is simply unset.
 */
export interface ConfigFactDTO {
  label: string;
  value?: string;
  /** "duration" — `value` is a whole number of seconds. */
  format?: string;
  redacted?: boolean;
  note?: string;
}

export interface ConfigGroupDTO {
  title: string;
  facts: ConfigFactDTO[];
}

export interface ConfigResponseDTO {
  groups: ConfigGroupDTO[];
  /** When the values were read off the instance, not when they were set. */
  read_at: string;
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
