/**
 * Access view model.
 *
 * Every value the Access screens render comes from `/api/v1` — the account
 * directory, the RBAC routes and the OAuth routes. This module holds the shape
 * those responses take once, plus the pure functions that derive counts and
 * labels from them, so no component is tempted to compute a grant total or a
 * membership inline and none of them can disagree about one.
 *
 * Nothing here fabricates data. A function that cannot answer returns null or
 * an empty list rather than a plausible default.
 */

import { ApiRequestError } from "@/lib/api-client";
import type {
  DirectoryUserDTO,
  ProviderDTO,
  ProviderSyncStatDTO,
  QueuePermissionDTO,
  QueueRolePermissionDTO,
  RoleWithUsageDTO,
  TeamDTO,
} from "@/lib/types";

export type PermissionKey = "send" | "receive" | "purge" | "delete";

export const PERMISSION_KEYS: readonly PermissionKey[] = [
  "send",
  "receive",
  "purge",
  "delete",
];

export const PERMISSION_LABELS: Record<PermissionKey, string> = {
  send: "Send",
  receive: "Receive",
  purge: "Purge",
  delete: "Delete",
};

export type Permissions = Record<PermissionKey, boolean>;

/**
 * The role the server's authorization middleware resolves by name. Several
 * server-side guards exist only to keep it reachable, and the UI mirrors them
 * so a refusal is explained before it happens rather than after.
 */
export const ADMIN_ROLE_NAME = "admin";

export interface AccessUser {
  userId: string;
  /**
   * Email is the primary identity. Display names are not reliably persisted
   * across providers, so the UI never leads with one.
   */
  email: string;
  /** "Local", or the identity provider that owns the account. */
  accountType: string;
  verified: boolean;
  /** The organization's display name, or its ID when it has no name. */
  organization: string;
  roleIds: string[];
  teamIds: string[];
  createdAt: string;
  /** Only provider-backed accounts synchronize; local ones never do. */
  synchronizedAt: string | null;
}

export interface AccessRole {
  roleId: string;
  name: string;
  /** Accounts holding the role, counted by the server. */
  userCount: number;
  /** True for the role authorization checks resolve by name. */
  isAdmin: boolean;
}

export interface QueueGrant {
  queueId: string;
  /** Empty when the queue list does not contain this ID — see `grantsOf`. */
  queueName: string;
  permissions: Permissions;
}

export interface AccessTeam {
  teamId: string;
  orgId: string;
  name: string;
  code: string;
}

export interface AccessOrganization {
  organizationId: string;
  code: string;
  name: string;
  teams: AccessTeam[];
}

export interface IdentityProvider {
  providerId: string;
  /** The operator-facing name, stored in the provider's own configuration. */
  name: string;
  /** The provider type the server keys its configuration off. */
  type: string;
  orgId: string;
  active: boolean;
  issuer: string;
  clientId: string;
  /** Configuration keys the server holds and refused to return. */
  redactedKeys: string[];
  /** Accounts synchronized through this provider, counted by the server. */
  userCount: number | null;
  lastSyncAt: string | null;
}

/**
 * The configuration key a provider's operator-facing name is stored under. The
 * server models a provider by type (`provider_name`), so the display name has
 * to live in the configuration map beside the issuer and client ID.
 */
export const DISPLAY_NAME_KEY = "display_name";

export const ISSUER_KEY = "issuer";
export const CLIENT_ID_KEY = "client_id";
export const CLIENT_SECRET_KEY = "client_secret";

export const IDENTITY_PROVIDER_TYPES = ["kinde", "okta", "auth0", "oidc"];

export const IDENTITY_PROVIDER_LABELS: Record<string, string> = {
  kinde: "Kinde",
  okta: "Okta",
  auth0: "Auth0",
  oidc: "Generic OIDC",
};

export function providerTypeLabel(type: string): string {
  return IDENTITY_PROVIDER_LABELS[type] ?? type;
}

export function emptyPermissions(): Permissions {
  return { send: false, receive: false, purge: false, delete: false };
}

export function permissionsOf(permission: QueuePermissionDTO): Permissions {
  return {
    send: permission.can_send,
    receive: permission.can_receive,
    purge: permission.can_purge,
    delete: permission.can_delete,
  };
}

export function toRole(role: RoleWithUsageDTO): AccessRole {
  return {
    roleId: role.role_id,
    name: role.role_name,
    userCount: role.user_count,
    isAdmin: role.role_name === ADMIN_ROLE_NAME,
  };
}

export function toUser(user: DirectoryUserDTO): AccessUser {
  return {
    userId: user.user_id,
    email: user.email,
    // An account with no provider signed up locally; that is a fact about the
    // row, not a default standing in for one we could not read.
    accountType: user.oauth_provider ? providerTypeLabel(user.oauth_provider) : "Local",
    verified: user.verified,
    organization: user.org_name || user.org_code || "",
    roleIds: user.roles.map((role) => role.role_id),
    teamIds: user.teams.map((team) => team.team_id),
    createdAt: user.created_at,
    synchronizedAt: user.last_sync_at ?? null,
  };
}

export function toTeam(team: TeamDTO): AccessTeam {
  return {
    teamId: team.team_id,
    orgId: team.org_id,
    name: team.team_name,
    code: team.team_code,
  };
}

export function toProvider(
  provider: ProviderDTO,
  stats: ProviderSyncStatDTO[],
): IdentityProvider {
  const stat = stats.find((candidate) => candidate.provider_name === provider.provider_name);

  return {
    providerId: provider.provider_id,
    name: provider.config[DISPLAY_NAME_KEY] || providerTypeLabel(provider.provider_name),
    type: provider.provider_name,
    orgId: provider.org_id ?? "",
    active: provider.is_active,
    issuer: provider.config[ISSUER_KEY] ?? "",
    clientId: provider.config[CLIENT_ID_KEY] ?? "",
    redactedKeys: provider.redacted_keys,
    // No row means the server has synchronized nobody through this provider,
    // which is a count of zero rather than an unknown.
    userCount: stat ? stat.user_count : 0,
    lastSyncAt: stat?.last_sync_at ?? null,
  };
}

/**
 * A role's grants, named with the queues the caller can see.
 *
 * A grant whose queue is absent from the list keeps its ID and an empty name:
 * the grant exists on the server, and dropping it would under-report what the
 * role can do.
 */
export function grantsOf(
  grants: QueuePermissionDTO[],
  queues: { queueId: string; queueName: string }[],
): QueueGrant[] {
  return grants.map((grant) => ({
    queueId: grant.queue_id,
    queueName: queues.find((queue) => queue.queueId === grant.queue_id)?.queueName ?? "",
    permissions: permissionsOf(grant),
  }));
}

/** A grant is one (queue, permission) pair, so the count is always derived. */
export function countGrants(grants: QueueGrant[]): number {
  return grants.reduce(
    (total, grant) => total + PERMISSION_KEYS.filter((key) => grant.permissions[key]).length,
    0,
  );
}

export function sameGrants(a: QueueGrant[], b: QueueGrant[]): boolean {
  if (a.length !== b.length) return false;

  return a.every((grant) => {
    const other = b.find((candidate) => candidate.queueId === grant.queueId);
    if (!other) return false;

    return PERMISSION_KEYS.every((key) => grant.permissions[key] === other.permissions[key]);
  });
}

export function roleById(roles: AccessRole[], roleId: string): AccessRole | undefined {
  return roles.find((role) => role.roleId === roleId);
}

export function roleNames(roles: AccessRole[], roleIds: string[]): string[] {
  return roleIds
    .map((id) => roleById(roles, id)?.name)
    .filter((name): name is string => Boolean(name));
}

export function teamById(teams: AccessTeam[], teamId: string): AccessTeam | undefined {
  return teams.find((team) => team.teamId === teamId);
}

export function teamsForUser(teams: AccessTeam[], user: AccessUser): AccessTeam[] {
  return user.teamIds
    .map((id) => teamById(teams, id))
    .filter((team): team is AccessTeam => Boolean(team));
}

export function membersOfTeam(users: AccessUser[], teamId: string): AccessUser[] {
  return users.filter((user) => user.teamIds.includes(teamId));
}

export function usersWithRole(users: AccessUser[], roleId: string): AccessUser[] {
  return users.filter((user) => user.roleIds.includes(roleId));
}

/**
 * Turns a rejected request into something an operator can act on.
 *
 * The server answers errors with status text only — it deliberately does not
 * hand back internal messages — so the status code plus the operation is all
 * there is to work with. Saying what the code means for *this* action is
 * reporting the server's answer; inventing a cause would not be.
 */
export function describeFailure(error: unknown, action: string): string {
  if (!(error instanceof ApiRequestError)) {
    return error instanceof Error
      ? `Could not ${action}: ${error.message}`
      : `Could not ${action}.`;
  }

  switch (error.status) {
    case 400:
      return `The server rejected the request to ${action} as invalid.`;

    case 401:
      return `Your session is no longer valid, so the server refused to ${action}.`;

    case 403:
      return `Your role may read access configuration but not ${action}.`;

    case 404:
      return `The server no longer has what this request refers to, so it could not ${action}.`;

    case 409:
      return `The server refused to ${action} because it would break a rule it enforces — reload to see the current values.`;

    default:
      return `The server could not ${action}: ${error.message}`;
  }
}

/** Whether a failure means the operator lacks permission for the write. */
export function isForbidden(error: unknown): boolean {
  return error instanceof ApiRequestError && error.status === 403;
}
