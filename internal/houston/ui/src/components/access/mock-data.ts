/**
 * Access has no transport yet.
 *
 * PlainQ exposes no list-users, roles, organizations or identity-provider
 * endpoints, so every value below is local mock data shaped like what the
 * server would eventually return. It lives in one module so that no component
 * is tempted to fabricate a count or a grant inline — every number the Access
 * screens render is derived from this data, never asserted.
 */

export type RoleKind = "built-in" | "custom";

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
  organization: string;
  /** Roles assigned to the user directly — never merged with team metadata. */
  roleIds: string[];
  /**
   * Team membership is deliberately absent here. The roster on `AccessTeam`
   * is the single record of who is in a team, so the Users table, the user
   * sheet and the Organizations screen can't drift into disagreeing about it.
   * Read it with `teamsForUser`.
   */
  createdAt: string;
  /** Only provider-backed accounts synchronize; local ones never do. */
  synchronizedAt: string | null;
}

export interface QueueGrant {
  queueId: string;
  queueName: string;
  permissions: Permissions;
}

export interface AccessRole {
  roleId: string;
  name: string;
  kind: RoleKind;
  /**
   * The administrator role bypasses per-queue grant checks inside the server,
   * so its grants are not the source of truth and its matrix stays locked.
   * Removing the bypass is itself an integration target.
   */
  bypass?: boolean;
  grants: QueueGrant[];
}

export interface AccessQueueRef {
  queueId: string;
  queueName: string;
}

export interface AccessTeam {
  teamId: string;
  name: string;
  memberEmails: string[];
  /** Roles attached to the team. Metadata only until inheritance ships. */
  roleIds: string[];
}

export interface AccessOrganization {
  organizationId: string;
  name: string;
  isDefault: boolean;
  teams: AccessTeam[];
}

export interface IdentityProvider {
  providerId: string;
  name: string;
  type: string;
  scope: string;
  active: boolean;
}

export const IDENTITY_PROVIDER_TYPES = ["Kinde", "Okta", "Auth0", "Generic OIDC"];

/**
 * Multi-tenancy is a build-time capability of the server. When it is off there
 * is one implicit organization and the directory collapses to a single notice.
 */
export const MULTI_TENANCY_ENABLED: boolean = true;

export const MOCK_ROLES: AccessRole[] = [
  {
    roleId: "role_administrator",
    name: "Administrator",
    kind: "built-in",
    bypass: true,
    grants: [],
  },
  {
    roleId: "role_producer",
    name: "Producer",
    kind: "built-in",
    // Seeded with no grants: the name promises nothing the grants don't say.
    grants: [],
  },
  {
    roleId: "role_consumer",
    name: "Consumer",
    kind: "built-in",
    grants: [
      {
        queueId: "01K0Q6XN3FH7T2W9B4M8R1D5CV",
        queueName: "orders-prod",
        permissions: { send: false, receive: true, purge: false, delete: false },
      },
      {
        queueId: "01K0Q6ZC4TQ8W1G5H9D2S6M3EA",
        queueName: "billing-events",
        permissions: { send: false, receive: true, purge: false, delete: false },
      },
    ],
  },
  {
    roleId: "role_billing_operator",
    name: "Billing operator",
    kind: "custom",
    grants: [
      {
        queueId: "01K0Q6ZC4TQ8W1G5H9D2S6M3EA",
        queueName: "billing-events",
        permissions: { send: true, receive: true, purge: false, delete: false },
      },
      {
        queueId: "01K0Q6XN3FH7T2W9B4M8R1D5CV",
        queueName: "orders-prod",
        permissions: { send: false, receive: true, purge: false, delete: false },
      },
    ],
  },
];

/** Queues a grant can be added for. Mirrors what a queue list would return. */
export const MOCK_QUEUES: AccessQueueRef[] = [
  { queueId: "01K0Q6ZC4TQ8W1G5H9D2S6M3EA", queueName: "billing-events" },
  { queueId: "01K0Q6XN3FH7T2W9B4M8R1D5CV", queueName: "orders-prod" },
  { queueId: "01K0Q71B8MJ4X6P2C7V3N9F0KT", queueName: "orders-dlq" },
  { queueId: "01K0Q73D5RS9Y8K1L4Z6Q2W7HB", queueName: "payments-retry" },
  { queueId: "01K0Q75F2GN6V3T8J5X1M9C4PD", queueName: "webhooks-inbound" },
];

export const MOCK_USERS: AccessUser[] = [
  {
    userId: "usr_01K0Q6M4A1",
    email: "maya@acme.test",
    accountType: "Local",
    verified: true,
    organization: "acme",
    roleIds: ["role_administrator"],
    createdAt: "2026-07-02T08:11:00Z",
    synchronizedAt: null,
  },
  {
    userId: "usr_01K0Q6M4A2",
    email: "samir@acme.test",
    accountType: "Kinde",
    verified: true,
    organization: "acme",
    roleIds: ["role_consumer", "role_billing_operator"],
    createdAt: "2026-07-14T10:36:00Z",
    synchronizedAt: "2026-07-21T06:00:00Z",
  },
  {
    userId: "usr_01K0Q6M4A3",
    email: "lena@acme.test",
    accountType: "Kinde",
    verified: true,
    organization: "acme",
    roleIds: ["role_billing_operator"],
    createdAt: "2026-06-28T15:02:00Z",
    synchronizedAt: "2026-07-21T06:00:00Z",
  },
  {
    userId: "usr_01K0Q6M4A4",
    email: "jon@acme.test",
    accountType: "Local",
    verified: false,
    organization: "acme",
    roleIds: ["role_producer"],
    createdAt: "2026-07-19T12:47:00Z",
    synchronizedAt: null,
  },
];

export const MOCK_ORGANIZATIONS: AccessOrganization[] = [
  {
    organizationId: "org_acme",
    name: "acme",
    isDefault: true,
    teams: [
      {
        teamId: "team_operations",
        name: "Operations",
        memberEmails: ["samir@acme.test", "lena@acme.test", "jon@acme.test"],
        roleIds: ["role_consumer"],
      },
      {
        teamId: "team_administrators",
        name: "Administrators",
        memberEmails: ["maya@acme.test"],
        roleIds: ["role_administrator"],
      },
      {
        teamId: "team_developers",
        name: "Developers",
        memberEmails: [],
        roleIds: [],
      },
    ],
  },
];

export const MOCK_IDENTITY_PROVIDERS: IdentityProvider[] = [
  {
    providerId: "idp_01K0Q6P1",
    name: "Kinde production",
    type: "Kinde",
    scope: "acme",
    active: true,
  },
  {
    providerId: "idp_01K0Q6P2",
    name: "Okta staging",
    type: "Okta",
    scope: "acme",
    active: false,
  },
];

/** A grant is one (queue, permission) pair, so the count is always derived. */
export function countGrants(role: AccessRole): number {
  return role.grants.reduce(
    (total, grant) =>
      total + PERMISSION_KEYS.filter((key) => grant.permissions[key]).length,
    0,
  );
}

export function usersWithRole(users: AccessUser[], roleId: string): AccessUser[] {
  return users.filter((user) => user.roleIds.includes(roleId));
}

export function roleById(roles: AccessRole[], roleId: string): AccessRole | undefined {
  return roles.find((role) => role.roleId === roleId);
}

export function roleNames(roles: AccessRole[], roleIds: string[]): string[] {
  return roleIds
    .map((id) => roleById(roles, id)?.name)
    .filter((name): name is string => Boolean(name));
}

export function teamById(
  organizations: AccessOrganization[],
  teamId: string,
): AccessTeam | undefined {
  for (const organization of organizations) {
    const team = organization.teams.find((candidate) => candidate.teamId === teamId);
    if (team) return team;
  }
  return undefined;
}

/**
 * A user's teams, read off the team rosters. Membership has exactly one
 * record, so the Users table, the user sheet and the Organizations screen all
 * answer "which teams is this account in?" the same way.
 */
export function teamsForUser(
  organizations: AccessOrganization[],
  email: string,
): AccessTeam[] {
  return organizations.flatMap((organization) =>
    organization.teams.filter((team) => team.memberEmails.includes(email)),
  );
}

/** The one way membership changes — used by both the sheet and the S21 panel. */
export function setTeamMembers(
  organizations: AccessOrganization[],
  teamId: string,
  memberEmails: string[],
): AccessOrganization[] {
  return organizations.map((organization) => ({
    ...organization,
    teams: organization.teams.map((team) =>
      team.teamId === teamId ? { ...team, memberEmails } : team,
    ),
  }));
}

export function emptyPermissions(): Permissions {
  return { send: false, receive: false, purge: false, delete: false };
}

/**
 * Which of the states the design specifies to render.
 *
 * With no transport there is nothing to make a directory fail, so the states
 * are selected with `?scenario=` on /access. They are real component states,
 * not mockups — the switch only replaces the server that would otherwise
 * decide between them.
 */
export type AccessScenario = "ok" | "empty" | "unavailable" | "stale" | "read-only";

const SCENARIOS: AccessScenario[] = ["ok", "empty", "unavailable", "stale", "read-only"];

export function readScenario(search?: string): AccessScenario {
  const raw = new URLSearchParams(
    search ?? (typeof window === "undefined" ? "" : window.location.search),
  ).get("scenario");
  return SCENARIOS.find((scenario) => scenario === raw) ?? "ok";
}

export type DirectoryStatus = "ok" | "unavailable" | "stale";

export interface DirectoryResult {
  status: DirectoryStatus;
  users: AccessUser[];
  /** Set only when a refresh failed over rows we already had. */
  error?: string;
}

const LATENCY_MS = 420;

/** Stands in for the list-users request the server does not answer yet. */
export function loadDirectory(scenario: AccessScenario): Promise<DirectoryResult> {
  return new Promise((resolve) => {
    window.setTimeout(() => {
      if (scenario === "unavailable") {
        resolve({ status: "unavailable", users: [] });
        return;
      }
      if (scenario === "empty") {
        resolve({ status: "ok", users: [] });
        return;
      }
      if (scenario === "stale") {
        resolve({
          status: "stale",
          users: MOCK_USERS,
          error: "Directory refresh failed — 503 from the account service.",
        });
        return;
      }
      resolve({ status: "ok", users: MOCK_USERS });
    }, LATENCY_MS);
  });
}
