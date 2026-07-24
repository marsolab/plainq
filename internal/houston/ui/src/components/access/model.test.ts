import { describe, expect, test } from "bun:test";

import { ApiRequestError } from "@/lib/api-client";
import type {
  DirectoryUserDTO,
  ProviderDTO,
  ProviderSyncStatDTO,
  QueuePermissionDTO,
  RoleWithUsageDTO,
} from "@/lib/types";
import {
  countGrants,
  describeFailure,
  grantsOf,
  isForbidden,
  membersOfTeam,
  permissionsOf,
  providerTypeLabel,
  roleNames,
  sameGrants,
  teamsForUser,
  toProvider,
  toRole,
  toTeam,
  toUser,
  usersWithRole,
} from "./model";

const TIMESTAMP = "2026-07-20T09:00:00Z";

function permission(overrides: Partial<QueuePermissionDTO> = {}): QueuePermissionDTO {
  return {
    queue_id: "queue-1",
    role_id: "role-1",
    can_send: false,
    can_receive: false,
    can_purge: false,
    can_delete: false,
    created_at: TIMESTAMP,
    updated_at: TIMESTAMP,
    ...overrides,
  };
}

function directoryUser(overrides: Partial<DirectoryUserDTO> = {}): DirectoryUserDTO {
  return {
    user_id: "user-1",
    email: "ana@acme.test",
    verified: true,
    is_oauth_user: false,
    created_at: TIMESTAMP,
    updated_at: TIMESTAMP,
    roles: [],
    teams: [],
    ...overrides,
  };
}

describe("toUser", () => {
  test("an account with no provider is local, not unknown", () => {
    expect(toUser(directoryUser()).accountType).toBe("Local");
    expect(toUser(directoryUser()).synchronizedAt).toBeNull();
  });

  test("a provider-backed account carries its provider and sync time", () => {
    const user = toUser(
      directoryUser({
        oauth_provider: "kinde",
        is_oauth_user: true,
        last_sync_at: TIMESTAMP,
      }),
    );

    expect(user.accountType).toBe("Kinde");
    expect(user.synchronizedAt).toBe(TIMESTAMP);
  });

  test("organization falls back from name to code, and stays empty when there is none", () => {
    expect(toUser(directoryUser({ org_name: "Acme", org_code: "acme" })).organization).toBe("Acme");
    expect(toUser(directoryUser({ org_code: "acme" })).organization).toBe("acme");
    expect(toUser(directoryUser()).organization).toBe("");
  });

  test("roles and teams keep their server identifiers", () => {
    const user = toUser(
      directoryUser({
        roles: [{ role_id: "role-1", role_name: "admin" }],
        teams: [{ team_id: "team-1", org_id: "org-1", team_name: "Ops", team_code: "ops" }],
      }),
    );

    expect(user.roleIds).toEqual(["role-1"]);
    expect(user.teamIds).toEqual(["team-1"]);
  });
});

describe("toRole", () => {
  test("carries the server's own count and marks the authorization role", () => {
    const role: RoleWithUsageDTO = {
      role_id: "role-1",
      role_name: "admin",
      created_at: TIMESTAMP,
      user_count: 3,
    };

    expect(toRole(role)).toEqual({
      roleId: "role-1",
      name: "admin",
      userCount: 3,
      isAdmin: true,
    });

    expect(toRole({ ...role, role_name: "consumer" }).isAdmin).toBe(false);
  });
});

describe("grantsOf", () => {
  const queues = [{ queueId: "queue-1", queueName: "orders-prod" }];

  test("names grants from the queue list", () => {
    const grants = grantsOf([permission({ can_receive: true })], queues);

    expect(grants).toEqual([
      {
        queueId: "queue-1",
        queueName: "orders-prod",
        permissions: { send: false, receive: true, purge: false, delete: false },
      },
    ]);
  });

  test("keeps a grant whose queue is not in the list", () => {
    // Dropping it would under-report what the role can do, which is the one
    // mistake an authorization view must not make.
    const grants = grantsOf([permission({ queue_id: "queue-gone", can_send: true })], queues);

    expect(grants).toHaveLength(1);
    expect(grants[0]!.queueId).toBe("queue-gone");
    expect(grants[0]!.queueName).toBe("");
    expect(grants[0]!.permissions.send).toBe(true);
  });
});

describe("countGrants", () => {
  test("counts (queue, permission) pairs, not rows", () => {
    const grants = grantsOf(
      [
        permission({ queue_id: "queue-1", can_send: true, can_receive: true }),
        permission({ queue_id: "queue-2" }),
      ],
      [],
    );

    expect(countGrants(grants)).toBe(2);
    expect(countGrants([])).toBe(0);
  });
});

describe("sameGrants", () => {
  const base = grantsOf(
    [
      permission({ queue_id: "queue-1", can_send: true }),
      permission({ queue_id: "queue-2", can_receive: true }),
    ],
    [],
  );

  test("order does not make two identical matrices differ", () => {
    expect(sameGrants(base, [base[1]!, base[0]!])).toBe(true);
  });

  test("a flipped permission is a difference", () => {
    const changed = base.map((grant, index) =>
      index === 0
        ? { ...grant, permissions: { ...grant.permissions, send: false } }
        : grant,
    );

    expect(sameGrants(base, changed)).toBe(false);
  });

  test("a removed row is a difference", () => {
    expect(sameGrants(base, [base[0]!])).toBe(false);
  });
});

describe("permissionsOf", () => {
  test("maps the wire's four independent abilities", () => {
    expect(permissionsOf(permission({ can_purge: true, can_delete: true }))).toEqual({
      send: false,
      receive: false,
      purge: true,
      delete: true,
    });
  });
});

describe("toProvider", () => {
  const provider: ProviderDTO = {
    provider_id: "idp-1",
    provider_name: "kinde",
    config: {
      display_name: "Kinde production",
      issuer: "https://acme.kinde.com",
      client_id: "kn_client",
    },
    redacted_keys: ["client_secret"],
    is_active: true,
    created_at: TIMESTAMP,
    updated_at: TIMESTAMP,
  };

  test("reads the operator-facing name out of the stored configuration", () => {
    expect(toProvider(provider, []).name).toBe("Kinde production");
  });

  test("falls back to the provider type when no name is stored", () => {
    const unnamed = { ...provider, config: { issuer: "https://acme.kinde.com" } };

    expect(toProvider(unnamed, []).name).toBe("Kinde");
  });

  test("carries the withheld keys so a stored secret can be reported", () => {
    expect(toProvider(provider, []).redactedKeys).toEqual(["client_secret"]);
  });

  test("no synchronization row means nobody was synchronized, not unknown", () => {
    const withoutStats = toProvider(provider, []);

    expect(withoutStats.userCount).toBe(0);
    expect(withoutStats.lastSyncAt).toBeNull();

    const stats: ProviderSyncStatDTO[] = [
      { provider_name: "kinde", user_count: 4, last_sync_at: TIMESTAMP },
    ];

    expect(toProvider(provider, stats).userCount).toBe(4);
    expect(toProvider(provider, stats).lastSyncAt).toBe(TIMESTAMP);
  });
});

describe("providerTypeLabel", () => {
  test("labels known types and passes unknown ones through", () => {
    expect(providerTypeLabel("oidc")).toBe("Generic OIDC");
    expect(providerTypeLabel("something-else")).toBe("something-else");
  });
});

describe("membership helpers", () => {
  const teams = [
    toTeam({
      team_id: "team-1",
      org_id: "org-1",
      team_name: "Operations",
      team_code: "ops",
      is_active: true,
      created_at: TIMESTAMP,
      updated_at: TIMESTAMP,
    }),
  ];

  const users = [
    toUser(directoryUser({ user_id: "user-1", roles: [{ role_id: "role-1", role_name: "admin" }] })),
    toUser(
      directoryUser({
        user_id: "user-2",
        email: "bo@acme.test",
        teams: [{ team_id: "team-1", org_id: "org-1", team_name: "Operations", team_code: "ops" }],
      }),
    ),
  ];

  test("teamsForUser resolves ids against the team list", () => {
    expect(teamsForUser(teams, users[1]!)).toEqual(teams);
    expect(teamsForUser(teams, users[0]!)).toEqual([]);
  });

  test("membersOfTeam and usersWithRole read the same rows", () => {
    expect(membersOfTeam(users, "team-1").map((user) => user.userId)).toEqual(["user-2"]);
    expect(usersWithRole(users, "role-1").map((user) => user.userId)).toEqual(["user-1"]);
  });

  test("roleNames drops ids the role list no longer has", () => {
    const roles = [toRole({ role_id: "role-1", role_name: "admin", created_at: TIMESTAMP, user_count: 1 })];

    expect(roleNames(roles, ["role-1", "role-gone"])).toEqual(["admin"]);
  });
});

describe("describeFailure", () => {
  test("explains what each status means for the attempted action", () => {
    expect(describeFailure(new ApiRequestError(403, "403: Forbidden"), "assign the role")).toContain(
      "not assign the role",
    );
    expect(describeFailure(new ApiRequestError(409, "409: Conflict"), "remove the role")).toContain(
      "refused to remove the role",
    );
    expect(describeFailure(new ApiRequestError(400, "400: Bad Request"), "save")).toContain(
      "rejected the request to save",
    );
    expect(describeFailure(new ApiRequestError(404, "404: Not Found"), "delete it")).toContain(
      "no longer has",
    );
  });

  test("passes an unrecognised failure through rather than guessing at it", () => {
    expect(describeFailure(new ApiRequestError(500, "500: Internal"), "save")).toContain(
      "500: Internal",
    );
    expect(describeFailure(new Error("network down"), "save")).toContain("network down");
    expect(describeFailure("not an error", "save")).toBe("Could not save.");
  });
});

describe("isForbidden", () => {
  test("is true only for a refusal the server made", () => {
    expect(isForbidden(new ApiRequestError(403, "403: Forbidden"))).toBe(true);
    expect(isForbidden(new ApiRequestError(401, "401: Unauthorized"))).toBe(false);
    expect(isForbidden(new Error("403"))).toBe(false);
  });
});
