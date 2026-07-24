"use client";

import * as React from "react";
import { Lock, Plus } from "lucide-react";
import { toast } from "sonner";

import { api } from "@/lib/api-client";
import { Button } from "@/components/ui/button";
import { InlineAlert } from "@/components/ui/feedback";
import { Status } from "@/components/ui/status";
import { Timestamp } from "@/components/ui/value";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

import { Sheet, SheetContent, SheetRow, SheetSection } from "./sheet";
import { QuietNotice } from "./notice";
import {
  ADMIN_ROLE_NAME,
  describeFailure,
  roleById,
  toTeam,
  usersWithRole,
  type AccessRole,
  type AccessTeam,
  type AccessUser,
} from "./model";

interface UserDetailSheetProps {
  user: AccessUser | null;
  /** The page in hand — the last-administrator hint reads it. */
  users: AccessUser[];
  roles: AccessRole[];
  /** Set when this operator may read the directory but not change it. */
  blockedReason?: string;
  onOpenChange: (open: boolean) => void;
  /** A write landed; the page refetches so the sheet shows stored values. */
  onChanged: () => void;
}

export function UserDetailSheet({
  user,
  users,
  roles,
  blockedReason,
  onOpenChange,
  onChanged,
}: UserDetailSheetProps) {
  const [assigningRole, setAssigningRole] = React.useState(false);
  const [pendingRoleId, setPendingRoleId] = React.useState("");
  const [addingTeam, setAddingTeam] = React.useState(false);
  const [pendingTeamId, setPendingTeamId] = React.useState("");
  const [notice, setNotice] = React.useState<string | null>(null);
  const [error, setError] = React.useState<string | null>(null);
  const [busy, setBusy] = React.useState<string | null>(null);

  const [teams, setTeams] = React.useState<AccessTeam[]>([]);
  const [teamsError, setTeamsError] = React.useState<string | null>(null);

  const userId = user?.userId ?? null;

  // Every draft belongs to the row that was opened; reopening starts clean.
  React.useEffect(() => {
    setAssigningRole(false);
    setPendingRoleId("");
    setAddingTeam(false);
    setPendingTeamId("");
    setNotice(null);
    setError(null);
  }, [userId]);

  // The account's own teams come from the server rather than from the row, so
  // the sheet stays right after a change made anywhere else.
  React.useEffect(() => {
    if (!userId) return;

    let cancelled = false;

    void (async () => {
      try {
        const rows = await api.oauth.userTeams.list(userId);
        if (!cancelled) {
          setTeams((rows ?? []).map(toTeam));
          setTeamsError(null);
        }
      } catch (failure) {
        if (!cancelled) setTeamsError(describeFailure(failure, "read this account's teams"));
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [userId]);

  if (!user) return null;

  const isProviderBacked = user.accountType !== "Local";
  const adminRole = roles.find((role) => role.isAdmin);
  const holdsRole = adminRole ? user.roleIds.includes(adminRole.roleId) : false;

  /**
   * The server refuses to strip the last administrator; this only says so
   * first. It is derived from the role's own user count, which the server
   * returned, so it stays right even when the page in hand shows one account.
   */
  const lastAdministrator = Boolean(adminRole && holdsRole && adminRole.userCount <= 1);
  const lastAdministratorReason = `Can't remove ${ADMIN_ROLE_NAME} from ${user.email} — it is the only account holding it. Assign the role to another account first.`;

  const run = async (key: string, action: string, work: () => Promise<void>) => {
    setBusy(key);
    setError(null);

    try {
      await work();
      onChanged();
    } catch (failure) {
      setError(describeFailure(failure, action));
    } finally {
      setBusy(null);
    }
  };

  const assignRole = () => {
    const role = roleById(roles, pendingRoleId);
    if (!role) return;

    if (user.roleIds.includes(role.roleId)) {
      // The server answers a duplicate with 409; saying so without the round
      // trip keeps the message identical either way.
      setNotice(`${user.email} already has the ${role.name} role. Nothing changed.`);
      setPendingRoleId("");
      return;
    }

    void run(`role:${role.roleId}`, `assign the ${role.name} role`, async () => {
      await api.rbac.userRoles.assign(user.userId, role.roleId);
      setNotice(null);
      setAssigningRole(false);
      setPendingRoleId("");
      toast.success(`${role.name} assigned to ${user.email}`);
    });
  };

  const removeRole = (roleId: string) => {
    const role = roleById(roles, roleId);

    void run(`role:${roleId}`, `remove the ${role?.name ?? roleId} role`, async () => {
      await api.rbac.userRoles.remove(user.userId, roleId);
      setNotice(null);
      toast.success(`${role?.name ?? roleId} removed from ${user.email}`);
    });
  };

  const addTeam = () => {
    const team = teams.find((candidate) => candidate.teamId === pendingTeamId);
    if (!pendingTeamId) return;

    void run(`team:${pendingTeamId}`, "add this account to the team", async () => {
      await api.oauth.userTeams.add(user.userId, pendingTeamId);
      setTeams(await api.oauth.userTeams.list(user.userId).then((rows) => rows.map(toTeam)));
      setNotice(null);
      setAddingTeam(false);
      setPendingTeamId("");
      toast.success(`${user.email} added to ${team?.name ?? "the team"}`);
    });
  };

  const removeTeam = (team: AccessTeam) => {
    void run(`team:${team.teamId}`, `remove this account from ${team.name}`, async () => {
      await api.oauth.userTeams.remove(user.userId, team.teamId);
      setTeams(await api.oauth.userTeams.list(user.userId).then((rows) => rows.map(toTeam)));
      setNotice(null);
      toast.success(`${user.email} removed from ${team.name}`);
    });
  };

  const otherAdministrators = adminRole
    ? usersWithRole(users, adminRole.roleId).filter(
        (candidate) => candidate.userId !== user.userId,
      ).length
    : 0;

  return (
    <Sheet open={Boolean(user)} onOpenChange={onOpenChange}>
      <SheetContent
        title={user.email}
        header={
          <div className="mt-1 flex flex-wrap items-center gap-2">
            <Status
              tone={user.verified ? "healthy" : "neutral"}
              className="text-[11px]"
              markerClassName="size-[7px]"
            >
              {user.verified ? "Verified" : "Unverified"}
            </Status>
            <span className="text-[11px] text-muted-foreground">· {user.accountType} ·</span>
            {user.synchronizedAt ? (
              <span className="inline-flex items-baseline gap-1.5 text-[11px] text-muted-foreground">
                synced
                <Timestamp value={user.synchronizedAt} variant="inline" />
              </span>
            ) : (
              <span className="text-[11px] text-muted-foreground">never synchronized</span>
            )}
          </div>
        }
      >
        {isProviderBacked ? (
          <div className="border-b border-border px-5 py-4">
            <p className="flex items-center gap-2 text-[11px] leading-[15px] text-muted-foreground">
              <Lock className="size-3 shrink-0" aria-hidden />
              Identity is managed by {user.accountType}. Email and verification can't be edited
              here.
            </p>
          </div>
        ) : null}

        {error ? (
          <div className="border-b border-border px-5 py-3">
            <InlineAlert className="items-start">{error}</InlineAlert>
          </div>
        ) : null}

        {notice ? (
          <div className="border-b border-border px-5 py-3">
            <QuietNotice>{notice}</QuietNotice>
          </div>
        ) : null}

        <SheetSection
          title="Direct roles"
          action={
            <Button
              variant="outline"
              size="sm"
              blockedReason={blockedReason}
              onClick={() => {
                setAssigningRole((open) => !open);
                setNotice(null);
              }}
              aria-expanded={assigningRole}
            >
              <Plus aria-hidden />
              Assign role
            </Button>
          }
        >
          {assigningRole ? (
            <div className="mb-2 flex items-center gap-2">
              <Select value={pendingRoleId} onValueChange={setPendingRoleId}>
                <SelectTrigger className="flex-1" aria-label="Role to assign">
                  <SelectValue placeholder="Select a role…" />
                </SelectTrigger>
                <SelectContent>
                  {roles.map((role) => (
                    <SelectItem key={role.roleId} value={role.roleId}>
                      {role.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <Button
                size="sm"
                onClick={assignRole}
                disabled={!pendingRoleId}
                loading={busy === `role:${pendingRoleId}`}
              >
                Assign
              </Button>
            </div>
          ) : null}

          {user.roleIds.length === 0 ? (
            <p className="border border-border px-2.5 py-3 text-xs text-muted-foreground">
              No direct roles. This account can do nothing on its own.
            </p>
          ) : (
            user.roleIds.map((roleId) => {
              const role = roleById(roles, roleId);
              const blocked =
                role?.isAdmin && lastAdministrator ? lastAdministratorReason : blockedReason;

              return (
                <SheetRow
                  key={roleId}
                  label={role?.name ?? roleId}
                  hint={
                    role
                      ? `${role.userCount} ${role.userCount === 1 ? "account holds" : "accounts hold"} this role`
                      : "Role no longer exists"
                  }
                  action={
                    <Button
                      variant="ghost"
                      size="sm"
                      blockedReason={blocked}
                      loading={busy === `role:${roleId}`}
                      onClick={() => removeRole(roleId)}
                    >
                      Remove
                    </Button>
                  }
                />
              );
            })
          )}

          {lastAdministrator ? (
            <InlineAlert className="mt-2 items-start">{lastAdministratorReason}</InlineAlert>
          ) : null}

          {holdsRole && !lastAdministrator && otherAdministrators === 0 ? (
            <p className="mt-2 text-[11px] leading-[15px] text-subtle">
              Other administrators exist outside this page of accounts, so removing the role here
              is permitted.
            </p>
          ) : null}
        </SheetSection>

        <SheetSection
          title="Teams"
          action={
            <Button
              variant="outline"
              size="sm"
              blockedReason={blockedReason}
              onClick={() => {
                setAddingTeam((open) => !open);
                setNotice(null);
              }}
              aria-expanded={addingTeam}
            >
              <Plus aria-hidden />
              Add to team
            </Button>
          }
          note="Teams carry no permissions of their own yet — the server stores membership but derives no roles from it, so none are shown."
        >
          {teamsError ? (
            <InlineAlert className="mb-2 items-start">{teamsError}</InlineAlert>
          ) : null}

          {addingTeam ? (
            <TeamPicker
              orgId={user.organization}
              memberOf={teams}
              value={pendingTeamId}
              onValueChange={setPendingTeamId}
              onAdd={addTeam}
              busy={busy === `team:${pendingTeamId}`}
            />
          ) : null}

          {teams.length === 0 ? (
            <p className="border border-border px-2.5 py-3 text-xs text-muted-foreground">
              Not a member of any team.
            </p>
          ) : (
            teams.map((team) => (
              <SheetRow
                key={team.teamId}
                label={team.name}
                hint={team.code}
                action={
                  <Button
                    variant="ghost"
                    size="sm"
                    blockedReason={blockedReason}
                    loading={busy === `team:${team.teamId}`}
                    onClick={() => removeTeam(team)}
                  >
                    Remove
                  </Button>
                }
              />
            ))
          )}
        </SheetSection>

        <div className="px-5 py-3.5 text-[11px] leading-[15px] text-subtle">
          Houston has no invite, suspend, delete or password-reset API for accounts — only role
          and team membership can be changed here.
        </div>
      </SheetContent>
    </Sheet>
  );
}

/**
 * Teams an account could join. The list is read per organization, so it is
 * fetched here rather than threaded through the page: the sheet is the only
 * place that needs it and it is opened one account at a time.
 */
function TeamPicker({
  orgId,
  memberOf,
  value,
  onValueChange,
  onAdd,
  busy,
}: {
  orgId: string;
  memberOf: AccessTeam[];
  value: string;
  onValueChange: (value: string) => void;
  onAdd: () => void;
  busy: boolean;
}) {
  const [teams, setTeams] = React.useState<AccessTeam[] | null>(null);
  const [error, setError] = React.useState<string | null>(null);

  React.useEffect(() => {
    let cancelled = false;

    void (async () => {
      try {
        const organizations = await api.oauth.organizations.list();
        const target =
          organizations.organizations.find(
            (organization) => organization.org_name === orgId || organization.org_code === orgId,
          ) ?? organizations.organizations[0];

        if (!target) {
          if (!cancelled) setTeams([]);
          return;
        }

        const rows = await api.oauth.organizations.teams(target.org_id);
        if (!cancelled) setTeams((rows ?? []).map(toTeam));
      } catch (failure) {
        if (!cancelled) setError(describeFailure(failure, "read the teams"));
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [orgId]);

  if (error) {
    return <InlineAlert className="mb-2 items-start">{error}</InlineAlert>;
  }

  const joinable = (teams ?? []).filter(
    (team) => !memberOf.some((current) => current.teamId === team.teamId),
  );

  if (teams !== null && joinable.length === 0) {
    return (
      <p className="mb-2 border border-border px-2.5 py-2 text-xs text-muted-foreground">
        {teams.length === 0
          ? "No teams exist. Teams are created by the server's organization data, not from Houston."
          : "This account is already in every team."}
      </p>
    );
  }

  return (
    <div className="mb-2 flex items-center gap-2">
      <Select value={value} onValueChange={onValueChange} disabled={teams === null}>
        <SelectTrigger className="flex-1" aria-label="Team to join">
          <SelectValue placeholder={teams === null ? "Loading teams…" : "Select a team…"} />
        </SelectTrigger>
        <SelectContent>
          {joinable.map((team) => (
            <SelectItem key={team.teamId} value={team.teamId}>
              {team.name}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
      <Button size="sm" onClick={onAdd} disabled={!value} loading={busy}>
        Add
      </Button>
    </div>
  );
}
