"use client";

import * as React from "react";
import { Lock, Plus } from "lucide-react";

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
  roleById,
  roleNames,
  setTeamMembers,
  teamById,
  teamsForUser,
  usersWithRole,
  type AccessOrganization,
  type AccessRole,
  type AccessTeam,
  type AccessUser,
} from "./mock-data";

const ADMINISTRATOR_ROLE_ID = "role_administrator";

interface UserDetailSheetProps {
  user: AccessUser | null;
  /** The full directory — the last-administrator check needs the whole set. */
  users: AccessUser[];
  roles: AccessRole[];
  organizations: AccessOrganization[];
  /** Set when this operator may read the directory but not change it. */
  blockedReason?: string;
  onOpenChange: (open: boolean) => void;
  onChange: (next: AccessUser) => void;
  /** Team membership is a team-roster edit, the same one the S21 panel makes. */
  onOrganizationsChange: (organizations: AccessOrganization[]) => void;
}

export function UserDetailSheet({
  user,
  users,
  roles,
  organizations,
  blockedReason,
  onOpenChange,
  onChange,
  onOrganizationsChange,
}: UserDetailSheetProps) {
  const [assigningRole, setAssigningRole] = React.useState(false);
  const [pendingRoleId, setPendingRoleId] = React.useState("");
  const [addingTeam, setAddingTeam] = React.useState(false);
  const [pendingTeamId, setPendingTeamId] = React.useState("");
  const [notice, setNotice] = React.useState<string | null>(null);

  // Every draft belongs to the row that was opened; reopening starts clean.
  React.useEffect(() => {
    setAssigningRole(false);
    setPendingRoleId("");
    setAddingTeam(false);
    setPendingTeamId("");
    setNotice(null);
  }, [user?.userId]);

  if (!user) return null;

  const teams = organizations.flatMap((organization) => organization.teams);
  const memberships = teamsForUser(organizations, user.email);
  const isProviderBacked = user.accountType !== "Local";
  const administrators = usersWithRole(users, ADMINISTRATOR_ROLE_ID);
  const holdsLastAdministrator =
    user.roleIds.includes(ADMINISTRATOR_ROLE_ID) && administrators.length <= 1;

  const lastAdministratorReason = `Can't remove Administrator from ${user.email} — it's the only administrator account. Assign the role to another user first.`;

  const assignRole = () => {
    const role = roleById(roles, pendingRoleId);
    if (!role) return;

    if (user.roleIds.includes(role.roleId)) {
      // A duplicate assignment is a 409: the server changed nothing and says so.
      setNotice(`${user.email} already has the ${role.name} role. Nothing changed.`);
      setPendingRoleId("");
      return;
    }

    onChange({ ...user, roleIds: [...user.roleIds, role.roleId] });
    setNotice(null);
    setAssigningRole(false);
    setPendingRoleId("");
  };

  const removeRole = (roleId: string) => {
    onChange({ ...user, roleIds: user.roleIds.filter((id) => id !== roleId) });
    setNotice(null);
  };

  const addTeam = () => {
    const team = teamById(organizations, pendingTeamId);
    if (!team) return;

    if (team.memberEmails.includes(user.email)) {
      setNotice(`${user.email} is already in the ${team.name} team. Nothing changed.`);
      setPendingTeamId("");
      return;
    }

    onOrganizationsChange(
      setTeamMembers(organizations, team.teamId, [...team.memberEmails, user.email]),
    );
    setNotice(null);
    setAddingTeam(false);
    setPendingTeamId("");
  };

  const removeTeam = (team: AccessTeam) => {
    onOrganizationsChange(
      setTeamMembers(
        organizations,
        team.teamId,
        team.memberEmails.filter((email) => email !== user.email),
      ),
    );
    setNotice(null);
  };

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
              <Button size="sm" onClick={assignRole} disabled={!pendingRoleId}>
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
              if (!role) return null;
              const blocked =
                roleId === ADMINISTRATOR_ROLE_ID && holdsLastAdministrator
                  ? lastAdministratorReason
                  : blockedReason;

              return (
                <SheetRow
                  key={roleId}
                  label={role.name}
                  hint={role.kind === "built-in" ? "Built-in" : "Custom"}
                  action={
                    <Button
                      variant="ghost"
                      size="sm"
                      blockedReason={blocked}
                      onClick={() => removeRole(roleId)}
                    >
                      Remove
                    </Button>
                  }
                />
              );
            })
          )}

          {holdsLastAdministrator ? (
            <InlineAlert className="mt-2 items-start">{lastAdministratorReason}</InlineAlert>
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
          note="Team-derived roles are shown only when inheritance can actually be computed — never guessed."
        >
          {addingTeam ? (
            <div className="mb-2 flex items-center gap-2">
              <Select value={pendingTeamId} onValueChange={setPendingTeamId}>
                <SelectTrigger className="flex-1" aria-label="Team to join">
                  <SelectValue placeholder="Select a team…" />
                </SelectTrigger>
                <SelectContent>
                  {teams.map((team) => (
                    <SelectItem key={team.teamId} value={team.teamId}>
                      {team.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <Button size="sm" onClick={addTeam} disabled={!pendingTeamId}>
                Add
              </Button>
            </div>
          ) : null}

          {memberships.length === 0 ? (
            <p className="border border-border px-2.5 py-3 text-xs text-muted-foreground">
              Not a member of any team.
            </p>
          ) : (
            memberships.map((team) => {
              const derived = roleNames(roles, team.roleIds);

              return (
                <SheetRow
                  key={team.teamId}
                  label={team.name}
                  hint={
                    derived.length > 0
                      ? `Derives: ${derived.join(", ")}`
                      : "No attached roles"
                  }
                  action={
                    <Button
                      variant="ghost"
                      size="sm"
                      blockedReason={blockedReason}
                      onClick={() => removeTeam(team)}
                    >
                      Remove
                    </Button>
                  }
                />
              );
            })
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
