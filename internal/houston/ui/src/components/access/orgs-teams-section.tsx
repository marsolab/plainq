"use client";

import * as React from "react";
import { ChevronRight, Plus } from "lucide-react";
import { toast } from "sonner";

import { api } from "@/lib/api-client";
import { Button } from "@/components/ui/button";
import { EmptyState } from "@/components/ui/empty-state";
import { InlineAlert } from "@/components/ui/feedback";
import { Panel } from "@/components/ui/panel";
import { Skeleton } from "@/components/ui/skeleton";
import { Micro } from "@/components/ui/value";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { cn } from "@/lib/utils";

import { DependencyNotice, QuietNotice } from "./notice";
import {
  describeFailure,
  membersOfTeam,
  toTeam,
  type AccessOrganization,
  type AccessTeam,
  type AccessUser,
} from "./model";

interface OrgsTeamsSectionProps {
  /** The directory page in hand — membership is read off it. */
  users: AccessUser[];
  usersLoading: boolean;
  blockedReason?: string;
  onMembershipChanged: () => void;
}

interface DirectoryShape {
  organizations: AccessOrganization[];
  multiTenancy: boolean;
  userOrg: string;
}

export function OrgsTeamsSection({
  users,
  usersLoading,
  blockedReason,
  onMembershipChanged,
}: OrgsTeamsSectionProps) {
  const [shape, setShape] = React.useState<DirectoryShape | null>(null);
  const [error, setError] = React.useState<string | null>(null);
  const [loading, setLoading] = React.useState(true);
  const [selectedOrgId, setSelectedOrgId] = React.useState("");
  const [selectedTeamId, setSelectedTeamId] = React.useState("");
  const [adding, setAdding] = React.useState(false);
  const [pendingUserId, setPendingUserId] = React.useState("");
  const [busy, setBusy] = React.useState<string | null>(null);
  const [notice, setNotice] = React.useState<string | null>(null);

  const load = React.useCallback(async () => {
    setLoading(true);

    try {
      const response = await api.oauth.organizations.list();

      // Teams belong to an organization, so they are fetched per organization
      // rather than assumed to exist. An organization whose teams fail to load
      // is reported with none rather than with a guess.
      const organizations = await Promise.all(
        (response.organizations ?? []).map(async (organization) => ({
          organizationId: organization.org_id,
          code: organization.org_code,
          name: organization.org_name,
          teams: (await api.oauth.organizations.teams(organization.org_id) ?? []).map(toTeam),
        })),
      );

      setShape({
        organizations,
        multiTenancy: response.multi_tenancy_enabled,
        userOrg: response.user_org,
      });
      setError(null);
    } catch (failure) {
      setError(describeFailure(failure, "read the organizations"));
    } finally {
      setLoading(false);
    }
  }, []);

  React.useEffect(() => {
    void load();
  }, [load]);

  if (loading && !shape) {
    return (
      <Panel className="p-4">
        <Skeleton className="h-4 w-48" />
      </Panel>
    );
  }

  if (error && !shape) {
    return (
      <Panel className="max-w-[640px]">
        <EmptyState
          title="Organizations could not be read"
          description={error}
          action={
            <Button variant="outline" onClick={() => void load()}>
              Try again
            </Button>
          }
        />
      </Panel>
    );
  }

  const organizations = shape?.organizations ?? [];

  if (organizations.length === 0) {
    return (
      <Panel className="max-w-[640px]">
        <DependencyNotice title="No organizations exist on this server">
          Organizations come from the server's own data; Houston has no create, rename or delete
          API for them. Roles still apply globally.
        </DependencyNotice>
      </Panel>
    );
  }

  const organization =
    organizations.find((candidate) => candidate.organizationId === selectedOrgId) ??
    organizations[0]!;
  const team =
    organization.teams.find((candidate) => candidate.teamId === selectedTeamId) ??
    organization.teams[0] ??
    null;

  const members = team ? membersOfTeam(users, team.teamId) : [];
  const candidates = users.filter((user) => !user.teamIds.includes(team?.teamId ?? ""));

  const run = async (key: string, action: string, work: () => Promise<void>) => {
    setBusy(key);
    setError(null);

    try {
      await work();
      onMembershipChanged();
    } catch (failure) {
      setError(describeFailure(failure, action));
    } finally {
      setBusy(null);
    }
  };

  const addMember = (target: AccessTeam) => {
    const user = users.find((candidate) => candidate.userId === pendingUserId);
    if (!user) return;

    void run(`add:${user.userId}`, `add ${user.email} to ${target.name}`, async () => {
      await api.oauth.userTeams.add(user.userId, target.teamId);
      setAdding(false);
      setPendingUserId("");
      setNotice(null);
      toast.success(`${user.email} added to ${target.name}`);
    });
  };

  const removeMember = (target: AccessTeam, user: AccessUser) => {
    void run(`remove:${user.userId}`, `remove ${user.email} from ${target.name}`, async () => {
      await api.oauth.userTeams.remove(user.userId, target.teamId);
      setNotice(null);
      toast.success(`${user.email} removed from ${target.name}`);
    });
  };

  return (
    <div className="flex flex-col gap-3">
      {error ? <InlineAlert className="items-start">{error}</InlineAlert> : null}

      {!shape?.multiTenancy ? (
        <QuietNotice>
          Multi-tenancy is disabled on this server, so every account shares one organization and
          the boundary below is descriptive rather than enforced.
        </QuietNotice>
      ) : null}

      <Panel className="grid grid-cols-1 lg:grid-cols-[1fr_1.1fr]">
        <div className="border-b border-border lg:border-r lg:border-b-0">
          <div className="flex h-11 items-center justify-between gap-3 border-b border-border px-4">
            <span className="text-[13px] font-semibold">{organization.name}</span>
            <Micro className="text-[10px]">
              {organization.organizationId === shape?.userOrg
                ? "your organization · read-only"
                : "read-only"}
            </Micro>
          </div>

          {organizations.length > 1 ? (
            <div className="border-b border-border px-4 py-2.5">
              <Select
                value={organization.organizationId}
                onValueChange={(value) => {
                  setSelectedOrgId(value);
                  setSelectedTeamId("");
                }}
              >
                <SelectTrigger className="w-full" aria-label="Organization">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {organizations.map((candidate) => (
                    <SelectItem key={candidate.organizationId} value={candidate.organizationId}>
                      {candidate.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          ) : null}

          <div className="py-1.5">
            {organization.teams.length === 0 ? (
              <p className="px-4 py-3 text-xs text-muted-foreground">
                This organization has no teams.
              </p>
            ) : (
              organization.teams.map((candidate, index) => {
                const active = candidate.teamId === team?.teamId;
                const count = membersOfTeam(users, candidate.teamId).length;

                return (
                  <button
                    key={candidate.teamId}
                    type="button"
                    onClick={() => {
                      setSelectedTeamId(candidate.teamId);
                      setAdding(false);
                      setNotice(null);
                    }}
                    aria-current={active ? "true" : undefined}
                    className={cn(
                      "flex w-full cursor-pointer items-center justify-between gap-3 px-4 py-2.5 text-left",
                      index > 0 && "border-t border-border",
                      active
                        ? "bg-muted shadow-[inset_2px_0_0_var(--color-foreground)]"
                        : "hover:bg-muted",
                    )}
                  >
                    <span className="min-w-0">
                      <span className="block text-[13px] leading-[17px] font-semibold">
                        {candidate.name}
                      </span>
                      <span className="block text-[11px] text-muted-foreground">
                        {/*
                          Counted from the directory page in hand, so it is a
                          count of members visible here, not of the team.
                        */}
                        {count} on this page · {candidate.code}
                      </span>
                    </span>
                    <ChevronRight
                      className="size-[13px] shrink-0 text-muted-foreground"
                      aria-hidden
                    />
                  </button>
                );
              })
            )}
          </div>

          <div className="border-t border-border px-4 py-2.5 text-[11px] leading-[15px] text-subtle">
            Organizations and teams are read-only here — create, rename and delete have no API.
            Only membership can be changed.
          </div>
        </div>

        <div>
          <div className="flex h-11 items-center justify-between gap-3 border-b border-border px-4">
            <span className="text-[13px] font-semibold">
              {team ? `${team.name} — members` : "Members"}
            </span>
            <Button
              variant="outline"
              size="sm"
              blockedReason={blockedReason}
              disabled={!team}
              aria-expanded={adding}
              onClick={() => {
                setAdding((open) => !open);
                setNotice(null);
              }}
            >
              <Plus aria-hidden />
              Add member
            </Button>
          </div>

          {adding && team ? (
            <div className="flex items-center gap-2 border-b border-border px-4 py-2.5">
              <Select value={pendingUserId} onValueChange={setPendingUserId}>
                <SelectTrigger className="flex-1" aria-label="Account to add">
                  <SelectValue placeholder="Select an account…" />
                </SelectTrigger>
                <SelectContent>
                  {candidates.map((user) => (
                    <SelectItem key={user.userId} value={user.userId}>
                      {user.email}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <Button
                size="sm"
                disabled={!pendingUserId}
                loading={busy === `add:${pendingUserId}`}
                onClick={() => addMember(team)}
              >
                Add
              </Button>
            </div>
          ) : null}

          {notice ? (
            <div className="border-b border-border px-4 py-2.5">
              <QuietNotice>{notice}</QuietNotice>
            </div>
          ) : null}

          <div className="py-1.5">
            {usersLoading && users.length === 0 ? (
              <div className="px-4 py-3">
                <Skeleton className="h-[13px] w-40" />
              </div>
            ) : members.length > 0 && team ? (
              members.map((user, index) => (
                <div
                  key={user.userId}
                  className={cn(
                    "flex items-center justify-between gap-3 px-4 py-2",
                    index > 0 && "border-t border-border",
                  )}
                >
                  <span className="text-[13px] font-medium">{user.email}</span>
                  <Button
                    variant="ghost"
                    size="sm"
                    blockedReason={blockedReason}
                    loading={busy === `remove:${user.userId}`}
                    onClick={() => removeMember(team, user)}
                  >
                    Remove
                  </Button>
                </div>
              ))
            ) : (
              <p className="px-4 py-3 text-xs text-muted-foreground">
                No members of this team on the current page of accounts. Adding one grants
                nothing on its own.
              </p>
            )}
          </div>

          <div className="flex flex-col gap-1.5 border-t border-border px-4 py-2.5">
            <div className="text-[11px] leading-[15px] text-subtle">
              Membership is stored, but PlainQ derives no roles from a team yet, so no
              effective-permission view is shown — a guessed answer about who can do what is
              worse than none.
            </div>
          </div>
        </div>
      </Panel>
    </div>
  );
}
