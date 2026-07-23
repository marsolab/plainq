"use client";

import * as React from "react";
import { ChevronRight, LoaderCircle, Plus } from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Panel } from "@/components/ui/panel";
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
  MULTI_TENANCY_ENABLED,
  roleNames,
  setTeamMembers,
  type AccessOrganization,
  type AccessRole,
  type AccessUser,
} from "./mock-data";

interface OrgsTeamsSectionProps {
  organizations: AccessOrganization[];
  roles: AccessRole[];
  users: AccessUser[];
  onOrganizationsChange: (organizations: AccessOrganization[]) => void;
  blockedReason?: string;
}

export function OrgsTeamsSection({
  organizations,
  roles,
  users,
  onOrganizationsChange,
  blockedReason,
}: OrgsTeamsSectionProps) {
  const organization = organizations[0];
  const [selectedTeamId, setSelectedTeamId] = React.useState(
    organization?.teams[0]?.teamId ?? "",
  );
  const [adding, setAdding] = React.useState(false);
  const [pendingEmail, setPendingEmail] = React.useState("");
  const [removing, setRemoving] = React.useState<string | null>(null);
  const [notice, setNotice] = React.useState<string | null>(null);

  if (!MULTI_TENANCY_ENABLED || !organization) {
    return (
      <Panel className="max-w-[640px]">
        <DependencyNotice title="Multi-tenancy is disabled on this server">
          Every account belongs to one implicit organization, so there is no directory to show.
          Roles still apply globally.
        </DependencyNotice>
      </Panel>
    );
  }

  const team =
    organization.teams.find((candidate) => candidate.teamId === selectedTeamId) ??
    organization.teams[0];

  const updateTeamMembers = (teamId: string, memberEmails: string[]) => {
    onOrganizationsChange(setTeamMembers(organizations, teamId, memberEmails));
  };

  const addMember = () => {
    if (!team || !pendingEmail) return;

    // The client doesn't pre-filter the roster: membership is the server's
    // fact, and a duplicate is answered with a 409 rather than hidden here.
    if (team.memberEmails.includes(pendingEmail)) {
      setNotice(`${pendingEmail} is already a member of ${team.name}. Nothing changed.`);
      setPendingEmail("");
      return;
    }

    updateTeamMembers(team.teamId, [...team.memberEmails, pendingEmail]);
    setNotice(null);
    setAdding(false);
    setPendingEmail("");
  };

  const removeMember = async (email: string) => {
    if (!team) return;
    setRemoving(email);
    await new Promise((resolve) => window.setTimeout(resolve, 700));
    updateTeamMembers(
      team.teamId,
      team.memberEmails.filter((candidate) => candidate !== email),
    );
    setRemoving(null);
    setNotice(null);
    toast.success(`${email} removed from ${team.name}`);
  };

  const attachedRoles = team ? roleNames(roles, team.roleIds) : [];

  return (
    <Panel className="grid grid-cols-1 lg:grid-cols-[1fr_1.1fr]">
      <div className="border-b border-border lg:border-r lg:border-b-0">
        <div className="flex h-11 items-center justify-between gap-3 border-b border-border px-4">
          <span className="text-[13px] font-semibold">{organization.name}</span>
          <Micro className="text-[10px]">
            {organization.isDefault ? "default organization · read-only" : "read-only"}
          </Micro>
        </div>

        <div className="py-1.5">
          {organization.teams.map((candidate, index) => {
            const active = candidate.teamId === team?.teamId;
            const attached = roleNames(roles, candidate.roleIds);

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
                    {candidate.memberEmails.length}{" "}
                    {candidate.memberEmails.length === 1 ? "member" : "members"} ·{" "}
                    {attached.length > 0
                      ? `roles: ${attached.join(", ")}`
                      : "no attached roles"}
                  </span>
                </span>
                <ChevronRight className="size-[13px] shrink-0 text-muted-foreground" aria-hidden />
              </button>
            );
          })}
        </div>

        <div className="border-t border-border px-4 py-2.5 text-[11px] leading-[15px] text-subtle">
          Organizations and teams are read-only here — create, rename and delete have no API.
          Only membership can be changed.
        </div>
      </div>

      <div>
        <div className="flex h-11 items-center justify-between gap-3 border-b border-border px-4">
          <span className="text-[13px] font-semibold">{team?.name} — members</span>
          <Button
            variant="outline"
            size="sm"
            blockedReason={blockedReason}
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

        {adding ? (
          <div className="flex items-center gap-2 border-b border-border px-4 py-2.5">
            <Select value={pendingEmail} onValueChange={setPendingEmail}>
              <SelectTrigger className="flex-1" aria-label="Account to add">
                <SelectValue placeholder="Select an account…" />
              </SelectTrigger>
              <SelectContent>
                {users.map((user) => (
                  <SelectItem key={user.userId} value={user.email}>
                    {user.email}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Button size="sm" disabled={!pendingEmail} onClick={addMember}>
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
          {team && team.memberEmails.length > 0 ? (
            team.memberEmails.map((email, index) => (
              <div
                key={email}
                className={cn(
                  "flex items-center justify-between gap-3 px-4 py-2",
                  index > 0 && "border-t border-border",
                )}
              >
                <span className="text-[13px] font-medium">{email}</span>
                {removing === email ? (
                  <span className="inline-flex items-center gap-2 text-xs text-muted-foreground">
                    <LoaderCircle className="size-[11px] animate-spin" aria-hidden />
                    Removing…
                  </span>
                ) : (
                  <Button
                    variant="ghost"
                    size="sm"
                    blockedReason={blockedReason}
                    onClick={() => void removeMember(email)}
                  >
                    Remove
                  </Button>
                )}
              </div>
            ))
          ) : (
            <p className="px-4 py-3 text-xs text-muted-foreground">
              No members yet. Adding one grants nothing on its own.
            </p>
          )}
        </div>

        <div className="flex flex-col gap-1.5 border-t border-border px-4 py-2.5">
          <div className="text-[11px] leading-[15px] text-strong">
            {attachedRoles.length > 0 ? (
              <>
                Attached roles:{" "}
                {attachedRoles.map((name) => (
                  <Badge key={name} className="mx-0.5 align-middle">
                    {name}
                  </Badge>
                ))}{" "}
                — members receive this role via the team once inheritance ships; until then it is
                shown as metadata only.
              </>
            ) : (
              "No attached roles — membership in this team grants nothing."
            )}
          </div>
          <div className="text-[11px] leading-[15px] text-subtle">
            No effective-permission view: inheritance can't be computed yet, and a guessed answer
            about who can do what is worse than none.
          </div>
        </div>
      </div>
    </Panel>
  );
}
