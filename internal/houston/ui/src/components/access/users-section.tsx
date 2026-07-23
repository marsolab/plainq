"use client";

import * as React from "react";
import { MoreHorizontal, Search, Users } from "lucide-react";

import { Badge, ScopeBadge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { EmptyState } from "@/components/ui/empty-state";
import { InlineAlert } from "@/components/ui/feedback";
import { Input } from "@/components/ui/input";
import { Panel, PanelHeader } from "@/components/ui/panel";
import { Skeleton } from "@/components/ui/skeleton";
import { Status } from "@/components/ui/status";
import { Micro, Timestamp } from "@/components/ui/value";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

import { DependencyNotice } from "./notice";
import { UserDetailSheet } from "./user-detail-sheet";
import {
  roleById,
  teamsForUser,
  type AccessOrganization,
  type AccessRole,
  type AccessUser,
  type DirectoryStatus,
} from "./mock-data";

const ALL = "__all__";

interface UsersSectionProps {
  /** The directory is owned by the page so edits survive a sub-tab switch. */
  users: AccessUser[];
  loading: boolean;
  status: DirectoryStatus;
  error: string | null;
  roles: AccessRole[];
  organizations: AccessOrganization[];
  blockedReason?: string;
  onRetry: () => void;
  onUserChange: (next: AccessUser) => void;
  onOrganizationsChange: (organizations: AccessOrganization[]) => void;
}

export function UsersSection({
  users,
  loading,
  status,
  error,
  roles,
  organizations,
  blockedReason,
  onRetry,
  onUserChange,
  onOrganizationsChange,
}: UsersSectionProps) {
  const [query, setQuery] = React.useState("");
  const [accountType, setAccountType] = React.useState(ALL);
  const [roleFilter, setRoleFilter] = React.useState(ALL);
  const [selectedUserId, setSelectedUserId] = React.useState<string | null>(null);

  const accountTypes = React.useMemo(
    () => Array.from(new Set(users.map((user) => user.accountType))).sort(),
    [users],
  );

  const filtered = React.useMemo(
    () =>
      users.filter((user) => {
        if (query && !user.email.toLowerCase().includes(query.trim().toLowerCase())) {
          return false;
        }
        if (accountType !== ALL && user.accountType !== accountType) return false;
        if (roleFilter !== ALL && !user.roleIds.includes(roleFilter)) return false;
        return true;
      }),
    [users, query, accountType, roleFilter],
  );

  const selectedUser = users.find((user) => user.userId === selectedUserId) ?? null;

  /**
   * Skeletons stand in for rows we have never had. A refresh over rows that
   * already exist keeps them on screen — the Retry button carries the pending
   * signal instead, so a failed refresh never blanks the table it labelled STALE.
   */
  const coldLoad = loading && users.length === 0;

  if (status === "unavailable" && !loading) {
    return (
      <Panel className="max-w-[640px]">
        <PanelHeader>State — user directory API unavailable</PanelHeader>
        <DependencyNotice title="The user directory isn't available yet">
          This server version doesn't expose a complete list-users API. Role and permission
          management still works from the Roles tab. No endless skeleton — this is a capability,
          not an error.
        </DependencyNotice>
      </Panel>
    );
  }

  return (
    <div className="flex flex-col gap-3">
      <div className="flex items-center justify-between gap-4">
        <div className="flex items-center gap-2">
          <div className="relative w-[260px]">
            <Search
              className="pointer-events-none absolute top-1/2 left-2.5 size-[13px] -translate-y-1/2 text-muted-foreground"
              aria-hidden
            />
            <Input
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Search by email…"
              aria-label="Search users by email"
              className="pl-[30px]"
            />
          </div>

          <Select value={accountType} onValueChange={setAccountType}>
            <SelectTrigger aria-label="Filter by account type">
              <span>
                Account type: <SelectValue />
              </span>
            </SelectTrigger>
            <SelectContent>
              <SelectItem value={ALL}>All</SelectItem>
              {accountTypes.map((type) => (
                <SelectItem key={type} value={type}>
                  {type}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>

          <Select value={roleFilter} onValueChange={setRoleFilter}>
            <SelectTrigger aria-label="Filter by role">
              <span>
                Role: <SelectValue />
              </span>
            </SelectTrigger>
            <SelectContent>
              <SelectItem value={ALL}>All</SelectItem>
              {roles.map((role) => (
                <SelectItem key={role.roleId} value={role.roleId}>
                  {role.name}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>

        <div className="flex items-center gap-2">
          {status === "stale" ? <ScopeBadge>Stale</ScopeBadge> : null}
          <Micro>
            {filtered.length} {filtered.length === 1 ? "user" : "users"}
          </Micro>
        </div>
      </div>

      {status === "stale" && error ? (
        <InlineAlert
          tone="warning"
          action={
            <Button variant="ghost" size="sm" loading={loading} onClick={onRetry}>
              Retry
            </Button>
          }
        >
          {error} Showing the last response that succeeded.
        </InlineAlert>
      ) : null}

      <Panel>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Email</TableHead>
              <TableHead>Account type</TableHead>
              <TableHead>Verified</TableHead>
              <TableHead>Organization</TableHead>
              <TableHead>Roles</TableHead>
              <TableHead>Teams</TableHead>
              <TableHead>Created</TableHead>
              <TableHead>Last synchronized</TableHead>
              <TableHead className="w-12" />
            </TableRow>
          </TableHeader>
          <TableBody>
            {coldLoad
              ? Array.from({ length: 4 }, (_, index) => (
                  <TableRow key={index}>
                    <TableCell>
                      <Skeleton className="h-[13px] w-36" />
                    </TableCell>
                    <TableCell>
                      <Skeleton className="h-[13px] w-14" />
                    </TableCell>
                    <TableCell>
                      <Skeleton className="h-[13px] w-16" />
                    </TableCell>
                    <TableCell>
                      <Skeleton className="h-[13px] w-12" />
                    </TableCell>
                    <TableCell>
                      <Skeleton className="h-[13px] w-24" />
                    </TableCell>
                    <TableCell>
                      <Skeleton className="h-[13px] w-20" />
                    </TableCell>
                    <TableCell>
                      <Skeleton className="h-[13px] w-24" />
                    </TableCell>
                    <TableCell>
                      <Skeleton className="h-[13px] w-24" />
                    </TableCell>
                    <TableCell />
                  </TableRow>
                ))
              : filtered.map((user) => (
                  <TableRow key={user.userId}>
                    <TableCell className="font-semibold">{user.email}</TableCell>
                    <TableCell>{user.accountType}</TableCell>
                    <TableCell>
                      <Status
                        tone={user.verified ? "healthy" : "neutral"}
                        markerClassName="size-[7px]"
                      >
                        {user.verified ? "Verified" : "Unverified"}
                      </Status>
                    </TableCell>
                    <TableCell>{user.organization}</TableCell>
                    <TableCell>
                      <span className="flex flex-wrap items-center gap-1.5">
                        {user.roleIds.map((roleId) => {
                          const role = roleById(roles, roleId);
                          return role ? <Badge key={roleId}>{role.name}</Badge> : null;
                        })}
                      </span>
                    </TableCell>
                    <TableCell className="text-muted-foreground">
                      {teamsForUser(organizations, user.email)
                        .map((team) => team.name)
                        .join(", ") || "—"}
                    </TableCell>
                    <TableCell>
                      <Timestamp value={user.createdAt} />
                    </TableCell>
                    <TableCell>
                      {user.synchronizedAt ? (
                        <Timestamp value={user.synchronizedAt} />
                      ) : (
                        <span className="text-subtle">—</span>
                      )}
                    </TableCell>
                    <TableCell>
                      {/*
                        One action, so the glyph is the action. There is no
                        invite, suspend, delete or reset to put beside it.
                      */}
                      <Button
                        variant="ghost"
                        size="icon-sm"
                        title="Manage membership"
                        aria-label={`Manage membership for ${user.email}`}
                        onClick={() => setSelectedUserId(user.userId)}
                      >
                        <MoreHorizontal aria-hidden />
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
          </TableBody>
        </Table>

        {!coldLoad && filtered.length === 0 ? (
          users.length === 0 ? (
            <EmptyState
              icon={Users}
              title="No accounts yet"
              description="Accounts appear here once someone signs up or an identity provider synchronizes one. Houston can't create them — there is no invite API."
            />
          ) : (
            <EmptyState
              icon={Search}
              title="No accounts match these filters"
              description="Clear the search or widen the account type and role filters."
              action={
                <Button
                  variant="outline"
                  onClick={() => {
                    setQuery("");
                    setAccountType(ALL);
                    setRoleFilter(ALL);
                  }}
                >
                  Clear filters
                </Button>
              }
            />
          )
        ) : null}
      </Panel>

      <p className="text-[11px] leading-[15px] text-subtle">
        Email is the primary identity — display names aren't reliably persisted across
        providers. There is no invite, delete, suspend or password-reset API, so those actions
        aren't offered.
      </p>

      <UserDetailSheet
        user={selectedUser}
        users={users}
        roles={roles}
        organizations={organizations}
        blockedReason={blockedReason}
        onOpenChange={(open) => {
          if (!open) setSelectedUserId(null);
        }}
        onChange={onUserChange}
        onOrganizationsChange={onOrganizationsChange}
      />
    </div>
  );
}
