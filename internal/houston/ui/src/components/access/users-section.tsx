"use client";

import * as React from "react";
import { ChevronLeft, ChevronRight, MoreHorizontal, Search, Users } from "lucide-react";

import { Badge, ScopeBadge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { EmptyState } from "@/components/ui/empty-state";
import { InlineAlert } from "@/components/ui/feedback";
import { Input } from "@/components/ui/input";
import { Panel } from "@/components/ui/panel";
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

import type { DirectoryState } from "./access-page";
import { UserDetailSheet } from "./user-detail-sheet";
import { roleById, type AccessRole } from "./model";

const ALL = "__all__";

/** How long typing settles before the directory is asked again. */
const SEARCH_DEBOUNCE_MS = 250;

interface UsersSectionProps {
  directory: DirectoryState;
  roles: AccessRole[];
  search: string;
  hasPrevious: boolean;
  pageSize: number;
  blockedReason?: string;
  onSearchChange: (search: string) => void;
  onNextPage: () => void;
  onPreviousPage: () => void;
  onRetry: () => void;
  /** A write landed; the page refetches rather than patching local state. */
  onChanged: () => void;
}

export function UsersSection({
  directory,
  roles,
  search,
  hasPrevious,
  pageSize,
  blockedReason,
  onSearchChange,
  onNextPage,
  onPreviousPage,
  onRetry,
  onChanged,
}: UsersSectionProps) {
  const [query, setQuery] = React.useState(search);
  const [accountType, setAccountType] = React.useState(ALL);
  const [roleFilter, setRoleFilter] = React.useState(ALL);
  const [selectedUserId, setSelectedUserId] = React.useState<string | null>(null);

  // Email search runs on the server, so it spans the whole directory rather
  // than the page in hand. Everything else filters the rows already fetched,
  // and the footer says which is which.
  React.useEffect(() => {
    if (query === search) return;

    const timer = window.setTimeout(() => onSearchChange(query), SEARCH_DEBOUNCE_MS);

    return () => window.clearTimeout(timer);
  }, [query, search, onSearchChange]);

  const { users, loading, error, total, hasMore } = directory;

  const accountTypes = React.useMemo(
    () => Array.from(new Set(users.map((user) => user.accountType))).sort(),
    [users],
  );

  const filtered = React.useMemo(
    () =>
      users.filter((user) => {
        if (accountType !== ALL && user.accountType !== accountType) return false;
        if (roleFilter !== ALL && !user.roleIds.includes(roleFilter)) return false;
        return true;
      }),
    [users, accountType, roleFilter],
  );

  const selectedUser = users.find((user) => user.userId === selectedUserId) ?? null;

  /**
   * Skeletons stand in for rows we have never had. A refresh over rows that
   * already exist keeps them on screen — the Retry button carries the pending
   * signal instead, so a failed refresh never blanks the table it labelled STALE.
   */
  const coldLoad = loading && users.length === 0;
  const stale = error !== null && users.length > 0;

  if (error && users.length === 0 && !loading) {
    return (
      <Panel className="max-w-[640px]">
        <EmptyState
          icon={Users}
          title="The account directory could not be read"
          description={error}
          action={
            <Button variant="outline" onClick={onRetry} loading={loading}>
              Try again
            </Button>
          }
        />
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
          {stale ? <ScopeBadge>Stale</ScopeBadge> : null}
          <Micro>
            {/*
              `total` counts every account matching the email search, which is
              a count the server returned. The row count is this page after the
              local filters, so the two are labelled separately.
            */}
            {filtered.length} shown · {total} {total === 1 ? "account" : "accounts"}
          </Micro>
        </div>
      </div>

      {stale && error ? (
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
                    {Array.from({ length: 8 }, (_, cell) => (
                      <TableCell key={cell}>
                        <Skeleton className="h-[13px] w-20" />
                      </TableCell>
                    ))}
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
                    <TableCell>
                      {user.organization || <span className="text-subtle">—</span>}
                    </TableCell>
                    <TableCell>
                      <span className="flex flex-wrap items-center gap-1.5">
                        {user.roleIds.length === 0 ? (
                          <span className="text-subtle">—</span>
                        ) : (
                          user.roleIds.map((roleId) => {
                            const role = roleById(roles, roleId);

                            return <Badge key={roleId}>{role?.name ?? roleId}</Badge>;
                          })
                        )}
                      </span>
                    </TableCell>
                    <TableCell className="text-muted-foreground">
                      {user.teamIds.length === 0 ? (
                        <span className="text-subtle">—</span>
                      ) : (
                        `${user.teamIds.length} ${user.teamIds.length === 1 ? "team" : "teams"}`
                      )}
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
          users.length === 0 && !search ? (
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

        <div className="flex items-center justify-between gap-4 border-t border-border px-4 py-2.5">
          <Micro className="text-subtle">
            {pageSize} accounts per request · cursor pagination · email search runs on the server,
            account type and role filter this page
          </Micro>
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={onPreviousPage}
              disabled={loading || !hasPrevious}
            >
              <ChevronLeft aria-hidden />
              Previous
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={onNextPage}
              disabled={loading || !hasMore}
            >
              Next
              <ChevronRight aria-hidden />
            </Button>
          </div>
        </div>
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
        blockedReason={blockedReason}
        onOpenChange={(open) => {
          if (!open) setSelectedUserId(null);
        }}
        onChanged={onChanged}
      />
    </div>
  );
}
