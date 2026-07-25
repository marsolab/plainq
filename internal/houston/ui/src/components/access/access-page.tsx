"use client";

import * as React from "react";

import { api, isAdministrator } from "@/lib/api-client";
import { PageHeader } from "@/components/ui/page-header";
import { Banner } from "@/components/ui/feedback";
import { cn } from "@/lib/utils";

import { UsersSection } from "./users-section";
import { RolesSection } from "./roles-section";
import { OrgsTeamsSection } from "./orgs-teams-section";
import { IdentityProvidersSection } from "./identity-providers-section";
import { describeFailure, toRole, toUser, type AccessRole, type AccessUser } from "./model";

const SECTIONS = [
  { id: "users", label: "Users" },
  { id: "roles", label: "Roles" },
  { id: "organizations", label: "Organizations & Teams" },
  { id: "providers", label: "Identity providers" },
] as const;

type SectionId = (typeof SECTIONS)[number]["id"];

/** Accounts per directory request. The server caps a page at 200. */
const PAGE_SIZE = 50;

const READ_ONLY_REASON =
  "Your role can read access configuration but not change it — the server refuses these writes.";

function readSection(search: string): SectionId {
  const raw = new URLSearchParams(search).get("section");
  return SECTIONS.find((section) => section.id === raw)?.id ?? "users";
}

/**
 * The directory as one request's worth of state. Keeping the error beside the
 * rows is what lets a failed refresh keep the last good page on screen instead
 * of blanking a table it has just labelled stale.
 */
export interface DirectoryState {
  users: AccessUser[];
  total: number;
  nextCursor: string;
  hasMore: boolean;
  loading: boolean;
  error: string | null;
}

const EMPTY_DIRECTORY: DirectoryState = {
  users: [],
  total: 0,
  nextCursor: "",
  hasMore: false,
  loading: true,
  error: null,
};

export function AccessPage() {
  const [section, setSection] = React.useState<SectionId>("users");

  // Sections are addressable (/access?section=roles), so the URL is the source
  // of truth for which one is open — including after Back and Forward.
  React.useEffect(() => {
    const sync = () => setSection(readSection(window.location.search));
    sync();
    window.addEventListener("popstate", sync);
    return () => window.removeEventListener("popstate", sync);
  }, []);

  /**
   * Whether this operator may write. The token the server issued carries the
   * roles it will check, so a control can be blocked with its reason instead of
   * failing with a 403 after the fact. It is not the enforcement — every write
   * below is refused server-side regardless — and an unreadable token means
   * "unknown", which blocks nothing.
   */
  const [administrator, setAdministrator] = React.useState<boolean | null>(null);

  React.useEffect(() => setAdministrator(isAdministrator()), []);

  const blockedReason = administrator === false ? READ_ONLY_REASON : undefined;

  const [directory, setDirectory] = React.useState<DirectoryState>(EMPTY_DIRECTORY);
  const [search, setSearch] = React.useState("");
  /** Cursors already consumed, so Previous is a real position, not a re-scan. */
  const [cursors, setCursors] = React.useState<string[]>([]);

  const [roles, setRoles] = React.useState<AccessRole[]>([]);
  const [rolesError, setRolesError] = React.useState<string | null>(null);
  const [rolesLoading, setRolesLoading] = React.useState(true);

  const cursor = cursors[cursors.length - 1] ?? "";

  const loadDirectory = React.useCallback(async (params: { cursor: string; search: string }) => {
    setDirectory((current) => ({ ...current, loading: true }));

    try {
      const page = await api.directory.users({
        limit: PAGE_SIZE,
        cursor: params.cursor || undefined,
        search: params.search || undefined,
      });

      setDirectory({
        users: (page.users ?? []).map(toUser),
        total: page.total,
        nextCursor: page.next_cursor,
        hasMore: page.has_more,
        loading: false,
        error: null,
      });
    } catch (error) {
      // Keep whatever rows are on screen: a refresh that failed says nothing
      // about the accounts the last successful read returned.
      setDirectory((current) => ({
        ...current,
        loading: false,
        error: describeFailure(error, "read the account directory"),
      }));
    }
  }, []);

  const loadRoles = React.useCallback(async () => {
    setRolesLoading(true);

    try {
      setRoles((await api.rbac.roles.list()).map(toRole));
      setRolesError(null);
    } catch (error) {
      setRolesError(describeFailure(error, "read the roles"));
    } finally {
      setRolesLoading(false);
    }
  }, []);

  React.useEffect(() => {
    void loadDirectory({ cursor, search });
  }, [loadDirectory, cursor, search]);

  React.useEffect(() => {
    void loadRoles();
  }, [loadRoles]);

  const refreshDirectory = React.useCallback(
    () => loadDirectory({ cursor, search }),
    [loadDirectory, cursor, search],
  );

  /** A membership or role change moves a user's counts, so both are refetched. */
  const refreshAll = React.useCallback(async () => {
    await Promise.all([refreshDirectory(), loadRoles()]);
  }, [refreshDirectory, loadRoles]);

  const open = (next: SectionId) => {
    const params = new URLSearchParams(window.location.search);
    params.set("section", next);
    window.history.pushState(null, "", `${window.location.pathname}?${params}`);
    setSection(next);
  };

  return (
    <div>
      <PageHeader
        title="Access"
        description="Users, roles, and how queue permissions are granted."
      />

      {blockedReason ? (
        <Banner className="mb-4">
          You are signed in without the administrator role. Everything on this page is readable;
          nothing on it can be changed.
        </Banner>
      ) : null}

      <div className="mb-5 flex gap-5 border-b border-border">
        {SECTIONS.map((item) => {
          const active = item.id === section;

          return (
            <a
              key={item.id}
              href={`/access?section=${item.id}`}
              aria-current={active ? "page" : undefined}
              onClick={(event) => {
                if (event.metaKey || event.ctrlKey || event.shiftKey) return;
                event.preventDefault();
                open(item.id);
              }}
              className={cn(
                "px-0.5 py-2 text-[13px]",
                active
                  ? "font-semibold text-foreground shadow-[inset_0_-2px_0_var(--color-foreground)]"
                  : "font-medium text-muted-foreground hover:text-foreground",
              )}
            >
              {item.label}
            </a>
          );
        })}
      </div>

      {section === "users" ? (
        <UsersSection
          directory={directory}
          roles={roles}
          search={search}
          hasPrevious={cursors.length > 0}
          pageSize={PAGE_SIZE}
          blockedReason={blockedReason}
          onSearchChange={(next) => {
            // A new filter is a new scan, so the cursor stack cannot carry over.
            setCursors([]);
            setSearch(next);
          }}
          onNextPage={() =>
            setCursors((current) =>
              directory.nextCursor ? [...current, directory.nextCursor] : current,
            )
          }
          onPreviousPage={() => setCursors((current) => current.slice(0, -1))}
          onRetry={() => void refreshDirectory()}
          onChanged={() => void refreshAll()}
        />
      ) : null}

      {section === "roles" ? (
        <RolesSection
          roles={roles}
          loading={rolesLoading}
          error={rolesError}
          blockedReason={blockedReason}
          onRetry={() => void loadRoles()}
          onRolesChanged={() => void loadRoles()}
        />
      ) : null}

      {section === "organizations" ? (
        <OrgsTeamsSection
          users={directory.users}
          usersLoading={directory.loading}
          blockedReason={blockedReason}
          onMembershipChanged={() => void refreshDirectory()}
        />
      ) : null}

      {section === "providers" ? (
        <IdentityProvidersSection blockedReason={blockedReason} />
      ) : null}
    </div>
  );
}
