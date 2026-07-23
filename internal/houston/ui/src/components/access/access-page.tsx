"use client";

import * as React from "react";

import { PageHeader } from "@/components/ui/page-header";
import { cn } from "@/lib/utils";

import { UsersSection } from "./users-section";
import { RolesSection } from "./roles-section";
import { OrgsTeamsSection } from "./orgs-teams-section";
import { IdentityProvidersSection } from "./identity-providers-section";
import {
  MOCK_IDENTITY_PROVIDERS,
  MOCK_ORGANIZATIONS,
  MOCK_ROLES,
  MOCK_USERS,
  loadDirectory,
  readScenario,
  type AccessOrganization,
  type AccessRole,
  type AccessScenario,
  type AccessUser,
  type DirectoryStatus,
  type IdentityProvider,
} from "./mock-data";

const SECTIONS = [
  { id: "users", label: "Users" },
  { id: "roles", label: "Roles" },
  { id: "organizations", label: "Organizations & Teams" },
  { id: "providers", label: "Identity providers" },
] as const;

type SectionId = (typeof SECTIONS)[number]["id"];

const READ_ONLY_REASON = "Your role can read access configuration but not change it.";

function readSection(search: string): SectionId {
  const raw = new URLSearchParams(search).get("section");
  return SECTIONS.find((section) => section.id === raw)?.id ?? "users";
}

export function AccessPage() {
  const [section, setSection] = React.useState<SectionId>("users");
  const [scenario, setScenario] = React.useState<AccessScenario>("ok");

  // Sections are addressable (/access?section=roles), so the URL is the source
  // of truth for which one is open — including after Back and Forward.
  React.useEffect(() => {
    const sync = () => {
      setSection(readSection(window.location.search));
      setScenario(readScenario(window.location.search));
    };
    sync();
    window.addEventListener("popstate", sync);
    return () => window.removeEventListener("popstate", sync);
  }, []);

  const [roles, setRoles] = React.useState<AccessRole[]>(MOCK_ROLES);
  const [organizations, setOrganizations] =
    React.useState<AccessOrganization[]>(MOCK_ORGANIZATIONS);
  const [providers, setProviders] =
    React.useState<IdentityProvider[]>(MOCK_IDENTITY_PROVIDERS);

  /**
   * The directory lives here beside roles and organizations, not inside the
   * Users section: a sub-tab unmounts its section, and a role or team change
   * made in the user sheet must still be there after a trip to Roles.
   */
  const [users, setUsers] = React.useState<AccessUser[]>([]);
  const [directoryStatus, setDirectoryStatus] = React.useState<DirectoryStatus>("ok");
  const [directoryError, setDirectoryError] = React.useState<string | null>(null);
  const [directoryLoading, setDirectoryLoading] = React.useState(true);

  const fetchDirectory = React.useCallback(async (target: AccessScenario) => {
    setDirectoryLoading(true);
    const result = await loadDirectory(target);
    setDirectoryStatus(result.status);
    setDirectoryError(result.error ?? null);
    // A failed refresh keeps the last good rows rather than blanking the table.
    if (result.status === "ok" || result.users.length > 0) {
      setUsers(result.users);
    }
    setDirectoryLoading(false);
  }, []);

  React.useEffect(() => {
    void fetchDirectory(scenario);
  }, [fetchDirectory, scenario]);

  const applyUserChange = React.useCallback((next: AccessUser) => {
    setUsers((current) =>
      current.map((user) => (user.userId === next.userId ? next : user)),
    );
  }, []);

  const blockedReason = scenario === "read-only" ? READ_ONLY_REASON : undefined;
  const organizationName = organizations[0]?.name ?? "default";

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

      <div className="mb-5 flex gap-5 border-b border-border">
        {SECTIONS.map((item) => {
          const active = item.id === section;
          const href =
            scenario === "ok"
              ? `/access?section=${item.id}`
              : `/access?section=${item.id}&scenario=${scenario}`;

          return (
            <a
              key={item.id}
              href={href}
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
          users={users}
          loading={directoryLoading}
          status={directoryStatus}
          error={directoryError}
          roles={roles}
          organizations={organizations}
          blockedReason={blockedReason}
          onRetry={() => void fetchDirectory("ok")}
          onUserChange={applyUserChange}
          onOrganizationsChange={setOrganizations}
        />
      ) : null}

      {/*
        Roles and Organizations read the seeded account list, not the fetched
        directory: they stand in for their own endpoints, and the `?scenario=`
        switch only models what list-users answers. Showing "0 users assigned"
        because that one call failed would be asserting something we don't know.
      */}
      {section === "roles" ? (
        <RolesSection
          roles={roles}
          users={MOCK_USERS}
          onRolesChange={setRoles}
          blockedReason={blockedReason}
        />
      ) : null}

      {section === "organizations" ? (
        <OrgsTeamsSection
          organizations={organizations}
          roles={roles}
          users={MOCK_USERS}
          onOrganizationsChange={setOrganizations}
          blockedReason={blockedReason}
        />
      ) : null}

      {section === "providers" ? (
        <IdentityProvidersSection
          providers={providers}
          organizationName={organizationName}
          onProvidersChange={setProviders}
          blockedReason={blockedReason}
        />
      ) : null}
    </div>
  );
}
