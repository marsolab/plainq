import type { ReactNode } from "react";

import { SidebarNav } from "./sidebar-nav";
import { Header, type SessionUser } from "./header";
import { Wordmark } from "./wordmark";
import { Status } from "@/components/ui/status";
import { initialOf } from "@/lib/format";

export type ServiceHealth = "healthy" | "degraded" | "unknown";

interface AppShellProps {
  currentPath: string;
  title: string;
  children: ReactNode;

  /** Top-bar freshness and refresh, owned by the page's data. */
  updatedAt?: Date | string | null;
  onRefresh?: () => void;
  refreshing?: boolean;

  user?: SessionUser | null;
  authEnabled?: boolean;
  canManageAccess?: boolean;

  health?: ServiceHealth;
  version?: string;

  /**
   * Page-level notice rendered above the content — telemetry loss, degraded
   * datastore. Never blocks the page it sits on.
   */
  banner?: ReactNode;
}

const HEALTH_LABEL: Record<ServiceHealth, string> = {
  healthy: "Service healthy",
  degraded: "Service degraded",
  unknown: "Service status unknown",
};

export function AppShell({
  currentPath,
  title,
  children,
  updatedAt,
  onRefresh,
  refreshing,
  user,
  authEnabled = true,
  canManageAccess = true,
  health = "healthy",
  version,
  banner,
}: AppShellProps) {
  return (
    <div className="flex h-screen bg-background">
      <aside className="flex w-56 shrink-0 flex-col border-r border-sidebar-border bg-sidebar">
        <div className="flex h-14 shrink-0 items-center border-b border-sidebar-border px-4">
          <a href="/" aria-label="PlainQ Houston — Queues">
            <Wordmark />
          </a>
        </div>

        <div className="flex-1 overflow-y-auto">
          <SidebarNav currentPath={currentPath} canManageAccess={canManageAccess} />
        </div>

        <div className="mt-auto flex flex-col gap-3 border-t border-sidebar-border px-4 py-3">
          <div className="flex items-center gap-2">
            <Status tone={health === "unknown" ? "warning" : health} className="text-xs text-strong">
              {HEALTH_LABEL[health]}
            </Status>
            {version ? (
              <span className="ml-auto font-mono text-[10px] text-muted-foreground">
                {version}
              </span>
            ) : null}
          </div>

          {authEnabled ? (
            user ? (
              <div className="flex items-center gap-2">
                <span className="inline-flex size-6 shrink-0 items-center justify-center border border-border bg-surface text-[10px] font-semibold">
                  {initialOf(user.email)}
                </span>
                <div className="min-w-0">
                  <div className="truncate text-xs font-medium">{user.email}</div>
                  {user.role ? (
                    <div className="text-[11px] text-muted-foreground">{user.role}</div>
                  ) : null}
                </div>
              </div>
            ) : null
          ) : (
            <Status tone="warning" className="text-xs">
              Authentication disabled
            </Status>
          )}
        </div>
      </aside>

      <div className="flex flex-1 flex-col overflow-hidden">
        <Header
          title={title}
          updatedAt={updatedAt}
          onRefresh={onRefresh}
          refreshing={refreshing}
          user={user}
          authEnabled={authEnabled}
        />
        <main className="flex-1 overflow-y-auto">
          {banner ? <div className="px-6 pt-4">{banner}</div> : null}
          <div className="p-6">{children}</div>
        </main>
      </div>
    </div>
  );
}
