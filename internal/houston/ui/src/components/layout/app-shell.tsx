import { SidebarNav } from "./sidebar-nav";
import { Header } from "./header";
import type { ReactNode } from "react";

interface AppShellProps {
  currentPath: string;
  title: string;
  subtitle?: string;
  children: ReactNode;
}

export function AppShell({
  currentPath,
  title,
  subtitle,
  children,
}: AppShellProps) {
  return (
    <div className="flex h-screen">
      {/* Sidebar */}
      <aside className="flex w-56 shrink-0 flex-col border-r bg-sidebar">
        <div className="flex h-14 items-center gap-2 border-b px-6">
          <div className="flex size-6 items-center justify-center rounded-md bg-primary text-primary-foreground text-xs font-bold">
            Q
          </div>
          <span className="text-sm font-semibold tracking-tight">PlainQ</span>
        </div>
        <div className="flex-1 overflow-y-auto py-4">
          <SidebarNav currentPath={currentPath} />
        </div>
      </aside>

      {/* Main content */}
      <div className="flex flex-1 flex-col overflow-hidden">
        <Header title={title} subtitle={subtitle} />
        <main className="flex-1 overflow-y-auto p-6">{children}</main>
      </div>
    </div>
  );
}
