import {
  LayoutDashboard,
  RadioTower,
  ChartLine,
  Shield,
  Server,
  type LucideIcon,
} from "lucide-react";

import { cn } from "@/lib/utils";
import { ScopeBadge } from "@/components/ui/badge";

export interface NavItem {
  label: string;
  href: string;
  icon: LucideIcon;
  /** Marks a surface whose transport is still experimental. */
  scope?: string;
  /** Hidden outright when the operator lacks the permission — never disabled. */
  requires?: "access";
  /** Sections whose paths also light this item up. */
  match?: string[];
}

export const NAV_ITEMS: NavItem[] = [
  { label: "Queues", href: "/", icon: LayoutDashboard, match: ["/queue"] },
  { label: "Pub/Sub", href: "/pubsub", icon: RadioTower, scope: "EXP" },
  // The server reserves /metrics for its Prometheus scrape endpoint, so the
  // telemetry surface lives at /telemetry and keeps the operator-facing name.
  { label: "Metrics", href: "/telemetry", icon: ChartLine },
  { label: "Access", href: "/access", icon: Shield, requires: "access" },
  { label: "System", href: "/system", icon: Server },
];

export function isActive(item: NavItem, currentPath: string): boolean {
  if (item.href === "/") {
    return (
      currentPath === "/" || (item.match ?? []).some((p) => currentPath.startsWith(p))
    );
  }
  return currentPath.startsWith(item.href);
}

interface SidebarNavProps {
  currentPath: string;
  /**
   * A restricted operator simply does not see Access. The section is
   * irrelevant to them, so hiding beats disabling.
   */
  canManageAccess?: boolean;
}

export function SidebarNav({ currentPath, canManageAccess = true }: SidebarNavProps) {
  const items = NAV_ITEMS.filter(
    (item) => item.requires !== "access" || canManageAccess,
  );

  return (
    <nav className="flex flex-col gap-0.5 px-2 py-3">
      {items.map((item) => {
        const active = isActive(item, currentPath);

        return (
          <a
            key={item.href}
            href={item.href}
            aria-current={active ? "page" : undefined}
            className={cn(
              "flex items-center gap-2.5 px-2.5 py-2 text-[13px] transition-colors",
              active
                ? "bg-sidebar-active font-semibold text-foreground shadow-[inset_2px_0_0_var(--color-foreground)]"
                : "font-medium text-sidebar-muted hover:bg-sidebar-active hover:text-foreground",
            )}
          >
            <item.icon className="size-[15px] shrink-0" aria-hidden />
            {item.label}
            {item.scope ? <ScopeBadge className="ml-auto">{item.scope}</ScopeBadge> : null}
          </a>
        );
      })}
    </nav>
  );
}
