"use client";

import * as React from "react";
import { RefreshCw, ChevronDown, LogOut } from "lucide-react";

import {
  DropdownMenu,
  DropdownMenuTrigger,
  DropdownMenuContent,
  DropdownMenuItem,
} from "@/components/ui/dropdown-menu";
import { Button } from "@/components/ui/button";
import { api } from "@/lib/api-client";
import { formatClock, initialOf } from "@/lib/format";
import { cn } from "@/lib/utils";

export interface SessionUser {
  email: string;
  role?: string;
}

interface HeaderProps {
  title: string;
  /** Freshness of the data below. Absent when the page owns no fetched data. */
  updatedAt?: Date | string | null;
  onRefresh?: () => void;
  refreshing?: boolean;
  user?: SessionUser | null;
  /** With auth off there is no account, no sign-out and no /login. */
  authEnabled?: boolean;
}

export function Header({
  title,
  updatedAt,
  onRefresh,
  refreshing = false,
  user,
  authEnabled = true,
}: HeaderProps) {
  const [signingOut, setSigningOut] = React.useState(false);

  const handleSignout = async () => {
    setSigningOut(true);
    try {
      await api.auth.signout();
    } catch {
      // Local credentials are cleared regardless: a failed server revocation
      // must not strand the operator in a session they asked to end.
    }
    window.location.href = "/login";
  };

  return (
    <header className="flex h-14 shrink-0 items-center justify-between border-b border-border bg-surface px-6">
      <span className="text-[13px] font-medium">{title}</span>

      <div className="flex items-center gap-3">
        {updatedAt ? (
          <span className="font-mono text-[11px] text-muted-foreground">
            Updated {formatClock(updatedAt)}
          </span>
        ) : null}

        {onRefresh ? (
          <Button
            variant="outline"
            size="icon-sm"
            onClick={onRefresh}
            disabled={refreshing}
            title="Refresh"
            aria-label="Refresh"
          >
            <RefreshCw className={cn("size-3.5", refreshing && "animate-spin")} aria-hidden />
          </Button>
        ) : null}

        {authEnabled && user ? (
          <>
            <span className="h-5 w-px bg-border" aria-hidden />
            <DropdownMenu>
              <DropdownMenuTrigger
                aria-label="Account menu"
                className="inline-flex cursor-pointer items-center gap-1.5 outline-none"
              >
                <span className="inline-flex size-6 items-center justify-center border border-border bg-background text-[10px] font-semibold">
                  {initialOf(user.email)}
                </span>
                <ChevronDown className="size-3.5 text-muted-foreground" aria-hidden />
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end" className="w-56">
                <div className="border-b border-border px-3 py-2.5">
                  <div className="truncate text-xs font-medium">{user.email}</div>
                  {user.role ? (
                    <div className="mt-px text-[11px] text-muted-foreground">{user.role}</div>
                  ) : null}
                </div>
                <DropdownMenuItem onClick={handleSignout} disabled={signingOut}>
                  <LogOut className="size-3.5" aria-hidden />
                  Sign out
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </>
        ) : null}
      </div>
    </header>
  );
}
