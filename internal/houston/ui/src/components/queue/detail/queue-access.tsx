"use client";

import * as React from "react";
import { Check, Lock, ShieldOff } from "lucide-react";

import { api } from "@/lib/api-client";
import { Panel, PanelFooter, PanelTitleBar } from "@/components/ui/panel";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Button } from "@/components/ui/button";
import { EmptyState } from "@/components/ui/empty-state";
import { InlineAlert } from "@/components/ui/feedback";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";
import type { Queue } from "@/lib/types";
import {
  ADMIN_ROLE_NAME,
  PERMISSION_KEYS,
  PERMISSION_LABELS,
  describeFailure,
  permissionsOf,
  type PermissionKey,
  type Permissions,
} from "@/components/access/model";

/**
 * Grants are stored by the server and read back here, but queue operations do
 * not consult them: PlainQ's queue-permission middleware exists and is not
 * mounted on the queue routes. The matrix is a real configuration that governs
 * nothing yet, and saying so is the difference between describing a policy and
 * claiming one is in force.
 */
const NOT_ENFORCED =
  "These grants are stored by the server, but queue operations don't consult them yet — PlainQ doesn't mount its queue-permission middleware on the queue routes. Nothing below currently restricts who can send, receive, purge or delete.";

interface RoleGrant {
  roleId: string;
  role: string;
  users: number;
  /** False when the server stores no row for this role on this queue. */
  granted: boolean;
  /** True for the role the permission check waves through when it is mounted. */
  bypass: boolean;
  permissions: Permissions;
}

/**
 * S12 — the inverse of the role editor: one queue's grants across every role.
 *
 * Send, Receive, Purge and Delete are independent abilities, and the
 * administrator row is a *bypass* rather than four grants somebody made. That
 * distinction is why there is no single "effective access" column: it would be
 * a number nobody stored.
 */
export function QueueAccess({ queue }: { queue: Queue }) {
  const [rows, setRows] = React.useState<RoleGrant[] | null>(null);
  const [error, setError] = React.useState<string | null>(null);
  const [loading, setLoading] = React.useState(true);

  const load = React.useCallback(async () => {
    setLoading(true);

    try {
      const response = await api.rbac.permissions.forQueue(queue.queueId);

      setRows(
        (response ?? []).map((row) => ({
          roleId: row.role.role_id,
          role: row.role.role_name,
          users: row.user_count,
          granted: row.granted,
          bypass: row.role.role_name === ADMIN_ROLE_NAME,
          permissions: permissionsOf(row.permission),
        })),
      );
      setError(null);
    } catch (failure) {
      setError(describeFailure(failure, "read this queue's role permissions"));
    } finally {
      setLoading(false);
    }
  }, [queue.queueId]);

  React.useEffect(() => {
    void load();
  }, [load]);

  if (error && rows === null) {
    return (
      <Panel>
        <EmptyState
          icon={ShieldOff}
          title="Role permissions could not be read"
          description={error}
          action={
            <Button variant="outline" onClick={() => void load()} loading={loading}>
              Try again
            </Button>
          }
        />
      </Panel>
    );
  }

  return (
    <div className="flex flex-col gap-4">
      <InlineAlert tone="warning" className="items-start">
        {NOT_ENFORCED}
      </InlineAlert>

      <Panel>
        <PanelTitleBar
          title={
            <span className="inline-flex items-baseline gap-2.5">
              {queue.queueName} — role permissions
              <span className="text-[11px] font-normal text-muted-foreground">
                Send · Receive · Purge · Delete are independent abilities
              </span>
            </span>
          }
          action={
            <Button variant="outline" size="sm" asChild>
              <a href="/access?section=roles">Edit in Access</a>
            </Button>
          }
        />

        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Role</TableHead>
              <TableHead>Provenance</TableHead>
              {PERMISSION_KEYS.map((key) => (
                <TableHead key={key} className="w-[100px] text-center">
                  {PERMISSION_LABELS[key]}
                </TableHead>
              ))}
            </TableRow>
          </TableHeader>
          <TableBody>
            {rows === null
              ? Array.from({ length: 3 }, (_, index) => (
                  <TableRow key={index}>
                    <TableCell colSpan={PERMISSION_KEYS.length + 2}>
                      <Skeleton className="h-[13px] w-40" />
                    </TableCell>
                  </TableRow>
                ))
              : rows.map((grant) => (
                  <TableRow key={grant.roleId} className={cn(grant.bypass && "bg-muted")}>
                    <TableCell>
                      <span className="font-semibold">{grant.role}</span>{" "}
                      <span className="text-[11px] text-subtle">
                        {grant.users} {grant.users === 1 ? "account" : "accounts"}
                      </span>
                    </TableCell>
                    <TableCell>
                      {grant.bypass ? (
                        <span className="inline-flex items-center gap-1.5 text-xs text-muted-foreground">
                          <Lock className="size-3" aria-hidden />
                          Bypasses the check when it is mounted
                        </span>
                      ) : grant.granted ? (
                        <span className="text-xs text-muted-foreground">Direct grant</span>
                      ) : (
                        <span className="text-xs text-subtle">No grant stored</span>
                      )}
                    </TableCell>
                    {PERMISSION_KEYS.map((key) => (
                      <AbilityCell
                        key={key}
                        on={grant.permissions[key]}
                        ability={key}
                        label={PERMISSION_LABELS[key]}
                      />
                    ))}
                  </TableRow>
                ))}
          </TableBody>
        </Table>

        {rows !== null && rows.length === 0 ? (
          <EmptyState
            icon={ShieldOff}
            title="No roles defined"
            description="A grant attaches to a role, and this server has none. Create one from Access → Roles."
          />
        ) : null}

        <PanelFooter>
          <span className="text-[11px] text-subtle">
            Read from the server for this queue. An administrator bypass is shown as a bypass,
            never rewritten into grants, and a role with no stored row reads as "no grant" rather
            than as an explicit deny.
          </span>
        </PanelFooter>
      </Panel>
    </div>
  );
}

function AbilityCell({
  on,
  ability,
  label,
}: {
  on: boolean;
  ability: PermissionKey;
  label: string;
}) {
  // A static square rather than a disabled checkbox: the grants are edited from
  // the role editor, and a checkbox here would promise a control that is not.
  return (
    <TableCell className="text-center" data-ability={ability}>
      <span
        aria-hidden
        className={cn(
          "inline-flex size-[15px] items-center justify-center",
          on ? "bg-primary text-primary-foreground" : "border border-muted-foreground bg-surface",
        )}
      >
        {on ? <Check className="size-[11px]" strokeWidth={3} /> : null}
      </span>
      <span className="sr-only">{`${label}: ${on ? "on" : "off"}`}</span>
    </TableCell>
  );
}
