"use client";

import { Check, Lock, Plus } from "lucide-react";

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
import { Banner } from "@/components/ui/feedback";
import { ScopeBadge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import type { Queue } from "@/lib/types";

const ABILITIES = [
  { key: "send", label: "Send" },
  { key: "receive", label: "Receive" },
  { key: "purge", label: "Purge" },
  { key: "remove", label: "Delete" },
] as const;

const BLOCKED = "No queue-permission endpoint exists — nothing here can be saved";

type GrantProvenance = "direct" | "bypass";

interface RoleGrant {
  role: string;
  kind: "built-in" | "custom";
  users: number;
  provenance: GrantProvenance;
  send: boolean;
  receive: boolean;
  purge: boolean;
  remove: boolean;
}

/**
 * Sample rows, not a read.
 *
 * Unlike Messages and Metrics — both of which are wired to real endpoints —
 * `/api/v1` exposes no queue-permission route, so there is nothing to fetch.
 * These four rows exist to show the *shape* the matrix will take, and every
 * surface that renders them says on the page that they were not read from the
 * server. They are deliberately not exported: nothing else may mistake them
 * for data.
 */
const SAMPLE_ROLE_GRANTS: RoleGrant[] = [
  {
    role: "Administrator",
    kind: "built-in",
    users: 1,
    provenance: "bypass",
    send: true,
    receive: true,
    purge: true,
    remove: true,
  },
  {
    role: "Producer",
    kind: "built-in",
    users: 0,
    provenance: "direct",
    send: true,
    receive: false,
    purge: false,
    remove: false,
  },
  {
    role: "Consumer",
    kind: "built-in",
    users: 3,
    provenance: "direct",
    send: false,
    receive: true,
    purge: false,
    remove: false,
  },
  {
    role: "Billing operator",
    kind: "custom",
    users: 2,
    provenance: "direct",
    send: false,
    receive: true,
    purge: false,
    remove: false,
  },
];

/**
 * S12 — the inverse of the role editor: one queue's grants across every role.
 *
 * Send, Receive, Purge and Delete are independent abilities, and the
 * administrator row is a *bypass* rather than four grants somebody made. That
 * distinction is why there is no single "effective access" column: it would be
 * a number nobody stored.
 */
export function QueueAccess({ queue }: { queue: Queue }) {
  return (
    <div className="flex flex-col gap-4">
      <Banner>
        Sample data — not read from the server. There is no queue-permission endpoint
        behind <span className="font-mono text-[11px]">/api/v1</span>, so no role,
        ability or user count below reflects this deployment, and nothing here can be
        staged or saved.
      </Banner>

      <Panel>
        <PanelTitleBar
          title={
            <span className="inline-flex items-baseline gap-2.5">
              {queue.queueName} — role permissions
              <ScopeBadge>Sample</ScopeBadge>
              <span className="text-[11px] font-normal text-muted-foreground">
                Send · Receive · Purge · Delete are independent abilities
              </span>
            </span>
          }
          action={
            <div className="flex items-center gap-2">
              <Button variant="outline" size="sm" blockedReason={BLOCKED}>
                <Plus aria-hidden />
                Add role permission
              </Button>
              <Button size="sm" blockedReason={BLOCKED}>
                Save
              </Button>
            </div>
          }
        />

        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Role</TableHead>
              <TableHead>Provenance</TableHead>
              {ABILITIES.map((ability) => (
                <TableHead key={ability.key} className="w-[100px] text-center">
                  {ability.label}
                </TableHead>
              ))}
            </TableRow>
          </TableHeader>
          <TableBody>
            {SAMPLE_ROLE_GRANTS.map((grant) => (
              <TableRow
                key={grant.role}
                className={cn(grant.provenance === "bypass" && "bg-muted")}
              >
                <TableCell>
                  <span className="font-semibold">{grant.role}</span>{" "}
                  <span className="text-[11px] text-subtle">
                    {grant.kind} · {grant.users} user{grant.users === 1 ? "" : "s"}
                  </span>
                </TableCell>
                <TableCell>
                  {grant.provenance === "bypass" ? (
                    <span className="inline-flex items-center gap-1.5 text-xs text-muted-foreground">
                      <Lock className="size-3" aria-hidden />
                      Bypass — locked while active
                    </span>
                  ) : (
                    <span className="text-xs text-muted-foreground">Direct grant</span>
                  )}
                </TableCell>
                {ABILITIES.map((ability) => (
                  <AbilityCell
                    key={ability.key}
                    grant={grant}
                    ability={ability.key}
                    label={ability.label}
                  />
                ))}
              </TableRow>
            ))}
          </TableBody>
        </Table>

        <PanelFooter>
          <span className="text-[11px] text-subtle">
            Sample rows, shown to describe the shape this matrix will take. An
            administrator bypass is shown as a bypass, never rewritten into grants.
          </span>
        </PanelFooter>
      </Panel>
    </div>
  );
}

function AbilityCell({
  grant,
  ability,
  label,
}: {
  grant: RoleGrant;
  ability: (typeof ABILITIES)[number]["key"];
  label: string;
}) {
  if (grant.provenance === "bypass") {
    return (
      <TableCell className="text-center font-mono text-[11px] text-subtle">all</TableCell>
    );
  }

  const on = grant[ability];

  // A static square rather than a disabled checkbox: the grants cannot be
  // edited here, and a checkbox would promise a control that does not exist.
  return (
    <TableCell className="text-center">
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
