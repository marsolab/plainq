"use client";

import * as React from "react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { InlineAlert } from "@/components/ui/feedback";
import { Panel } from "@/components/ui/panel";
import { Status } from "@/components/ui/status";
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
import { cn } from "@/lib/utils";

import {
  MOCK_QUEUES,
  PERMISSION_KEYS,
  PERMISSION_LABELS,
  countGrants,
  emptyPermissions,
  usersWithRole,
  type AccessRole,
  type AccessUser,
  type PermissionKey,
  type QueueGrant,
} from "./mock-data";

const BYPASS_REASON =
  "Administrator bypasses per-queue checks in the server. Its grants can't be edited until the bypass becomes a real grant set.";

interface RolesSectionProps {
  roles: AccessRole[];
  users: AccessUser[];
  onRolesChange: (roles: AccessRole[]) => void;
  blockedReason?: string;
}

function cloneGrants(grants: QueueGrant[]): QueueGrant[] {
  return grants.map((grant) => ({ ...grant, permissions: { ...grant.permissions } }));
}

function sameGrants(a: QueueGrant[], b: QueueGrant[]): boolean {
  if (a.length !== b.length) return false;
  return a.every((grant, index) => {
    const other = b[index];
    if (!other || other.queueId !== grant.queueId) return false;
    return PERMISSION_KEYS.every((key) => grant.permissions[key] === other.permissions[key]);
  });
}

export function RolesSection({
  roles,
  users,
  onRolesChange,
  blockedReason,
}: RolesSectionProps) {
  const [selectedRoleId, setSelectedRoleId] = React.useState(
    roles.find((role) => role.kind === "custom")?.roleId ?? roles[0]?.roleId ?? "",
  );
  /**
   * Matrix edits stage per role rather than auto-saving each cell — a role can
   * carry dozens of grants and a half-applied permission set is a hazard. The
   * draft is keyed by role so switching rows never silently discards work.
   */
  const [drafts, setDrafts] = React.useState<Record<string, QueueGrant[]>>({});
  const [saving, setSaving] = React.useState(false);
  const [addQueueId, setAddQueueId] = React.useState("");

  const role = roles.find((candidate) => candidate.roleId === selectedRoleId);
  if (!role) return null;

  const grants = drafts[role.roleId] ?? role.grants;
  const dirty = Boolean(drafts[role.roleId]) && !sameGrants(grants, role.grants);
  const assigned = usersWithRole(users, role.roleId);
  const locked = Boolean(role.bypass);
  const editBlocked = locked ? BYPASS_REASON : blockedReason;

  const ungranted = MOCK_QUEUES.filter(
    (queue) => !grants.some((grant) => grant.queueId === queue.queueId),
  );

  const stage = (next: QueueGrant[]) => {
    setDrafts((current) => ({ ...current, [role.roleId]: next }));
  };

  const toggle = (queueId: string, key: PermissionKey) => {
    stage(
      grants.map((grant) =>
        grant.queueId === queueId
          ? {
              ...grant,
              permissions: { ...grant.permissions, [key]: !grant.permissions[key] },
            }
          : grant,
      ),
    );
  };

  const addQueue = (queueId: string) => {
    const queue = MOCK_QUEUES.find((candidate) => candidate.queueId === queueId);
    if (!queue) return;
    stage([...cloneGrants(grants), { ...queue, permissions: emptyPermissions() }]);
    setAddQueueId("");
  };

  const cancel = () => {
    setDrafts((current) => {
      const next = { ...current };
      delete next[role.roleId];
      return next;
    });
  };

  const save = async () => {
    setSaving(true);
    // Grants have no endpoint yet; the delay stands in for the round-trip so
    // the staged state behaves the way it will once one exists.
    await new Promise((resolve) => window.setTimeout(resolve, 400));
    onRolesChange(
      roles.map((candidate) =>
        candidate.roleId === role.roleId
          ? { ...candidate, grants: cloneGrants(grants) }
          : candidate,
      ),
    );
    cancel();
    setSaving(false);
    toast.success(`${role.name} grants saved`);
  };

  const changed = (queueId: string, key: PermissionKey): boolean => {
    const saved = role.grants.find((grant) => grant.queueId === queueId);
    const staged = grants.find((grant) => grant.queueId === queueId);
    if (!staged) return false;
    if (!saved) return staged.permissions[key];
    return saved.permissions[key] !== staged.permissions[key];
  };

  return (
    <Panel>
      <div className="flex items-center justify-between gap-4 border-b border-border px-4 py-3">
        <div className="flex items-center gap-2.5">
          <span className="text-sm font-semibold">{role.name}</span>
          <Badge>{role.kind === "built-in" ? "Built-in" : "Custom"}</Badge>
          <span className="text-xs text-muted-foreground">
            {assigned.length} {assigned.length === 1 ? "user" : "users"} assigned
          </span>
        </div>
        <div className="flex items-center gap-2">
          {dirty ? (
            <Status tone="warning" markerClassName="size-[7px]">
              Unsaved changes
            </Status>
          ) : null}
          <Button variant="outline" size="sm" disabled={!dirty || saving} onClick={cancel}>
            Cancel
          </Button>
          <Button
            size="sm"
            loading={saving}
            disabled={!dirty}
            blockedReason={editBlocked}
            onClick={() => void save()}
          >
            Save changes
          </Button>
        </div>
      </div>

      {locked ? (
        <div className="border-b border-border p-4">
          <InlineAlert tone="warning" className="items-start">
            {BYPASS_REASON}
          </InlineAlert>
        </div>
      ) : null}

      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Queue</TableHead>
            {PERMISSION_KEYS.map((key) => (
              <TableHead key={key} className="w-[110px] text-center">
                {PERMISSION_LABELS[key]}
              </TableHead>
            ))}
          </TableRow>
        </TableHeader>
        <TableBody>
          {grants.map((grant) => (
            <TableRow key={grant.queueId}>
              <TableCell className="py-2.5">
                <span className="block text-[13px] leading-[17px] font-semibold">
                  {grant.queueName}
                </span>
                <span className="block font-mono text-[10px] text-muted-foreground">
                  {grant.queueId}
                </span>
              </TableCell>
              {PERMISSION_KEYS.map((key) => (
                <TableCell
                  key={key}
                  className={cn(
                    "py-2.5 text-center",
                    changed(grant.queueId, key) && "bg-warning-surface",
                  )}
                >
                  <span className="inline-flex">
                    <Checkbox
                      checked={grant.permissions[key]}
                      disabled={Boolean(editBlocked)}
                      title={editBlocked}
                      onCheckedChange={() => toggle(grant.queueId, key)}
                      aria-label={`${PERMISSION_LABELS[key]} on ${grant.queueName}`}
                    />
                  </span>
                </TableCell>
              ))}
            </TableRow>
          ))}

          <TableRow>
            <TableCell className="py-2.5">
              <Select
                value={addQueueId}
                onValueChange={addQueue}
                disabled={Boolean(editBlocked) || ungranted.length === 0}
              >
                <SelectTrigger size="sm" aria-label="Add queue permission">
                  <SelectValue placeholder="+ Add queue permission" />
                </SelectTrigger>
                <SelectContent>
                  {ungranted.map((queue) => (
                    <SelectItem key={queue.queueId} value={queue.queueId}>
                      {queue.queueName}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </TableCell>
            <TableCell colSpan={PERMISSION_KEYS.length} className="py-2.5 whitespace-normal">
              <span className="text-xs text-muted-foreground">
                {ungranted.length === 0
                  ? "Every known queue already has a grant for this role."
                  : "Queues without grants for this role. A new row starts with nothing granted."}
              </span>
            </TableCell>
          </TableRow>
        </TableBody>
      </Table>

      <div className="grid grid-cols-1 border-t border-border md:grid-cols-2">
        <div className="border-b border-border px-4 py-3 md:border-r md:border-b-0">
          <div className="caption mb-2">Role list — actual grants, not names</div>
          <div className="flex flex-col gap-1.5">
            {roles.map((candidate) => {
              const total = countGrants(candidate);
              const editing = Boolean(
                drafts[candidate.roleId] &&
                  !sameGrants(drafts[candidate.roleId]!, candidate.grants),
              );

              return (
                <button
                  key={candidate.roleId}
                  type="button"
                  onClick={() => setSelectedRoleId(candidate.roleId)}
                  aria-label={`Edit ${candidate.name} grants`}
                  aria-current={candidate.roleId === role.roleId ? "true" : undefined}
                  className={cn(
                    "flex cursor-pointer items-baseline justify-between gap-4 px-1 py-0.5 text-left text-xs",
                    candidate.roleId === role.roleId ? "bg-muted" : "hover:bg-muted",
                  )}
                >
                  <span className="font-medium">
                    {candidate.name}{" "}
                    <span className="text-subtle">
                      · {candidate.kind}
                      {candidate.bypass ? " · locked" : ""}
                    </span>
                  </span>
                  <span className="shrink-0 font-mono text-muted-foreground">
                    {candidate.bypass
                      ? "bypass (integration target)"
                      : total === 0
                        ? "0 grants configured"
                        : `${total} ${total === 1 ? "grant" : "grants"}`}
                    {editing ? " · editing" : ""}
                  </span>
                </button>
              );
            })}
          </div>
        </div>

        <div className="px-4 py-3">
          <div className="caption mb-2">Guards</div>
          <div className="flex flex-col gap-1.5 text-xs leading-normal text-strong">
            <span>
              {assigned.length > 0
                ? `Role in use can't be deleted — reassign its ${assigned.length} ${
                    assigned.length === 1 ? "user" : "users"
                  } first.`
                : "No users hold this role, so it can be deleted without reassignment."}
            </span>
            <span>Concurrent change → reload or review server values; no silent overwrite.</span>
            <span>No queues yet → role persists; grants can be added later.</span>
          </div>
        </div>
      </div>
    </Panel>
  );
}
