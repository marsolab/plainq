"use client";

import * as React from "react";
import { toast } from "sonner";

import { api } from "@/lib/api-client";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { EmptyState } from "@/components/ui/empty-state";
import { InlineAlert } from "@/components/ui/feedback";
import { Panel } from "@/components/ui/panel";
import { Skeleton } from "@/components/ui/skeleton";
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
  PERMISSION_KEYS,
  PERMISSION_LABELS,
  countGrants,
  describeFailure,
  emptyPermissions,
  grantsOf,
  sameGrants,
  type AccessRole,
  type PermissionKey,
  type QueueGrant,
} from "./model";

/**
 * Grants are stored by the server but not yet consulted on queue operations:
 * the permission middleware exists and is not mounted on the queue routes. The
 * matrix is therefore a real, persisted configuration that governs nothing
 * yet — and the screen has to say so rather than imply enforcement.
 */
const NOT_ENFORCED =
  "Grants are stored and read back by the server, but queue operations don't consult them yet — PlainQ doesn't mount its queue-permission middleware. Configure them now; they take effect when it does.";

interface QueueRef {
  queueId: string;
  queueName: string;
}

interface RolesSectionProps {
  roles: AccessRole[];
  loading: boolean;
  error: string | null;
  blockedReason?: string;
  onRetry: () => void;
  /** Role counts move when grants change nothing, but roles can be added. */
  onRolesChanged: () => void;
}

function cloneGrants(grants: QueueGrant[]): QueueGrant[] {
  return grants.map((grant) => ({ ...grant, permissions: { ...grant.permissions } }));
}

export function RolesSection({
  roles,
  loading,
  error,
  blockedReason,
  onRetry,
  onRolesChanged,
}: RolesSectionProps) {
  const [selectedRoleId, setSelectedRoleId] = React.useState("");
  const [saved, setSaved] = React.useState<QueueGrant[] | null>(null);
  const [draft, setDraft] = React.useState<QueueGrant[] | null>(null);
  const [grantsError, setGrantsError] = React.useState<string | null>(null);
  const [grantsLoading, setGrantsLoading] = React.useState(false);
  const [saving, setSaving] = React.useState(false);
  const [saveError, setSaveError] = React.useState<string | null>(null);
  const [addQueueId, setAddQueueId] = React.useState("");
  const [queues, setQueues] = React.useState<QueueRef[]>([]);
  const [queuesError, setQueuesError] = React.useState<string | null>(null);

  const role = roles.find((candidate) => candidate.roleId === selectedRoleId) ?? roles[0] ?? null;
  const roleId = role?.roleId ?? "";

  // Queue names come from the queue list; a grant whose queue is missing keeps
  // its ID rather than disappearing from the matrix.
  React.useEffect(() => {
    let cancelled = false;

    void (async () => {
      try {
        const response = await api.queues.list({ limit: 100 });
        if (!cancelled) {
          setQueues(
            (response.queues ?? []).map((queue) => ({
              queueId: queue.queueId,
              queueName: queue.queueName,
            })),
          );
          setQueuesError(null);
        }
      } catch (failure) {
        if (!cancelled) setQueuesError(describeFailure(failure, "read the queue list"));
      }
    })();

    return () => {
      cancelled = true;
    };
  }, []);

  const loadGrants = React.useCallback(
    async (targetRoleId: string, targetQueues: QueueRef[]) => {
      if (!targetRoleId) return;

      setGrantsLoading(true);

      try {
        const response = await api.rbac.permissions.forRole(targetRoleId);
        setSaved(grantsOf(response.grants ?? [], targetQueues));
        setDraft(null);
        setGrantsError(null);
      } catch (failure) {
        setSaved(null);
        setGrantsError(describeFailure(failure, "read this role's grants"));
      } finally {
        setGrantsLoading(false);
      }
    },
    [],
  );

  React.useEffect(() => {
    void loadGrants(roleId, queues);
  }, [loadGrants, roleId, queues]);

  if (loading && roles.length === 0) {
    return (
      <Panel className="p-4">
        <Skeleton className="h-4 w-40" />
      </Panel>
    );
  }

  if (error && roles.length === 0) {
    return (
      <Panel className="max-w-[640px]">
        <EmptyState
          title="Roles could not be read"
          description={error}
          action={
            <Button variant="outline" onClick={onRetry}>
              Try again
            </Button>
          }
        />
      </Panel>
    );
  }

  if (!role) {
    return (
      <Panel className="max-w-[640px]">
        <EmptyState
          title="No roles defined"
          description="A role is what a queue grant attaches to. Create one on the server to start granting permissions."
        />
      </Panel>
    );
  }

  const grants = draft ?? saved ?? [];
  const dirty = draft !== null && saved !== null && !sameGrants(draft, saved);
  const ungranted = queues.filter(
    (queue) => !grants.some((grant) => grant.queueId === queue.queueId),
  );

  const stage = (next: QueueGrant[]) => setDraft(next);

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
    const queue = queues.find((candidate) => candidate.queueId === queueId);
    if (!queue) return;

    stage([...cloneGrants(grants), { ...queue, permissions: emptyPermissions() }]);
    setAddQueueId("");
  };

  const cancel = () => {
    setDraft(null);
    setSaveError(null);
  };

  const save = async () => {
    setSaving(true);
    setSaveError(null);

    try {
      // The server applies the whole matrix in one transaction and answers
      // with what it stored, so the rows below become the stored values rather
      // than the ones that were staged.
      const response = await api.rbac.permissions.replaceForRole(
        role.roleId,
        grants.map((grant) => ({
          queue_id: grant.queueId,
          can_send: grant.permissions.send,
          can_receive: grant.permissions.receive,
          can_purge: grant.permissions.purge,
          can_delete: grant.permissions.delete,
        })),
      );

      setSaved(grantsOf(response.grants ?? [], queues));
      setDraft(null);
      onRolesChanged();
      toast.success(`${role.name} grants saved`);
    } catch (failure) {
      setSaveError(describeFailure(failure, `save the ${role.name} grants`));
    } finally {
      setSaving(false);
    }
  };

  const changed = (queueId: string, key: PermissionKey): boolean => {
    if (!saved || !draft) return false;

    const stored = saved.find((grant) => grant.queueId === queueId);
    const staged = draft.find((grant) => grant.queueId === queueId);
    if (!staged) return false;
    if (!stored) return staged.permissions[key];

    return stored.permissions[key] !== staged.permissions[key];
  };

  return (
    <div className="flex flex-col gap-3">
      <InlineAlert tone="warning" className="items-start">
        {NOT_ENFORCED}
      </InlineAlert>

      {queuesError ? (
        <InlineAlert className="items-start">
          {queuesError} Grants still load and save; rows show queue IDs instead of names.
        </InlineAlert>
      ) : null}

      {saveError ? <InlineAlert className="items-start">{saveError}</InlineAlert> : null}

      <Panel>
        <div className="flex items-center justify-between gap-4 border-b border-border px-4 py-3">
          <div className="flex items-center gap-2.5">
            <span className="text-sm font-semibold">{role.name}</span>
            {role.isAdmin ? <Badge>Authorization role</Badge> : null}
            <span className="text-xs text-muted-foreground">
              {role.userCount} {role.userCount === 1 ? "account" : "accounts"} assigned
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
              blockedReason={blockedReason}
              onClick={() => void save()}
            >
              Save changes
            </Button>
          </div>
        </div>

        {role.isAdmin ? (
          <div className="border-b border-border p-4">
            <InlineAlert tone="warning" className="items-start">
              Accounts with this role pass PlainQ's queue-permission check without consulting the
              grants below — that is what the check does when it is mounted. The rows are still
              stored, and still shown, rather than being rewritten into an implied "all".
            </InlineAlert>
          </div>
        ) : null}

        {grantsError ? (
          <div className="p-4">
            <InlineAlert
              className="items-start"
              action={
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => void loadGrants(role.roleId, queues)}
                >
                  Retry
                </Button>
              }
            >
              {grantsError}
            </InlineAlert>
          </div>
        ) : (
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
              {grantsLoading && saved === null ? (
                <TableRow>
                  <TableCell colSpan={PERMISSION_KEYS.length + 1} className="py-2.5">
                    <Skeleton className="h-[13px] w-40" />
                  </TableCell>
                </TableRow>
              ) : (
                grants.map((grant) => (
                  <TableRow key={grant.queueId}>
                    <TableCell className="py-2.5">
                      <span className="block text-[13px] leading-[17px] font-semibold">
                        {grant.queueName || (
                          <span className="text-muted-foreground">
                            Queue not in the current list
                          </span>
                        )}
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
                            disabled={Boolean(blockedReason)}
                            title={blockedReason}
                            onCheckedChange={() => toggle(grant.queueId, key)}
                            aria-label={`${PERMISSION_LABELS[key]} on ${grant.queueName || grant.queueId}`}
                          />
                        </span>
                      </TableCell>
                    ))}
                  </TableRow>
                ))
              )}

              <TableRow>
                <TableCell className="py-2.5">
                  <Select
                    value={addQueueId}
                    onValueChange={addQueue}
                    disabled={Boolean(blockedReason) || ungranted.length === 0}
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
                <TableCell
                  colSpan={PERMISSION_KEYS.length}
                  className="py-2.5 whitespace-normal"
                >
                  <span className="text-xs text-muted-foreground">
                    {queues.length === 0
                      ? "No queues to grant on yet."
                      : ungranted.length === 0
                        ? "Every queue in the list already has a row for this role."
                        : "Queues without a row for this role. A new row starts with nothing granted."}
                  </span>
                </TableCell>
              </TableRow>
            </TableBody>
          </Table>
        )}

        <div className="grid grid-cols-1 border-t border-border md:grid-cols-2">
          <div className="border-b border-border px-4 py-3 md:border-r md:border-b-0">
            <div className="caption mb-2">Role list — actual grants, not names</div>
            <div className="flex flex-col gap-1.5">
              {roles.map((candidate) => {
                const selected = candidate.roleId === role.roleId;
                const total = selected ? countGrants(grants) : null;

                return (
                  <button
                    key={candidate.roleId}
                    type="button"
                    onClick={() => setSelectedRoleId(candidate.roleId)}
                    aria-label={`Edit ${candidate.name} grants`}
                    aria-current={selected ? "true" : undefined}
                    className={cn(
                      "flex cursor-pointer items-baseline justify-between gap-4 px-1 py-0.5 text-left text-xs",
                      selected ? "bg-muted" : "hover:bg-muted",
                    )}
                  >
                    <span className="font-medium">
                      {candidate.name}{" "}
                      <span className="text-subtle">
                        · {candidate.userCount}{" "}
                        {candidate.userCount === 1 ? "account" : "accounts"}
                      </span>
                    </span>
                    <span className="shrink-0 font-mono text-muted-foreground">
                      {/*
                        Only the open role's grants have been read. Printing a
                        count for the others would be a number nobody fetched.
                      */}
                      {total === null
                        ? "grants not read"
                        : total === 0
                          ? "0 grants configured"
                          : `${total} ${total === 1 ? "grant" : "grants"}`}
                      {selected && dirty ? " · editing" : ""}
                    </span>
                  </button>
                );
              })}
            </div>
          </div>

          <div className="px-4 py-3">
            <div className="caption mb-2">Guards the server enforces</div>
            <div className="flex flex-col gap-1.5 text-xs leading-normal text-strong">
              <span>A role still held by an account can't be deleted — the server answers 409.</span>
              <span>
                The last account holding <span className="font-mono">admin</span> can't lose it,
                and that role can't be renamed or deleted.
              </span>
              <span>Saving replaces the whole matrix in one transaction — no partial writes.</span>
            </div>
          </div>
        </div>
      </Panel>
    </div>
  );
}
