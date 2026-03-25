import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import { Tabs, TabsList, TabsTab, TabsPanel } from "@/components/ui/tabs";
import { EVICTION_POLICY_LABELS } from "@/lib/constants";
import type { Queue } from "@/lib/types";
import { api } from "@/lib/api-client";
import { formatDistanceToNow } from "date-fns";
import { Trash2, Eraser, ArrowLeft, Copy } from "lucide-react";
import { useState } from "react";
import { Toaster, toast } from "sonner";

interface QueueDetailOverviewProps {
  queue: Queue;
}

export function QueueDetailOverview({ queue }: QueueDetailOverviewProps) {
  const [deleting, setDeleting] = useState(false);
  const [purging, setPurging] = useState(false);

  const handleDelete = async () => {
    if (!confirm(`Delete queue "${queue.queueName}"? This cannot be undone.`)) return;
    setDeleting(true);
    try {
      await api.queues.delete(queue.queueId);
      toast.success("Queue deleted");
      window.location.href = "/";
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to delete queue");
      setDeleting(false);
    }
  };

  const handlePurge = async () => {
    if (!confirm(`Purge all messages from "${queue.queueName}"?`)) return;
    setPurging(true);
    try {
      await api.queues.purge(queue.queueId);
      toast.success("Queue purged");
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to purge queue");
    } finally {
      setPurging(false);
    }
  };

  const copyId = () => {
    navigator.clipboard.writeText(queue.queueId);
    toast.success("Queue ID copied");
  };

  return (
    <div>
      <Toaster position="top-right" />

      {/* Back link + title */}
      <div className="mb-6">
        <a
          href="/"
          className="mb-2 inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground"
        >
          <ArrowLeft className="size-3" />
          Back to queues
        </a>
        <div className="flex items-start justify-between">
          <div>
            <h2 className="text-xl font-semibold">{queue.queueName}</h2>
            <button
              onClick={copyId}
              className="mt-1 inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground"
            >
              <Copy className="size-3" />
              {queue.queueId}
            </button>
          </div>
          <div className="flex gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={handlePurge}
              disabled={purging}
            >
              <Eraser className="size-4" />
              {purging ? "Purging..." : "Purge"}
            </Button>
            <Button
              variant="destructive"
              size="sm"
              onClick={handleDelete}
              disabled={deleting}
            >
              <Trash2 className="size-4" />
              {deleting ? "Deleting..." : "Delete"}
            </Button>
          </div>
        </div>
      </div>

      <Tabs defaultValue="overview">
        <TabsList>
          <TabsTab value="overview">Overview</TabsTab>
          <TabsTab value="messages">Messages</TabsTab>
          <TabsTab value="metrics">Metrics</TabsTab>
          <TabsTab value="settings">Settings</TabsTab>
        </TabsList>

        <TabsPanel value="overview">
          <div className="mt-4 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            <StatCard
              label="Eviction Policy"
              value={EVICTION_POLICY_LABELS[queue.evictionPolicy] ?? queue.evictionPolicy}
            />
            <StatCard
              label="Max Receive Attempts"
              value={String(queue.maxReceiveAttempts)}
            />
            <StatCard
              label="Retention Period"
              value={formatSeconds(queue.retentionPeriodSeconds)}
            />
            <StatCard
              label="Visibility Timeout"
              value={`${queue.visibilityTimeoutSeconds}s`}
            />
            <StatCard
              label="Created"
              value={formatDistanceToNow(new Date(queue.createdAt), {
                addSuffix: true,
              })}
            />
            {queue.deadLetterQueueId && (
              <StatCard
                label="Dead Letter Queue"
                value={queue.deadLetterQueueId}
              />
            )}
          </div>
        </TabsPanel>

        <TabsPanel value="messages">
          <div className="mt-4 flex h-48 items-center justify-center rounded-lg border border-dashed text-muted-foreground">
            Message browser coming soon
          </div>
        </TabsPanel>

        <TabsPanel value="metrics">
          <div className="mt-4 flex h-48 items-center justify-center rounded-lg border border-dashed text-muted-foreground">
            Queue metrics coming soon
          </div>
        </TabsPanel>

        <TabsPanel value="settings">
          <div className="mt-4 flex h-48 items-center justify-center rounded-lg border border-dashed text-muted-foreground">
            Queue settings coming soon
          </div>
        </TabsPanel>
      </Tabs>
    </div>
  );
}

function StatCard({ label, value }: { label: string; value: string }) {
  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-sm font-medium text-muted-foreground">
          {label}
        </CardTitle>
      </CardHeader>
      <CardContent>
        <p className="text-2xl font-semibold">{value}</p>
      </CardContent>
    </Card>
  );
}

function formatSeconds(seconds: number): string {
  if (seconds >= 86400) return `${Math.floor(seconds / 86400)}d`;
  if (seconds >= 3600) return `${Math.floor(seconds / 3600)}h`;
  if (seconds >= 60) return `${Math.floor(seconds / 60)}m`;
  return `${seconds}s`;
}
