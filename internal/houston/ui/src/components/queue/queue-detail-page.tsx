import { useEffect, useState } from "react";
import { QueueDetailOverview } from "./queue-detail-overview";
import { Skeleton } from "@/components/ui/skeleton";
import { api } from "@/lib/api-client";
import type { Queue } from "@/lib/types";

export function QueueDetailPage() {
  const queueId = typeof window !== "undefined"
    ? window.location.pathname.split("/").filter(Boolean).pop() ?? ""
    : "";
  const [queue, setQueue] = useState<Queue | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.queues
      .get(queueId)
      .then(setQueue)
      .catch((err) =>
        setError(err instanceof Error ? err.message : "Failed to load queue"),
      )
      .finally(() => setLoading(false));
  }, [queueId]);

  if (loading) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-8 w-48" />
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {Array.from({ length: 5 }).map((_, i) => (
            <Skeleton key={i} className="h-24 rounded-xl" />
          ))}
        </div>
      </div>
    );
  }

  if (error || !queue) {
    return (
      <div className="flex h-48 items-center justify-center rounded-lg border border-dashed">
        <p className="text-sm text-muted-foreground">
          {error || "Queue not found"}
        </p>
      </div>
    );
  }

  return <QueueDetailOverview queue={queue} />;
}
