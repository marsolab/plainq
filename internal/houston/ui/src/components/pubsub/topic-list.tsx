import { useEffect, useState } from "react";
import { toast, Toaster } from "sonner";
import { formatDistanceToNow } from "date-fns";
import { RadioTower, Send, Trash2 } from "lucide-react";
import { api } from "@/lib/api-client";
import type { Queue, Topic } from "@/lib/types";
import { TopicMetricsDashboard } from "@/components/metrics/topic-metrics-dashboard";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";

export function TopicList() {
  const [topics, setTopics] = useState<Topic[]>([]);
  const [queues, setQueues] = useState<Queue[]>([]);
  const [topicName, setTopicName] = useState("");
  const [message, setMessage] = useState("Hello from PlainQ pub/sub");
  const [loading, setLoading] = useState(true);
  const [metricsRefreshKey, setMetricsRefreshKey] = useState(0);

  async function refresh() {
    setLoading(true);
    try {
      const [topicData, queueData] = await Promise.all([
        api.topics.list(),
        api.queues.list({ limit: 100 }),
      ]);
      setTopics(topicData.topics ?? []);
      setQueues(queueData.queues ?? []);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to load pub/sub");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    refresh();
  }, []);

  async function createTopic() {
    if (!topicName.trim()) return;
    await api.topics.create({ topicName: topicName.trim() });
    setTopicName("");
    toast.success("Topic created");
    await refresh();
    setMetricsRefreshKey((key) => key + 1);
  }

  async function subscribe(topicId: string, queueId: string) {
    if (!queueId) return;
    await api.topics.subscribe(topicId, queueId);
    toast.success("Queue subscribed");
    await refresh();
    setMetricsRefreshKey((key) => key + 1);
  }

  async function publish(topicId: string) {
    const delivered = await api.topics.publish(topicId, message);
    toast.success(`Published ${delivered.deliveredCount} message deliveries`);
    setMetricsRefreshKey((key) => key + 1);
  }

  return (
    <div className="space-y-6">
      <Toaster position="top-right" />
      <TopicMetricsDashboard topics={topics} refreshKey={metricsRefreshKey} />
      <div className="flex items-end justify-between gap-4">
        <div>
          <h2 className="text-lg font-semibold">Pub/Sub Topics</h2>
          <p className="text-sm text-muted-foreground">
            Fan out a published message to every queue subscribed to a topic.
          </p>
        </div>
        <div className="flex gap-2">
          <Input
            placeholder="topic name"
            value={topicName}
            onChange={(e) => setTopicName(e.target.value)}
          />
          <Button onClick={createTopic}>Create topic</Button>
        </div>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Publish test message</CardTitle>
        </CardHeader>
        <CardContent>
          <Input value={message} onChange={(e) => setMessage(e.target.value)} />
        </CardContent>
      </Card>

      {loading ? (
        <p className="text-sm text-muted-foreground">Loading topics…</p>
      ) : topics.length === 0 ? (
        <div className="rounded-lg border p-8 text-center text-sm text-muted-foreground">
          No topics yet. Create one to start publishing.
        </div>
      ) : (
        <div className="grid gap-4">
          {topics.map((topic) => (
            <Card key={topic.topicId}>
              <CardHeader className="flex-row items-center justify-between">
                <div className="flex items-center gap-3">
                  <RadioTower className="size-5 text-primary" />
                  <div>
                    <CardTitle className="text-base">{topic.topicName}</CardTitle>
                    <p className="text-xs text-muted-foreground">
                      Created {formatDistanceToNow(new Date(topic.createdAt), { addSuffix: true })}
                    </p>
                  </div>
                </div>
                <Button variant="outline" size="sm" onClick={() => publish(topic.topicId)}>
                  <Send className="mr-2 size-4" />
                  Publish
                </Button>
              </CardHeader>
              <CardContent className="space-y-3">
                <TopicSubscribe
                  queues={queues}
                  onSubscribe={(queueId) => subscribe(topic.topicId, queueId)}
                />
                <div className="space-y-2">
                  {(topic.subscriptions ?? []).map((sub) => (
                    <div
                      key={sub.subscriptionId}
                      className="flex items-center justify-between rounded-md border px-3 py-2 text-sm"
                    >
                      <span>{sub.queueName || sub.queueId}</span>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={async () => {
                          await api.topics.unsubscribe(topic.topicId, sub.subscriptionId);
                          await refresh();
                          setMetricsRefreshKey((key) => key + 1);
                        }}
                      >
                        <Trash2 className="size-4" />
                      </Button>
                    </div>
                  ))}
                  {(topic.subscriptions ?? []).length === 0 && (
                    <p className="text-sm text-muted-foreground">No queues subscribed.</p>
                  )}
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}

function TopicSubscribe({
  queues,
  onSubscribe,
}: {
  queues: Queue[];
  onSubscribe: (queueId: string) => void;
}) {
  const [queueId, setQueueId] = useState("");

  return (
    <div className="flex gap-2">
      <select
        className="rounded-md border bg-background px-3 py-2 text-sm"
        value={queueId}
        onChange={(e) => setQueueId(e.target.value)}
      >
        <option value="">Select queue…</option>
        {queues.map((q) => (
          <option key={q.queueId} value={q.queueId}>
            {q.queueName}
          </option>
        ))}
      </select>
      <Button variant="secondary" onClick={() => onSubscribe(queueId)}>
        Subscribe queue
      </Button>
    </div>
  );
}
