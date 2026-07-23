"use client";

import * as React from "react";
import { Plus, RadioTower, TriangleAlert } from "lucide-react";

import { PageHeader } from "@/components/ui/page-header";
import { Panel } from "@/components/ui/panel";
import { Button } from "@/components/ui/button";
import { ScopeBadge } from "@/components/ui/badge";
import { Banner } from "@/components/ui/feedback";
import { EmptyState } from "@/components/ui/empty-state";
import { api } from "@/lib/api-client";
import type { Queue, Topic } from "@/lib/types";
import { loadAllQueues } from "./pubsub-api";
import { CreateTopicDialog } from "./create-topic-dialog";
import { TopicList, TopicListSkeleton } from "./topic-list";
import { TopicDetail, TopicDetailSkeleton } from "./topic-detail";
import { TopicSummary } from "./topic-summary";
import { loadTopicMetrics, type TopicMetricsState } from "./telemetry";

interface PubSubPageProps {
  /** False when the operator may read Pub/Sub but not change it. */
  canManage?: boolean;
}

export function PubSubPage({ canManage = true }: PubSubPageProps) {
  const [topics, setTopics] = React.useState<Topic[]>([]);
  const [queues, setQueues] = React.useState<Queue[]>([]);
  const [loaded, setLoaded] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);
  const [metrics, setMetrics] = React.useState<TopicMetricsState>({ status: "loading" });
  // Every mutation moves the collector's counters, and the detail panel's
  // series has to be re-read as well as the overview.
  const [metricsKey, setMetricsKey] = React.useState(0);
  const [selectedTopicId, setSelectedTopicId] = React.useState<string | null>(null);
  const [createOpen, setCreateOpen] = React.useState(false);

  const load = React.useCallback(async () => {
    try {
      const [topicData, queueData] = await Promise.all([
        api.topics.list(),
        loadAllQueues(),
      ]);
      setTopics(topicData.topics ?? []);
      setQueues(queueData);
      setError(null);
      setLoaded(true);
    } catch (err) {
      // Rows already on screen stay: a failed refresh is not evidence that the
      // topics went away. They are relabelled stale instead.
      setError(err instanceof Error ? err.message : "Could not reach the server");
    }
  }, []);

  const refreshMetrics = React.useCallback(() => {
    setMetricsKey((key) => key + 1);
  }, []);

  /** A topic changed: re-read the list and the readings that describe it. */
  const reload = React.useCallback(() => {
    void load();
    refreshMetrics();
  }, [load, refreshMetrics]);

  React.useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const requested = params.get("topic");
    if (requested) setSelectedTopicId(requested);
    void load();
  }, [load]);

  React.useEffect(() => {
    let cancelled = false;
    void loadTopicMetrics().then((result) => {
      if (!cancelled) setMetrics(result);
    });

    return () => {
      cancelled = true;
    };
  }, [metricsKey]);

  const selectTopic = React.useCallback((topicId: string | null) => {
    setSelectedTopicId(topicId);
    const url = new URL(window.location.href);
    if (topicId === null) url.searchParams.delete("topic");
    else url.searchParams.set("topic", topicId);
    window.history.replaceState(null, "", url);
  }, []);

  const selectedTopic =
    topics.find((topic) => topic.topicId === selectedTopicId) ?? topics[0] ?? null;

  // A ?topic= that names nothing — a stale bookmark, or the topic just deleted
  // — otherwise leaves the address bar claiming one topic while the panel
  // shows another. Reconcile onto whatever is actually selected.
  React.useEffect(() => {
    if (!loaded || selectedTopicId === null) return;
    if (topics.some((topic) => topic.topicId === selectedTopicId)) return;
    selectTopic(selectedTopic?.topicId ?? null);
  }, [loaded, topics, selectedTopicId, selectedTopic, selectTopic]);

  const subscriptionCount = loaded
    ? topics.reduce((total, topic) => total + (topic.subscriptions ?? []).length, 0)
    : null;

  const stale = error !== null && loaded;
  const blockedReason = canManage ? undefined : "Your role cannot change Pub/Sub topics.";

  return (
    <>
      <PageHeader
        title={
          <span className="inline-flex items-center gap-2.5">
            Pub/Sub
            <ScopeBadge className="px-[7px] py-0.5 text-[10px] leading-[16px] tracking-[0.08em]">
              Experimental
            </ScopeBadge>
          </span>
        }
        description="Publish once to copy a message to every connected queue. HTTP only."
        actions={
          <Button blockedReason={blockedReason} onClick={() => setCreateOpen(true)}>
            <Plus aria-hidden />
            Create topic
          </Button>
        }
      />

      {stale ? (
        <Banner
          tone="error"
          className="mb-4"
          action={
            <button type="button" onClick={() => void load()} className="cursor-pointer underline underline-offset-2">
              Retry
            </button>
          }
        >
          Could not refresh topics: {error}. Showing the last good data.
        </Banner>
      ) : null}

      <TopicSummary
        metrics={metrics}
        listedSubscriptions={subscriptionCount}
        loading={!loaded && !error}
        onRetryMetrics={refreshMetrics}
      />

      {!loaded && error ? (
        <Panel>
          <EmptyState
            icon={TriangleAlert}
            title="Could not load topics"
            description={error}
            action={
              <Button variant="outline" onClick={() => void load()}>
                Retry
              </Button>
            }
          />
        </Panel>
      ) : !loaded ? (
        <div className="grid grid-cols-[1fr_1.1fr] items-start gap-4">
          <TopicListSkeleton />
          <TopicDetailSkeleton />
        </div>
      ) : topics.length === 0 ? (
        <Panel>
          <EmptyState
            icon={RadioTower}
            title="No topics yet"
            description="A topic copies every published message to each queue connected to it. Nothing is kept on the topic itself, so a publish with no connections is delivered nowhere."
            action={
              <Button blockedReason={blockedReason} onClick={() => setCreateOpen(true)}>
                <Plus aria-hidden />
                Create topic
              </Button>
            }
          />
        </Panel>
      ) : (
        <div className="grid grid-cols-[1fr_1.1fr] items-start gap-4">
          <TopicList
            topics={topics}
            selectedTopicId={selectedTopic?.topicId ?? null}
            onSelect={selectTopic}
            metrics={metrics}
            stale={stale}
          />
          {selectedTopic ? (
            <TopicDetail
              key={selectedTopic.topicId}
              topic={selectedTopic}
              queues={queues}
              metrics={metrics}
              metricsKey={metricsKey}
              canManage={canManage}
              onChanged={reload}
            />
          ) : null}
        </div>
      )}

      <CreateTopicDialog
        open={createOpen}
        onOpenChange={setCreateOpen}
        existingNames={topics.map((topic) => topic.topicName)}
        onCreated={(topicId) => {
          selectTopic(topicId);
          reload();
        }}
      />
    </>
  );
}
