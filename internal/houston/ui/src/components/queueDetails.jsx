import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { QueueDetailMetrics } from "@/components/metrics";

export default function QueueDetails({ queueDetails, error }) {
  if (error) {
    return (
      <div className="bg-white px-2 py-4">
        <div className="text-red-500">Error: {error}</div>
      </div>
    );
  }

  if (!queueDetails) {
    return (
      <div className="bg-white px-2 py-4">
        <div className="text-gray-500">Loading...</div>
      </div>
    );
  }

  return (
    <div className="bg-white px-2">
      <Tabs defaultValue="queue" className="w-full">
        <TabsContent value="queue">
          <div className="space-y-6">
            {/* Queue header */}
            <div className="flex flex-row justify-between pt-4 pb-4">
              <div>
                <p className="text-2xl font-bold">{queueDetails.queueName}</p>
                <p className="text-sm text-gray-500">ID: {queueDetails.queueId}</p>
              </div>
            </div>

            {/* Queue tabs */}
            <Tabs defaultValue="overview" className="w-full">
              <TabsList>
                <TabsTrigger value="overview">Overview</TabsTrigger>
                <TabsTrigger value="metrics">Metrics</TabsTrigger>
                <TabsTrigger value="settings">Settings</TabsTrigger>
              </TabsList>

              <TabsContent value="overview" className="space-y-4 pt-4">
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                  <Card>
                    <CardHeader className="pb-2">
                      <CardTitle className="text-sm font-medium text-gray-500">
                        Retention Period
                      </CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="text-2xl font-bold">
                        {formatDuration(queueDetails.retentionPeriodSeconds)}
                      </div>
                    </CardContent>
                  </Card>

                  <Card>
                    <CardHeader className="pb-2">
                      <CardTitle className="text-sm font-medium text-gray-500">
                        Visibility Timeout
                      </CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="text-2xl font-bold">
                        {queueDetails.visibilityTimeoutSeconds}s
                      </div>
                    </CardContent>
                  </Card>

                  <Card>
                    <CardHeader className="pb-2">
                      <CardTitle className="text-sm font-medium text-gray-500">
                        Max Receive Attempts
                      </CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="text-2xl font-bold">
                        {queueDetails.maxReceiveAttempts}
                      </div>
                    </CardContent>
                  </Card>

                  <Card>
                    <CardHeader className="pb-2">
                      <CardTitle className="text-sm font-medium text-gray-500">
                        Eviction Policy
                      </CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="text-2xl font-bold">
                        {formatEvictionPolicy(queueDetails.evictionPolicy)}
                      </div>
                    </CardContent>
                  </Card>

                  <Card>
                    <CardHeader className="pb-2">
                      <CardTitle className="text-sm font-medium text-gray-500">
                        Created At
                      </CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="text-lg font-medium">
                        {new Date(queueDetails.createdAt).toLocaleString()}
                      </div>
                    </CardContent>
                  </Card>

                  {queueDetails.deadLetterQueueId && (
                    <Card>
                      <CardHeader className="pb-2">
                        <CardTitle className="text-sm font-medium text-gray-500">
                          Dead Letter Queue
                        </CardTitle>
                      </CardHeader>
                      <CardContent>
                        <a
                          href={`/queue/${queueDetails.deadLetterQueueId}`}
                          className="text-blue-600 hover:underline"
                        >
                          {queueDetails.deadLetterQueueId}
                        </a>
                      </CardContent>
                    </Card>
                  )}
                </div>
              </TabsContent>

              <TabsContent value="metrics" className="pt-4">
                <QueueDetailMetrics
                  queueId={queueDetails.queueId}
                  queueName={queueDetails.queueName}
                />
              </TabsContent>

              <TabsContent value="settings" className="pt-4">
                <Card>
                  <CardHeader>
                    <CardTitle>Queue Settings</CardTitle>
                    <CardDescription>
                      Configure queue behavior and policies
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    <p className="text-gray-500">
                      Queue settings management coming soon.
                    </p>
                  </CardContent>
                </Card>
              </TabsContent>
            </Tabs>
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
}

function formatDuration(seconds) {
  if (seconds >= 86400) {
    const days = Math.floor(seconds / 86400);
    return `${days} day${days > 1 ? "s" : ""}`;
  }
  if (seconds >= 3600) {
    const hours = Math.floor(seconds / 3600);
    return `${hours} hour${hours > 1 ? "s" : ""}`;
  }
  if (seconds >= 60) {
    const minutes = Math.floor(seconds / 60);
    return `${minutes} minute${minutes > 1 ? "s" : ""}`;
  }
  return `${seconds}s`;
}

function formatEvictionPolicy(policy) {
  const policies = {
    EVICTION_POLICY_UNSPECIFIED: "Unspecified",
    EVICTION_POLICY_DROP: "Drop",
    EVICTION_POLICY_DEAD_LETTER: "Dead Letter",
    EVICTION_POLICY_REORDER: "Reorder",
  };
  return policies[policy] || policy;
}
