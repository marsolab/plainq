import { useState, useEffect, useCallback } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { RefreshCw } from "lucide-react";
import RateChart from "./RateChart";
import MetricCard from "./MetricCard";
import QueueMetricsTable from "./QueueMetricsTable";
import InFlightChart from "./InFlightChart";

const TIME_RANGE_PRESETS = [
  { value: "5m", label: "Last 5 minutes" },
  { value: "15m", label: "Last 15 minutes" },
  { value: "30m", label: "Last 30 minutes" },
  { value: "1h", label: "Last 1 hour" },
  { value: "3h", label: "Last 3 hours" },
  { value: "6h", label: "Last 6 hours" },
  { value: "12h", label: "Last 12 hours" },
  { value: "24h", label: "Last 24 hours" },
  { value: "7d", label: "Last 7 days" },
  { value: "30d", label: "Last 30 days" },
];

export default function MetricsDashboard({ queueId }) {
  const [timeRange, setTimeRange] = useState("1h");
  const [overview, setOverview] = useState(null);
  const [loading, setLoading] = useState(true);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [lastUpdated, setLastUpdated] = useState(null);

  const fetchOverview = useCallback(async () => {
    try {
      const response = await fetch(`/api/v1/metrics/overview`);
      if (response.ok) {
        const data = await response.json();
        setOverview(data);
        setLastUpdated(new Date());
      }
    } catch (error) {
      console.error("Failed to fetch metrics overview:", error);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchOverview();

    if (autoRefresh) {
      const interval = setInterval(fetchOverview, 5000); // Refresh every 5 seconds
      return () => clearInterval(interval);
    }
  }, [fetchOverview, autoRefresh]);

  const formatRate = (rate) => {
    if (rate === undefined || rate === null) return "0";
    if (rate >= 1000000) return `${(rate / 1000000).toFixed(2)}M`;
    if (rate >= 1000) return `${(rate / 1000).toFixed(2)}K`;
    return rate.toFixed(2);
  };

  const formatNumber = (num) => {
    if (num === undefined || num === null) return "0";
    if (num >= 1000000000) return `${(num / 1000000000).toFixed(2)}B`;
    if (num >= 1000000) return `${(num / 1000000).toFixed(2)}M`;
    if (num >= 1000) return `${(num / 1000).toFixed(2)}K`;
    return num.toString();
  };

  if (loading && !overview) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-gray-900"></div>
      </div>
    );
  }

  const systemMetrics = overview?.systemMetrics || {};
  const queueMetrics = overview?.queueMetrics || [];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <div>
          <h2 className="text-2xl font-bold">Metrics Dashboard</h2>
          <p className="text-gray-500 text-sm">
            {lastUpdated && `Last updated: ${lastUpdated.toLocaleTimeString()}`}
          </p>
        </div>
        <div className="flex items-center gap-4">
          <Select value={timeRange} onValueChange={setTimeRange}>
            <SelectTrigger className="w-[180px]">
              <SelectValue placeholder="Select time range" />
            </SelectTrigger>
            <SelectContent>
              {TIME_RANGE_PRESETS.map((preset) => (
                <SelectItem key={preset.value} value={preset.value}>
                  {preset.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Button
            variant="outline"
            size="icon"
            onClick={fetchOverview}
            className={autoRefresh ? "animate-spin-slow" : ""}
          >
            <RefreshCw className="h-4 w-4" />
          </Button>
          <Button
            variant={autoRefresh ? "default" : "outline"}
            onClick={() => setAutoRefresh(!autoRefresh)}
          >
            {autoRefresh ? "Auto-refresh ON" : "Auto-refresh OFF"}
          </Button>
        </div>
      </div>

      {/* System-wide metrics cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <MetricCard
          title="Send Rate"
          value={formatRate(systemMetrics.sendRate)}
          unit="msg/s"
          description="Messages sent per second"
          trend={systemMetrics.sendRate > 0 ? "up" : "neutral"}
          color="blue"
        />
        <MetricCard
          title="Receive Rate"
          value={formatRate(systemMetrics.receiveRate)}
          unit="msg/s"
          description="Messages received per second"
          trend={systemMetrics.receiveRate > 0 ? "up" : "neutral"}
          color="green"
        />
        <MetricCard
          title="Delete Rate"
          value={formatRate(systemMetrics.deleteRate)}
          unit="msg/s"
          description="Messages deleted per second"
          trend={systemMetrics.deleteRate > 0 ? "up" : "neutral"}
          color="purple"
        />
        <MetricCard
          title="In Flight"
          value={formatNumber(systemMetrics.totalInFlight)}
          unit="msgs"
          description="Messages currently being processed"
          trend={systemMetrics.totalInFlight > 100 ? "warning" : "neutral"}
          color="orange"
        />
      </div>

      {/* Charts */}
      <Tabs defaultValue="rates" className="space-y-4">
        <TabsList>
          <TabsTrigger value="rates">Throughput Rates</TabsTrigger>
          <TabsTrigger value="inflight">In-Flight Messages</TabsTrigger>
          <TabsTrigger value="queues">Queue Details</TabsTrigger>
        </TabsList>

        <TabsContent value="rates" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Message Throughput</CardTitle>
              <CardDescription>
                Send, receive, and delete rates over time
              </CardDescription>
            </CardHeader>
            <CardContent>
              <RateChart
                queueId={queueId}
                timeRange={timeRange}
                height={400}
              />
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="inflight" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>In-Flight Messages</CardTitle>
              <CardDescription>
                Messages currently being processed across all queues
              </CardDescription>
            </CardHeader>
            <CardContent>
              <InFlightChart
                queueId={queueId}
                timeRange={timeRange}
                height={400}
              />
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="queues" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Queue Metrics</CardTitle>
              <CardDescription>
                Detailed metrics for each queue
              </CardDescription>
            </CardHeader>
            <CardContent>
              <QueueMetricsTable queues={queueMetrics} />
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      {/* Summary stats */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-gray-500">
              Total Messages Sent
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold">
              {formatNumber(systemMetrics.totalSent)}
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-gray-500">
              Total Messages Received
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold">
              {formatNumber(systemMetrics.totalReceived)}
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-gray-500">
              Total Messages Deleted
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold">
              {formatNumber(systemMetrics.totalDeleted)}
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
