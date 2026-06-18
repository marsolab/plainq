import { useState, useEffect, useCallback } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Button } from "@/components/ui/button";
import { RefreshCw, Download, Activity, Clock, Zap, AlertCircle } from "lucide-react";
import RateChart from "./RateChart";
import InFlightChart from "./InFlightChart";
import MetricCard from "./MetricCard";

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
];

export default function QueueDetailMetrics({ queueId, queueName }) {
  const [timeRange, setTimeRange] = useState("1h");
  const [metrics, setMetrics] = useState(null);
  const [loading, setLoading] = useState(true);
  const [autoRefresh, setAutoRefresh] = useState(true);

  const fetchMetrics = useCallback(async () => {
    try {
      const response = await fetch(
        `/api/v1/metrics/queue/${queueId}?range=${timeRange}`
      );
      if (response.ok) {
        const data = await response.json();
        setMetrics(data);
      }
    } catch (error) {
      console.error("Failed to fetch queue metrics:", error);
    } finally {
      setLoading(false);
    }
  }, [queueId, timeRange]);

  useEffect(() => {
    fetchMetrics();

    if (autoRefresh) {
      const interval = setInterval(fetchMetrics, 5000);
      return () => clearInterval(interval);
    }
  }, [fetchMetrics, autoRefresh]);

  const formatRate = (rate) => {
    if (rate === undefined || rate === null) return "0";
    if (rate >= 1000) return `${(rate / 1000).toFixed(2)}K`;
    return rate.toFixed(2);
  };

  const formatNumber = (num) => {
    if (num === undefined || num === null) return "0";
    if (num >= 1000000) return `${(num / 1000000).toFixed(2)}M`;
    if (num >= 1000) return `${(num / 1000).toFixed(2)}K`;
    return num.toString();
  };

  const handleExport = async (format) => {
    try {
      const response = await fetch(
        `/api/v1/metrics/export?queue_id=${queueId}&range=${timeRange}&format=${format}`
      );
      if (response.ok) {
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `metrics-${queueId}-${timeRange}.${format}`;
        a.click();
        window.URL.revokeObjectURL(url);
      }
    } catch (error) {
      console.error("Export failed:", error);
    }
  };

  if (loading && !metrics) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-gray-900"></div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <div>
          <h3 className="text-xl font-bold">Queue Metrics</h3>
          <p className="text-sm text-gray-500">{queueName || queueId}</p>
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
          <Button variant="outline" onClick={() => handleExport("json")}>
            <Download className="h-4 w-4 mr-2" />
            Export
          </Button>
          <Button
            variant="outline"
            size="icon"
            onClick={fetchMetrics}
          >
            <RefreshCw className="h-4 w-4" />
          </Button>
          <Button
            variant={autoRefresh ? "default" : "outline"}
            onClick={() => setAutoRefresh(!autoRefresh)}
            size="sm"
          >
            {autoRefresh ? "Auto ON" : "Auto OFF"}
          </Button>
        </div>
      </div>

      {/* Current metrics cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <MetricCard
          title="Current Send Rate"
          value={formatRate(metrics?.currentSendRate)}
          unit="msg/s"
          description="Messages being sent now"
          color="blue"
        />
        <MetricCard
          title="Current Receive Rate"
          value={formatRate(metrics?.currentReceiveRate)}
          unit="msg/s"
          description="Messages being received now"
          color="green"
        />
        <MetricCard
          title="Current Delete Rate"
          value={formatRate(metrics?.currentDeleteRate)}
          unit="msg/s"
          description="Messages being deleted now"
          color="purple"
        />
        <MetricCard
          title="In Flight"
          value={formatNumber(metrics?.currentInFlight)}
          unit="msgs"
          description="Being processed"
          color="orange"
          trend={metrics?.currentInFlight > 100 ? "warning" : "neutral"}
        />
      </div>

      {/* Summary stats */}
      <div className="grid grid-cols-2 md:grid-cols-6 gap-4">
        <Card>
          <CardContent className="pt-4">
            <div className="flex items-center gap-2">
              <Activity className="h-4 w-4 text-gray-500" />
              <div>
                <p className="text-xs text-gray-500">Avg Send Rate</p>
                <p className="font-bold">{formatRate(metrics?.avgSendRate)}</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4">
            <div className="flex items-center gap-2">
              <Zap className="h-4 w-4 text-gray-500" />
              <div>
                <p className="text-xs text-gray-500">Max Send Rate</p>
                <p className="font-bold">{formatRate(metrics?.maxSendRate)}</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4">
            <div className="flex items-center gap-2">
              <Activity className="h-4 w-4 text-gray-500" />
              <div>
                <p className="text-xs text-gray-500">Avg Receive Rate</p>
                <p className="font-bold">{formatRate(metrics?.avgReceiveRate)}</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4">
            <div className="flex items-center gap-2">
              <Zap className="h-4 w-4 text-gray-500" />
              <div>
                <p className="text-xs text-gray-500">Max Receive Rate</p>
                <p className="font-bold">{formatRate(metrics?.maxReceiveRate)}</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4">
            <div className="flex items-center gap-2">
              <Clock className="h-4 w-4 text-gray-500" />
              <div>
                <p className="text-xs text-gray-500">Total Sent</p>
                <p className="font-bold">{formatNumber(metrics?.totalSent)}</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4">
            <div className="flex items-center gap-2">
              <AlertCircle className="h-4 w-4 text-gray-500" />
              <div>
                <p className="text-xs text-gray-500">Total Deleted</p>
                <p className="font-bold">{formatNumber(metrics?.totalDeleted)}</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Charts */}
      <Tabs defaultValue="rates" className="space-y-4">
        <TabsList>
          <TabsTrigger value="rates">Throughput</TabsTrigger>
          <TabsTrigger value="inflight">In-Flight</TabsTrigger>
        </TabsList>

        <TabsContent value="rates">
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
                height={350}
              />
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="inflight">
          <Card>
            <CardHeader>
              <CardTitle>In-Flight Messages</CardTitle>
              <CardDescription>
                Messages currently being processed
              </CardDescription>
            </CardHeader>
            <CardContent>
              <InFlightChart
                queueId={queueId}
                timeRange={timeRange}
                height={350}
              />
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
