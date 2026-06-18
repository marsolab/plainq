import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ArrowUpDown, ChevronRight, TrendingUp, TrendingDown, Minus } from "lucide-react";
import { useState } from "react";

export default function QueueMetricsTable({ queues }) {
  const [sortField, setSortField] = useState("queueId");
  const [sortDirection, setSortDirection] = useState("asc");

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

  const handleSort = (field) => {
    if (sortField === field) {
      setSortDirection(sortDirection === "asc" ? "desc" : "asc");
    } else {
      setSortField(field);
      setSortDirection("asc");
    }
  };

  const sortedQueues = [...queues].sort((a, b) => {
    let aVal = a[sortField];
    let bVal = b[sortField];

    // Handle string vs number comparison
    if (typeof aVal === "string") {
      aVal = aVal.toLowerCase();
      bVal = bVal.toLowerCase();
    }

    if (sortDirection === "asc") {
      return aVal > bVal ? 1 : -1;
    } else {
      return aVal < bVal ? 1 : -1;
    }
  });

  const getHealthStatus = (queue) => {
    // Simple health check based on metrics
    if (queue.inFlight > 1000) return { status: "warning", label: "High Load" };
    if (queue.emptyReceives > queue.messagesReceived * 0.5)
      return { status: "warning", label: "Many Empty Receives" };
    if (queue.sendRate === 0 && queue.receiveRate === 0)
      return { status: "idle", label: "Idle" };
    return { status: "healthy", label: "Healthy" };
  };

  const StatusBadge = ({ status, label }) => {
    const variants = {
      healthy: "bg-green-100 text-green-700 border-green-200",
      warning: "bg-orange-100 text-orange-700 border-orange-200",
      idle: "bg-gray-100 text-gray-700 border-gray-200",
      error: "bg-red-100 text-red-700 border-red-200",
    };

    return (
      <Badge variant="outline" className={variants[status]}>
        {label}
      </Badge>
    );
  };

  const RateTrend = ({ current, previous }) => {
    if (previous === undefined || previous === 0) {
      return <Minus className="h-4 w-4 text-gray-400" />;
    }

    const change = ((current - previous) / previous) * 100;

    if (change > 10) {
      return <TrendingUp className="h-4 w-4 text-green-500" />;
    } else if (change < -10) {
      return <TrendingDown className="h-4 w-4 text-red-500" />;
    }
    return <Minus className="h-4 w-4 text-gray-400" />;
  };

  const SortableHeader = ({ field, children }) => (
    <TableHead
      className="cursor-pointer hover:bg-gray-50"
      onClick={() => handleSort(field)}
    >
      <div className="flex items-center gap-1">
        {children}
        <ArrowUpDown className="h-3 w-3 text-gray-400" />
      </div>
    </TableHead>
  );

  if (!queues || queues.length === 0) {
    return (
      <div className="text-center py-8 text-gray-500">
        No queue metrics available
      </div>
    );
  }

  return (
    <div className="overflow-x-auto">
      <Table>
        <TableHeader>
          <TableRow>
            <SortableHeader field="queueId">Queue ID</SortableHeader>
            <TableHead>Status</TableHead>
            <SortableHeader field="sendRate">Send Rate</SortableHeader>
            <SortableHeader field="receiveRate">Receive Rate</SortableHeader>
            <SortableHeader field="deleteRate">Delete Rate</SortableHeader>
            <SortableHeader field="inFlight">In Flight</SortableHeader>
            <SortableHeader field="messagesSent">Total Sent</SortableHeader>
            <SortableHeader field="messagesReceived">Total Received</SortableHeader>
            <TableHead></TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {sortedQueues.map((queue) => {
            const health = getHealthStatus(queue);

            return (
              <TableRow key={queue.queueId} className="hover:bg-gray-50">
                <TableCell className="font-medium">
                  <a
                    href={`/queue/${queue.queueId}`}
                    className="text-blue-600 hover:underline"
                  >
                    {queue.queueName || queue.queueId}
                  </a>
                </TableCell>
                <TableCell>
                  <StatusBadge status={health.status} label={health.label} />
                </TableCell>
                <TableCell>
                  <div className="flex items-center gap-2">
                    <span className="font-mono">
                      {formatRate(queue.sendRate)}
                    </span>
                    <span className="text-xs text-gray-500">msg/s</span>
                  </div>
                </TableCell>
                <TableCell>
                  <div className="flex items-center gap-2">
                    <span className="font-mono">
                      {formatRate(queue.receiveRate)}
                    </span>
                    <span className="text-xs text-gray-500">msg/s</span>
                  </div>
                </TableCell>
                <TableCell>
                  <div className="flex items-center gap-2">
                    <span className="font-mono">
                      {formatRate(queue.deleteRate)}
                    </span>
                    <span className="text-xs text-gray-500">msg/s</span>
                  </div>
                </TableCell>
                <TableCell>
                  <span
                    className={`font-mono ${
                      queue.inFlight > 100 ? "text-orange-600 font-bold" : ""
                    }`}
                  >
                    {formatNumber(queue.inFlight)}
                  </span>
                </TableCell>
                <TableCell>
                  <span className="font-mono">
                    {formatNumber(queue.messagesSent)}
                  </span>
                </TableCell>
                <TableCell>
                  <span className="font-mono">
                    {formatNumber(queue.messagesReceived)}
                  </span>
                </TableCell>
                <TableCell>
                  <Button variant="ghost" size="sm" asChild>
                    <a href={`/queue/${queue.queueId}#metrics`}>
                      <ChevronRight className="h-4 w-4" />
                    </a>
                  </Button>
                </TableCell>
              </TableRow>
            );
          })}
        </TableBody>
      </Table>

      {/* Summary row */}
      <div className="mt-4 p-4 bg-gray-50 rounded-lg">
        <div className="grid grid-cols-4 gap-4 text-sm">
          <div>
            <span className="text-gray-500">Total Queues:</span>
            <span className="ml-2 font-bold">{queues.length}</span>
          </div>
          <div>
            <span className="text-gray-500">Avg Send Rate:</span>
            <span className="ml-2 font-bold">
              {formatRate(
                queues.reduce((sum, q) => sum + (q.sendRate || 0), 0) /
                  queues.length
              )}
            </span>
            <span className="text-xs text-gray-500 ml-1">msg/s</span>
          </div>
          <div>
            <span className="text-gray-500">Total In Flight:</span>
            <span className="ml-2 font-bold">
              {formatNumber(queues.reduce((sum, q) => sum + (q.inFlight || 0), 0))}
            </span>
          </div>
          <div>
            <span className="text-gray-500">Total Messages:</span>
            <span className="ml-2 font-bold">
              {formatNumber(
                queues.reduce((sum, q) => sum + (q.messagesSent || 0), 0)
              )}
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}
