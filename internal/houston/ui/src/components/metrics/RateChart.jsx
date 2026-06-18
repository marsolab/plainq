import { useState, useEffect, useMemo } from "react";
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
  Area,
  AreaChart,
} from "recharts";

const COLORS = {
  send: "#3b82f6",    // Blue
  receive: "#22c55e", // Green
  delete: "#a855f7",  // Purple
};

export default function RateChart({ queueId, timeRange, height = 300 }) {
  const [data, setData] = useState([]);
  const [loading, setLoading] = useState(true);
  const [chartType, setChartType] = useState("line");

  useEffect(() => {
    const fetchData = async () => {
      try {
        const endpoint = queueId
          ? `/api/v1/metrics/queue/${queueId}/rates?range=${timeRange}`
          : `/api/v1/metrics/rates?range=${timeRange}`;

        const response = await fetch(endpoint);
        if (response.ok) {
          const result = await response.json();

          // Transform data for Recharts
          const transformedData = transformRateData(result.metrics);
          setData(transformedData);
        }
      } catch (error) {
        console.error("Failed to fetch rate data:", error);
      } finally {
        setLoading(false);
      }
    };

    fetchData();

    // Refresh every 5 seconds
    const interval = setInterval(fetchData, 5000);
    return () => clearInterval(interval);
  }, [queueId, timeRange]);

  // Transform API response to Recharts format
  const transformRateData = (metrics) => {
    if (!metrics || metrics.length === 0) return [];

    // Create a map of timestamps to values
    const dataMap = new Map();

    metrics.forEach((metric) => {
      const metricType = metric.metricName.replace("plainq_", "").replace("_rate", "");

      (metric.dataPoints || []).forEach((point) => {
        const timestamp = point.timestamp;
        if (!dataMap.has(timestamp)) {
          dataMap.set(timestamp, { timestamp });
        }
        dataMap.get(timestamp)[metricType] = point.value;
      });
    });

    // Convert to array and sort by timestamp
    return Array.from(dataMap.values()).sort((a, b) => a.timestamp - b.timestamp);
  };

  const formatTimestamp = (timestamp) => {
    const date = new Date(timestamp);
    return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  };

  const formatValue = (value) => {
    if (value === undefined || value === null) return "0";
    if (value >= 1000) return `${(value / 1000).toFixed(1)}K`;
    return value.toFixed(2);
  };

  const CustomTooltip = ({ active, payload, label }) => {
    if (active && payload && payload.length) {
      return (
        <div className="bg-white border border-gray-200 rounded-lg shadow-lg p-3">
          <p className="text-sm text-gray-500 mb-2">
            {new Date(label).toLocaleString()}
          </p>
          {payload.map((entry, index) => (
            <div key={index} className="flex items-center gap-2">
              <div
                className="w-3 h-3 rounded-full"
                style={{ backgroundColor: entry.color }}
              />
              <span className="text-sm font-medium capitalize">
                {entry.dataKey}:
              </span>
              <span className="text-sm">{formatValue(entry.value)} msg/s</span>
            </div>
          ))}
        </div>
      );
    }
    return null;
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center" style={{ height }}>
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-gray-900"></div>
      </div>
    );
  }

  if (data.length === 0) {
    return (
      <div className="flex items-center justify-center text-gray-500" style={{ height }}>
        No data available for the selected time range
      </div>
    );
  }

  const ChartComponent = chartType === "area" ? AreaChart : LineChart;

  return (
    <div>
      <div className="flex justify-end mb-4 gap-2">
        <button
          onClick={() => setChartType("line")}
          className={`px-3 py-1 text-sm rounded ${
            chartType === "line"
              ? "bg-gray-900 text-white"
              : "bg-gray-100 text-gray-700"
          }`}
        >
          Line
        </button>
        <button
          onClick={() => setChartType("area")}
          className={`px-3 py-1 text-sm rounded ${
            chartType === "area"
              ? "bg-gray-900 text-white"
              : "bg-gray-100 text-gray-700"
          }`}
        >
          Area
        </button>
      </div>

      <ResponsiveContainer width="100%" height={height}>
        <ChartComponent data={data}>
          <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" />
          <XAxis
            dataKey="timestamp"
            tickFormatter={formatTimestamp}
            stroke="#9ca3af"
            fontSize={12}
          />
          <YAxis
            tickFormatter={formatValue}
            stroke="#9ca3af"
            fontSize={12}
          />
          <Tooltip content={<CustomTooltip />} />
          <Legend />

          {chartType === "area" ? (
            <>
              <Area
                type="monotone"
                dataKey="send"
                name="Send Rate"
                stroke={COLORS.send}
                fill={COLORS.send}
                fillOpacity={0.3}
                strokeWidth={2}
              />
              <Area
                type="monotone"
                dataKey="receive"
                name="Receive Rate"
                stroke={COLORS.receive}
                fill={COLORS.receive}
                fillOpacity={0.3}
                strokeWidth={2}
              />
              <Area
                type="monotone"
                dataKey="delete"
                name="Delete Rate"
                stroke={COLORS.delete}
                fill={COLORS.delete}
                fillOpacity={0.3}
                strokeWidth={2}
              />
            </>
          ) : (
            <>
              <Line
                type="monotone"
                dataKey="send"
                name="Send Rate"
                stroke={COLORS.send}
                strokeWidth={2}
                dot={false}
                activeDot={{ r: 4 }}
              />
              <Line
                type="monotone"
                dataKey="receive"
                name="Receive Rate"
                stroke={COLORS.receive}
                strokeWidth={2}
                dot={false}
                activeDot={{ r: 4 }}
              />
              <Line
                type="monotone"
                dataKey="delete"
                name="Delete Rate"
                stroke={COLORS.delete}
                strokeWidth={2}
                dot={false}
                activeDot={{ r: 4 }}
              />
            </>
          )}
        </ChartComponent>
      </ResponsiveContainer>
    </div>
  );
}
