import { useState, useEffect } from "react";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  ReferenceLine,
} from "recharts";

export default function InFlightChart({ queueId, timeRange, height = 300 }) {
  const [data, setData] = useState([]);
  const [loading, setLoading] = useState(true);
  const [threshold, setThreshold] = useState(100);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const endpoint = queueId
          ? `/api/v1/metrics/queue/${queueId}/inflight?range=${timeRange}`
          : `/api/v1/metrics/inflight?range=${timeRange}`;

        const response = await fetch(endpoint);
        if (response.ok) {
          const result = await response.json();

          // Transform data
          const transformedData = (result.history || []).map((point) => ({
            timestamp: point.timestamp,
            value: point.value,
          }));
          setData(transformedData);
        }
      } catch (error) {
        console.error("Failed to fetch in-flight data:", error);
      } finally {
        setLoading(false);
      }
    };

    fetchData();

    const interval = setInterval(fetchData, 5000);
    return () => clearInterval(interval);
  }, [queueId, timeRange]);

  const formatTimestamp = (timestamp) => {
    const date = new Date(timestamp);
    return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  };

  const formatValue = (value) => {
    if (value >= 1000) return `${(value / 1000).toFixed(1)}K`;
    return value.toString();
  };

  const CustomTooltip = ({ active, payload, label }) => {
    if (active && payload && payload.length) {
      const value = payload[0].value;
      const isHigh = value > threshold;

      return (
        <div className="bg-white border border-gray-200 rounded-lg shadow-lg p-3">
          <p className="text-sm text-gray-500 mb-2">
            {new Date(label).toLocaleString()}
          </p>
          <div className="flex items-center gap-2">
            <div
              className={`w-3 h-3 rounded-full ${
                isHigh ? "bg-orange-500" : "bg-blue-500"
              }`}
            />
            <span className="text-sm font-medium">In Flight:</span>
            <span className={`text-sm font-bold ${isHigh ? "text-orange-600" : ""}`}>
              {formatValue(value)} messages
            </span>
          </div>
          {isHigh && (
            <p className="text-xs text-orange-600 mt-2">
              Above threshold ({threshold})
            </p>
          )}
        </div>
      );
    }
    return null;
  };

  // Calculate max value and stats
  const maxValue = data.length > 0 ? Math.max(...data.map((d) => d.value)) : 0;
  const avgValue =
    data.length > 0
      ? data.reduce((sum, d) => sum + d.value, 0) / data.length
      : 0;
  const currentValue = data.length > 0 ? data[data.length - 1].value : 0;

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

  return (
    <div>
      {/* Stats row */}
      <div className="flex gap-6 mb-4">
        <div className="text-center">
          <p className="text-sm text-gray-500">Current</p>
          <p className="text-xl font-bold text-blue-600">
            {formatValue(currentValue)}
          </p>
        </div>
        <div className="text-center">
          <p className="text-sm text-gray-500">Average</p>
          <p className="text-xl font-bold text-gray-700">
            {formatValue(Math.round(avgValue))}
          </p>
        </div>
        <div className="text-center">
          <p className="text-sm text-gray-500">Peak</p>
          <p className="text-xl font-bold text-orange-600">
            {formatValue(maxValue)}
          </p>
        </div>
        <div className="ml-auto">
          <label className="text-sm text-gray-500 mr-2">Threshold:</label>
          <input
            type="number"
            value={threshold}
            onChange={(e) => setThreshold(parseInt(e.target.value) || 100)}
            className="w-20 px-2 py-1 border rounded text-sm"
          />
        </div>
      </div>

      <ResponsiveContainer width="100%" height={height}>
        <AreaChart data={data}>
          <defs>
            <linearGradient id="colorInFlight" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3} />
              <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
            </linearGradient>
          </defs>
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
            domain={[0, Math.max(maxValue, threshold) * 1.1]}
          />
          <Tooltip content={<CustomTooltip />} />
          <ReferenceLine
            y={threshold}
            stroke="#f97316"
            strokeDasharray="5 5"
            label={{
              value: `Threshold (${threshold})`,
              fill: "#f97316",
              fontSize: 12,
            }}
          />
          <Area
            type="monotone"
            dataKey="value"
            name="In Flight"
            stroke="#3b82f6"
            strokeWidth={2}
            fillOpacity={1}
            fill="url(#colorInFlight)"
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}
