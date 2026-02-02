import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { ArrowUp, ArrowDown, Minus, AlertTriangle } from "lucide-react";

const COLORS = {
  blue: {
    bg: "bg-blue-50",
    text: "text-blue-600",
    border: "border-blue-200",
  },
  green: {
    bg: "bg-green-50",
    text: "text-green-600",
    border: "border-green-200",
  },
  purple: {
    bg: "bg-purple-50",
    text: "text-purple-600",
    border: "border-purple-200",
  },
  orange: {
    bg: "bg-orange-50",
    text: "text-orange-600",
    border: "border-orange-200",
  },
  red: {
    bg: "bg-red-50",
    text: "text-red-600",
    border: "border-red-200",
  },
};

export default function MetricCard({
  title,
  value,
  unit,
  description,
  trend = "neutral",
  color = "blue",
  previousValue,
  sparklineData,
}) {
  const colorScheme = COLORS[color] || COLORS.blue;

  const TrendIcon = () => {
    switch (trend) {
      case "up":
        return <ArrowUp className="h-4 w-4 text-green-500" />;
      case "down":
        return <ArrowDown className="h-4 w-4 text-red-500" />;
      case "warning":
        return <AlertTriangle className="h-4 w-4 text-orange-500" />;
      default:
        return <Minus className="h-4 w-4 text-gray-400" />;
    }
  };

  const calculateChange = () => {
    if (previousValue === undefined || previousValue === 0) return null;
    const change = ((parseFloat(value) - previousValue) / previousValue) * 100;
    return change.toFixed(1);
  };

  const change = calculateChange();

  return (
    <Card className={`${colorScheme.bg} ${colorScheme.border} border`}>
      <CardHeader className="pb-2">
        <CardTitle className="text-sm font-medium text-gray-600">
          {title}
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="flex items-baseline gap-2">
          <span className={`text-3xl font-bold ${colorScheme.text}`}>
            {value}
          </span>
          <span className="text-sm text-gray-500">{unit}</span>
          <div className="ml-auto flex items-center gap-1">
            <TrendIcon />
            {change && (
              <span
                className={`text-sm ${
                  parseFloat(change) >= 0 ? "text-green-500" : "text-red-500"
                }`}
              >
                {parseFloat(change) >= 0 ? "+" : ""}
                {change}%
              </span>
            )}
          </div>
        </div>
        {description && (
          <p className="text-xs text-gray-500 mt-2">{description}</p>
        )}
        {sparklineData && sparklineData.length > 0 && (
          <div className="mt-3">
            <MiniSparkline data={sparklineData} color={colorScheme.text} />
          </div>
        )}
      </CardContent>
    </Card>
  );
}

// Mini sparkline component
function MiniSparkline({ data, color, height = 30 }) {
  if (!data || data.length < 2) return null;

  const values = data.map((d) => d.value || d);
  const min = Math.min(...values);
  const max = Math.max(...values);
  const range = max - min || 1;

  const width = 100;
  const points = values
    .map((value, index) => {
      const x = (index / (values.length - 1)) * width;
      const y = height - ((value - min) / range) * height;
      return `${x},${y}`;
    })
    .join(" ");

  return (
    <svg width="100%" height={height} viewBox={`0 0 ${width} ${height}`}>
      <polyline
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        points={points}
        className={color}
      />
    </svg>
  );
}
