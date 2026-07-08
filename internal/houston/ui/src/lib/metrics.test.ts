import { describe, expect, test } from "bun:test";
import {
  formatMetricNumber,
  formatMetricRate,
  isTelemetryUnavailableError,
  transformRateMetrics,
} from "./metrics";
import { api } from "./api-client";

describe("formatMetricNumber", () => {
  test("formats compact values", () => {
    expect(formatMetricNumber(0)).toBe("0");
    expect(formatMetricNumber(999)).toBe("999");
    expect(formatMetricNumber(1200)).toBe("1.20K");
    expect(formatMetricNumber(2_500_000)).toBe("2.50M");
  });
});

describe("formatMetricRate", () => {
  test("formats rates with two decimals", () => {
    expect(formatMetricRate(0)).toBe("0.00");
    expect(formatMetricRate(12.345)).toBe("12.35");
    expect(formatMetricRate(1500)).toBe("1.50K");
  });
});

describe("transformRateMetrics", () => {
  test("merges metric series by timestamp", () => {
    const rows = transformRateMetrics([
      {
        metricName: "plainq_topic_publish_rate",
        dataPoints: [{ timestamp: 1000, value: 2 }],
      },
      {
        metricName: "plainq_topic_delivery_rate",
        dataPoints: [{ timestamp: 1000, value: 4 }],
      },
    ]);

    expect(rows).toEqual([
      {
        timestamp: 1000,
        publish: 2,
        delivery: 4,
      },
    ]);
  });
});

describe("isTelemetryUnavailableError", () => {
  test("matches disabled telemetry errors with the apiFetch status prefix", () => {
    expect(isTelemetryUnavailableError(new Error("404: not found"))).toBe(true);
    expect(isTelemetryUnavailableError(new Error("503: telemetry unavailable"))).toBe(true);
    expect(
      isTelemetryUnavailableError(
        new Error("request failed after retrying 404: telemetry unavailable"),
      ),
    ).toBe(false);
    expect(isTelemetryUnavailableError(new Error("503 telemetry unavailable"))).toBe(false);
    expect(isTelemetryUnavailableError(new Error("network failed"))).toBe(false);
  });
});

describe("api errors", () => {
  test("preserve response status in the message", async () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async (input: RequestInfo | URL) => {
      if (String(input).includes("/queue/q1")) {
        return new Response(JSON.stringify({ message: "queue missing" }), {
          status: 503,
          headers: { "Content-Type": "application/json" },
        });
      }

      return new Response(JSON.stringify({}), { status: 200 });
    }) as typeof fetch;

    try {
      await expect(api.queues.get("q1")).rejects.toThrow("503: queue missing");
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});
