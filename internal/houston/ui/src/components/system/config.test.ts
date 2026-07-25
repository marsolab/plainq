import { describe, expect, test } from "bun:test";

import type { ConfigResponseDTO } from "@/lib/types";
import { factValue, toConfigFact, toConfigGroups } from "./config";

describe("factValue", () => {
  test("formats a duration from the seconds the server sent", () => {
    expect(factValue({ label: "Access token TTL", value: "900", format: "duration" })).toBe(
      "15 min",
    );
    expect(factValue({ label: "Retention", value: "2592000", format: "duration" })).toBe("30 d");
    expect(factValue({ label: "GC interval", value: "0", format: "duration" })).toBe("0 s");
  });

  test("leaves a plain value alone", () => {
    expect(factValue({ label: "Driver", value: "postgres" })).toBe("postgres");
    expect(factValue({ label: "Signing secret", value: "set", redacted: true })).toBe("set");
  });

  test("shows an unparseable duration as it arrived", () => {
    // The server said something; replacing it with a dash would lose that.
    expect(factValue({ label: "Retention", value: "unbounded", format: "duration" })).toBe(
      "unbounded",
    );
  });

  test("an absent value reads as empty, not as the string undefined", () => {
    expect(factValue({ label: "Profiler" })).toBe("");
  });
});

describe("toConfigFact", () => {
  test("carries redaction across as the withheld flag", () => {
    expect(
      toConfigFact({
        label: "DSN",
        value: "postgres://plainq@db:5432/plainq",
        redacted: true,
        note: "Credentials removed.",
      }),
    ).toEqual({
      label: "DSN",
      value: "postgres://plainq@db:5432/plainq",
      withheld: true,
      note: "Credentials removed.",
    });
  });

  test("a plain fact is not withheld", () => {
    expect(toConfigFact({ label: "Driver", value: "sqlite" }).withheld).toBe(false);
  });
});

describe("toConfigGroups", () => {
  test("maps every group and formats their durations", () => {
    const response: ConfigResponseDTO = {
      read_at: "2026-07-24T09:00:00Z",
      groups: [
        {
          title: "Storage",
          facts: [
            { label: "Driver", value: "sqlite" },
            { label: "GC interval", value: "60", format: "duration" },
          ],
        },
        { title: "Logging", facts: [] },
      ],
    };

    expect(toConfigGroups(response)).toEqual([
      {
        title: "Storage",
        facts: [
          { label: "Driver", value: "sqlite", withheld: false, note: undefined },
          { label: "GC interval", value: "1 min", withheld: false, note: undefined },
        ],
      },
      { title: "Logging", facts: [] },
    ]);
  });

  test("a response without groups is empty rather than a crash", () => {
    expect(toConfigGroups({ read_at: "2026-07-24T09:00:00Z" } as ConfigResponseDTO)).toEqual([]);
  });
});
