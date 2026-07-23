import { describe, expect, test } from "bun:test";
import { DEAD_LETTER_POLICY } from "./queue-create-model";
import { getQueueCreateDialogConfig } from "./queue-create-dialog";

describe("getQueueCreateDialogConfig", () => {
  test("configures the default dialog with every eviction policy", () => {
    const config = getQueueCreateDialogConfig("default");

    expect(config.title).toBe("Create queue");
    expect(config.description).toBe("Configuration is immutable after creation.");
    expect(config.allowDeadLetter).toBe(true);
    expect(config.policyOptions).toContainEqual(
      expect.objectContaining({ value: DEAD_LETTER_POLICY }),
    );
  });

  test("configures a non-recursive dead-letter dialog", () => {
    const config = getQueueCreateDialogConfig("dead-letter");

    expect(config.title).toBe("Create dead-letter queue");
    expect(config.description).toBe(
      "Configure the queue that will receive evicted messages.",
    );
    expect(config.allowDeadLetter).toBe(false);
    expect(config.policyOptions).not.toContainEqual(
      expect.objectContaining({ value: DEAD_LETTER_POLICY }),
    );
  });
});
