import { expect, test } from "bun:test";
import { renderToStaticMarkup } from "react-dom/server";

import { TopicSummary } from "./topic-summary";

test("the active Pub/Sub unavailable notice names the real telemetry flag", () => {
  const markup = renderToStaticMarkup(
    <TopicSummary
      metrics={{ status: "unavailable" }}
      listedSubscriptions={null}
      onRetryMetrics={() => {}}
    />,
  );

  expect(markup).toContain(">--telemetry.enable</span>");
});
