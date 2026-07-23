import { Panel } from "@/components/ui/panel";
import { Button } from "@/components/ui/button";

import { ErrorState, RouteNotFound } from "./error-state";

/**
 * The two standalone error routes.
 *
 * Both render from nothing: no fetch, no session, no hydration required. An
 * error page that depends on the thing that just failed is worthless, so these
 * are static markup with plain links for recovery.
 */

function NotFoundPage() {
  return (
    <Panel className="max-w-[480px]">
      <RouteNotFound />
    </Panel>
  );
}

function ServerErrorPage() {
  return (
    <Panel className="max-w-[480px]">
      <ErrorState
        code="500"
        title="The server hit an unexpected error"
        description="This page could not be rendered. Whether anything you started went through is not known from here — check the surface you came from before repeating it."
        actions={
          <>
            <Button asChild>
              <a href="/">Queues</a>
            </Button>
            <Button variant="outline" asChild>
              <a href="/system">System</a>
            </Button>
          </>
        }
        footnote="Nothing about the fault is shown here on purpose — the detail belongs in the server log."
      />
    </Panel>
  );
}

export { NotFoundPage, ServerErrorPage };
