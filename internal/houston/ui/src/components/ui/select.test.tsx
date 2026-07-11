import { afterAll, beforeAll, describe, expect, mock, test } from "bun:test";
import type { ReactNode } from "react";
import { act, create, type ReactTestRenderer } from "react-test-renderer";

declare global {
  var IS_REACT_ACT_ENVIRONMENT: boolean | undefined;
}

globalThis.IS_REACT_ACT_ENVIRONMENT = true;

function passthrough({ children }: { children?: ReactNode }) {
  return children;
}

mock.module("@base-ui/react/select", () => ({
  Select: {
    Root: passthrough,
    Value: passthrough,
    Group: passthrough,
    GroupLabel: passthrough,
    Trigger: passthrough,
    Icon: passthrough,
    Portal: passthrough,
    Positioner: ({ children, ...props }: { children?: ReactNode }) => (
      <div data-select-positioner="" {...props}>
        {children}
      </div>
    ),
    Popup: ({ children, ...props }: { children?: ReactNode }) => (
      <div role="listbox" {...props}>
        {children}
      </div>
    ),
    Item: passthrough,
    ItemIndicator: passthrough,
    ItemText: passthrough,
  },
}));

const { SelectPopup, SelectTrigger } = await import("./select");

describe("SelectPopup", () => {
  let renderer: ReactTestRenderer;
  let originalConsoleError: typeof console.error;

  beforeAll(() => {
    originalConsoleError = console.error;
    console.error = (...args: unknown[]) => {
      if (String(args[0] ?? "").includes("react-test-renderer is deprecated")) {
        return;
      }

      originalConsoleError(...args);
    };

    act(() => {
      renderer = create(<SelectPopup>Option</SelectPopup>);
    });
  });

  afterAll(() => {
    act(() => renderer.unmount());
    console.error = originalConsoleError;
  });

  test("renders above modal dialogs", () => {
    const positioner = renderer.root.findByProps({
      "data-select-positioner": "",
    });

    expect(positioner.props.className).toContain("z-[60]");
  });
});

describe("SelectTrigger", () => {
  test("accepts a ref for dialog focus restoration", () => {
    expect(SelectTrigger.$$typeof).toBe(Symbol.for("react.forward_ref"));
  });
});
