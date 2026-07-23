import { afterAll, beforeAll, describe, expect, mock, test } from "bun:test";
import { createRef, type ReactNode } from "react";
import { act, create, type ReactTestRenderer } from "react-test-renderer";

declare global {
  var IS_REACT_ACT_ENVIRONMENT: boolean | undefined;
}

globalThis.IS_REACT_ACT_ENVIRONMENT = true;

function passthrough({ children }: { children?: ReactNode }) {
  return children;
}

/** Records what the trigger primitive was handed, so ref forwarding is observable. */
const trigger: { ref?: unknown } = {};

const actual = await import("radix-ui");

mock.module("radix-ui", () => ({
  ...actual,
  Select: {
    Root: passthrough,
    Group: passthrough,
    Value: passthrough,
    Icon: passthrough,
    Portal: passthrough,
    Viewport: passthrough,
    Label: passthrough,
    Item: passthrough,
    ItemIndicator: passthrough,
    ItemText: passthrough,
    Separator: passthrough,
    ScrollUpButton: passthrough,
    ScrollDownButton: passthrough,
    Trigger: ({ children, ref }: { children?: ReactNode; ref?: unknown }) => {
      trigger.ref = ref;
      return <button type="button">{children}</button>;
    },
    Content: ({ children, ...props }: { children?: ReactNode }) => (
      <div role="listbox" {...props}>
        {children}
      </div>
    ),
  },
}));

const { SelectContent, SelectPopup, SelectTrigger } = await import("./select");

describe("SelectContent", () => {
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
      renderer = create(<SelectContent>Option</SelectContent>);
    });
  });

  afterAll(() => {
    act(() => renderer.unmount());
    console.error = originalConsoleError;
  });

  test("renders above modal dialogs", () => {
    const content = renderer.root.findByProps({ role: "listbox" });

    expect(content.props.className).toContain("z-[60]");
  });

  test("is also exported as SelectPopup for existing call sites", () => {
    expect(SelectPopup).toBe(SelectContent);
  });
});

describe("SelectTrigger", () => {
  test("forwards a ref for dialog focus restoration", () => {
    const ref = createRef<HTMLButtonElement>();
    let renderer: ReactTestRenderer;

    act(() => {
      renderer = create(<SelectTrigger ref={ref}>Choose</SelectTrigger>);
    });

    expect(trigger.ref).toBe(ref);

    act(() => renderer.unmount());
  });
});
