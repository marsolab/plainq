import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { Slot } from "radix-ui";
import { LoaderCircle } from "lucide-react";

import { cn } from "@/lib/utils";

const buttonVariants = cva(
  "group/button inline-flex shrink-0 items-center justify-center gap-2 border border-transparent text-[13px] font-medium whitespace-nowrap transition-colors outline-none select-none disabled:pointer-events-none disabled:opacity-45 [&_svg]:pointer-events-none [&_svg]:shrink-0 [&_svg:not([class*='size-'])]:size-3.5",
  {
    variants: {
      variant: {
        // The one filled action per view.
        default: "bg-primary text-primary-foreground hover:bg-primary-hover",
        outline:
          "border-border bg-surface text-foreground hover:bg-muted aria-expanded:bg-muted",
        // Tertiary: no chrome until hover.
        ghost:
          "text-strong hover:bg-muted hover:text-foreground aria-expanded:bg-muted",
        destructive:
          "bg-destructive text-destructive-foreground hover:bg-destructive/90",
        // Destructive that has to sit beside neutral actions without shouting.
        "destructive-outline":
          "border-destructive-border bg-surface text-destructive-text hover:bg-destructive-surface",
        link: "text-foreground underline-offset-4 hover:underline",
      },
      size: {
        default: "h-8 px-3",
        sm: "h-7 gap-1.5 px-2.5 text-xs",
        lg: "h-9 px-4",
        icon: "size-8",
        "icon-sm": "size-7",
      },
    },
    defaultVariants: {
      variant: "default",
      size: "default",
    },
  },
);

type ButtonProps = React.ComponentProps<"button"> &
  VariantProps<typeof buttonVariants> & {
    asChild?: boolean;
    /** Keeps the label and width; swaps in a spinner ahead of it. */
    loading?: boolean;
    /**
     * Why this action is unavailable to this operator. Renders the button
     * disabled but visible with the reason as its tooltip — a blocked action
     * explains more than a missing one.
     */
    blockedReason?: string;
  };

function Button({
  className,
  variant = "default",
  size = "default",
  asChild = false,
  loading = false,
  blockedReason,
  disabled,
  children,
  ...props
}: ButtonProps) {
  const Comp = asChild ? Slot.Root : "button";
  const isBlocked = Boolean(blockedReason);

  return (
    <Comp
      data-slot="button"
      data-variant={variant}
      data-size={size}
      aria-busy={loading || undefined}
      title={blockedReason ?? props.title}
      disabled={disabled || loading || isBlocked}
      className={cn(
        buttonVariants({ variant, size }),
        isBlocked && "border-border bg-muted text-subtle",
        className,
      )}
      {...props}
    >
      {/*
       * Slot demands exactly one element child, so `asChild` hands the
       * consumer's element straight through — the caller owns its contents.
       */}
      {asChild ? (
        children
      ) : (
        <>
          {loading ? <LoaderCircle className="size-3.5 animate-spin" aria-hidden /> : null}
          {children}
        </>
      )}
    </Comp>
  );
}

export { Button, buttonVariants };
