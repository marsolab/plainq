import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { Tabs as TabsPrimitive } from "radix-ui";

import { cn } from "@/lib/utils";

function Tabs({
  className,
  orientation = "horizontal",
  ...props
}: React.ComponentProps<typeof TabsPrimitive.Root>) {
  return (
    <TabsPrimitive.Root
      data-slot="tabs"
      data-orientation={orientation}
      className={cn("group/tabs flex gap-4 data-horizontal:flex-col", className)}
      {...props}
    />
  );
}

/**
 * Tabs are always underlined — there is no filled or pill variant. The
 * `variant` prop survives for call-site compatibility and only controls how
 * far the rule under the list runs.
 */
const tabsListVariants = cva(
  "group/tabs-list inline-flex items-center gap-4 text-muted-foreground group-data-vertical/tabs:h-fit group-data-vertical/tabs:flex-col group-data-vertical/tabs:items-stretch group-data-vertical/tabs:gap-0 group-data-vertical/tabs:border-r group-data-vertical/tabs:border-border",
  {
    variants: {
      variant: {
        default: "w-full border-b border-border group-data-vertical/tabs:border-b-0",
        line: "w-fit border-b border-border group-data-vertical/tabs:border-b-0",
      },
    },
    defaultVariants: {
      variant: "default",
    },
  },
);

function TabsList({
  className,
  variant = "default",
  ...props
}: React.ComponentProps<typeof TabsPrimitive.List> &
  VariantProps<typeof tabsListVariants>) {
  return (
    <TabsPrimitive.List
      data-slot="tabs-list"
      data-variant={variant}
      className={cn(tabsListVariants({ variant }), className)}
      {...props}
    />
  );
}

function TabsTrigger({
  className,
  ...props
}: React.ComponentProps<typeof TabsPrimitive.Trigger>) {
  return (
    <TabsPrimitive.Trigger
      data-slot="tabs-trigger"
      className={cn(
        "relative inline-flex items-center justify-center gap-1.5 whitespace-nowrap",
        "border-b-2 border-transparent pb-2 text-[13px] font-medium text-muted-foreground transition-colors",
        // Sits the 2px rule on top of the list's hairline rather than below it.
        "-mb-px hover:text-foreground",
        "data-active:border-foreground data-active:font-semibold data-active:text-foreground",
        "group-data-vertical/tabs:-mr-px group-data-vertical/tabs:mb-0 group-data-vertical/tabs:justify-start",
        "group-data-vertical/tabs:border-b-0 group-data-vertical/tabs:border-r-2 group-data-vertical/tabs:px-3 group-data-vertical/tabs:py-1.5",
        "group-data-vertical/tabs:data-active:border-foreground",
        "disabled:pointer-events-none disabled:opacity-45",
        "[&_svg]:pointer-events-none [&_svg]:shrink-0 [&_svg:not([class*='size-'])]:size-3.5",
        className,
      )}
      {...props}
    />
  );
}

function TabsContent({
  className,
  ...props
}: React.ComponentProps<typeof TabsPrimitive.Content>) {
  return (
    <TabsPrimitive.Content
      data-slot="tabs-content"
      className={cn("flex-1 text-[13px] outline-none", className)}
      {...props}
    />
  );
}

export { Tabs, TabsList, TabsTrigger, TabsContent, tabsListVariants };
