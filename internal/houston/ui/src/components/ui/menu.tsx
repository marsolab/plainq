import { Menu as BaseMenu } from "@base-ui/react/menu";
import { cn } from "@/lib/utils";
import type { ComponentPropsWithoutRef } from "react";

const Menu = BaseMenu.Root;
const MenuTrigger = BaseMenu.Trigger;

function MenuPopup({
  className,
  ...props
}: ComponentPropsWithoutRef<typeof BaseMenu.Popup>) {
  return (
    <BaseMenu.Portal>
      <BaseMenu.Positioner>
        <BaseMenu.Popup
          className={cn(
            "z-50 min-w-[8rem] overflow-hidden rounded-md border bg-surface p-1 shadow-md data-[ending-style]:opacity-0 data-[starting-style]:opacity-0",
            className,
          )}
          {...props}
        />
      </BaseMenu.Positioner>
    </BaseMenu.Portal>
  );
}

function MenuItem({
  className,
  ...props
}: ComponentPropsWithoutRef<typeof BaseMenu.Item>) {
  return (
    <BaseMenu.Item
      className={cn(
        "relative flex cursor-default select-none items-center gap-2 rounded-sm px-2 py-1.5 text-sm outline-none transition-colors data-[highlighted]:bg-accent data-[highlighted]:text-accent-foreground data-[disabled]:pointer-events-none data-[disabled]:opacity-50 [&_svg]:size-4 [&_svg]:shrink-0",
        className,
      )}
      {...props}
    />
  );
}

function MenuSeparator({
  className,
  ...props
}: ComponentPropsWithoutRef<typeof BaseMenu.Separator>) {
  return (
    <BaseMenu.Separator
      className={cn("-mx-1 my-1 h-px bg-border", className)}
      {...props}
    />
  );
}

export { Menu, MenuTrigger, MenuPopup, MenuItem, MenuSeparator };
