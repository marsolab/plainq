import { Menu, MenuTrigger, MenuPopup, MenuItem, MenuSeparator } from "@/components/ui/menu";
import { Button } from "@/components/ui/button";
import { CircleUser, LogOut } from "lucide-react";
import { api } from "@/lib/api-client";

interface HeaderProps {
  title: string;
  subtitle?: string;
}

export function Header({ title, subtitle }: HeaderProps) {
  const handleSignout = async () => {
    try {
      await api.auth.signout();
    } catch {
      // ignore
    }
    window.location.href = "/login";
  };

  return (
    <header className="flex h-14 items-center justify-between border-b px-6">
      <div>
        <h1 className="text-lg font-semibold">{title}</h1>
        {subtitle && (
          <p className="text-sm text-muted-foreground">{subtitle}</p>
        )}
      </div>
      <Menu>
        <MenuTrigger
          className="inline-flex items-center justify-center rounded-full size-8 hover:bg-accent transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
        >
          <CircleUser className="size-5 text-muted-foreground" />
        </MenuTrigger>
        <MenuPopup>
          <MenuItem onClick={handleSignout}>
            <LogOut className="size-4" />
            Sign out
          </MenuItem>
        </MenuPopup>
      </Menu>
    </header>
  );
}
