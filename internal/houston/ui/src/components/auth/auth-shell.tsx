import * as React from "react";

import { Panel, PanelHeader, PanelBody } from "@/components/ui/panel";
import { Wordmark } from "@/components/layout/wordmark";
import { cn } from "@/lib/utils";

/**
 * The auth routes get no shell: no sidebar, no top bar, nothing that implies
 * an application the visitor is not yet inside. Just the app background and
 * one centred column.
 */
function AuthPage({ className, ...props }: React.ComponentProps<"main">) {
  return (
    <main
      data-slot="auth-page"
      className={cn(
        "flex min-h-screen flex-col items-center justify-center px-6 py-12",
        className,
      )}
      {...props}
    />
  );
}

/** The 344px column every centred auth screen is built in. */
function AuthColumn({ className, ...props }: React.ComponentProps<"div">) {
  return (
    <div
      data-slot="auth-column"
      className={cn("flex w-[344px] max-w-full flex-col items-stretch gap-5", className)}
      {...props}
    />
  );
}

/**
 * The panel names its own route in the mono caption bar. On a surface with no
 * navigation, that caption is the only thing telling an operator where they
 * landed — worth more here than the tidier alternative of hiding it.
 */
function AuthPanel({
  caption,
  className,
  children,
  ...props
}: React.ComponentProps<"section"> & { caption: string }) {
  return (
    <Panel className={cn("w-full", className)} {...props}>
      <PanelHeader>{caption}</PanelHeader>
      <PanelBody className="flex flex-col gap-3 p-5">{children}</PanelBody>
    </Panel>
  );
}

/** Sentence-case heading inside an auth panel. */
function AuthHeading({ className, ...props }: React.ComponentProps<"h1">) {
  return (
    <h1
      data-slot="auth-heading"
      className={cn("text-base leading-[22px] font-semibold", className)}
      {...props}
    />
  );
}

/**
 * Neutral result box. Used wherever the copy has to read the same whether or
 * not an account exists, and for states the visitor can only read rather than
 * act on. Deliberately not an InlineAlert: nothing here failed.
 */
function AuthNotice({ className, ...props }: React.ComponentProps<"div">) {
  return (
    <div
      data-slot="auth-notice"
      role="status"
      className={cn(
        "border border-border bg-muted px-3 py-2 text-xs leading-relaxed text-strong",
        className,
      )}
      {...props}
    />
  );
}

function AuthBrand({ className }: { className?: string }) {
  return <Wordmark className={cn("justify-center", className)} />;
}

export { AuthPage, AuthColumn, AuthPanel, AuthHeading, AuthNotice, AuthBrand };
