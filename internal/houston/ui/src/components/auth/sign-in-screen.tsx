"use client";

import * as React from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";

import { Button } from "@/components/ui/button";
import { InlineAlert } from "@/components/ui/feedback";
import { Micro } from "@/components/ui/value";
import { TextField, PasswordField } from "./form-fields";
import { AuthPage, AuthColumn, AuthPanel, AuthHeading, AuthNotice, AuthBrand } from "./auth-shell";
import { StartupGate } from "./startup-gate";
import { signIn, type AuthResult } from "./auth-transport";

/**
 * S03 — sign in.
 *
 * Every rejection of a credential pair reads the same regardless of what the
 * server said, so the form cannot be used to discover which addresses are
 * registered. Only affordances the server can actually serve are drawn: there
 * is no password-reset endpoint, so there is no reset link to click.
 */

const signInSchema = z.object({
  email: z.email("Enter a valid email address."),
  password: z.string().min(1, "Enter your password."),
});

type SignInValues = z.infer<typeof signInSchema>;

/** Notices another route can hand over on the way here. */
const NOTICES = {
  expired: "Your session expired. Sign in again.",
  created: "Account created. Sign in to continue.",
  configured: "This server is already set up. Sign in to continue.",
} as const;

type NoticeKey = keyof typeof NOTICES;

function readNotice(search: string): NoticeKey | null {
  const reason = new URLSearchParams(search).get("reason");
  return reason && reason in NOTICES ? (reason as NoticeKey) : null;
}

/**
 * `next` arrives in the URL bar, so anything but a same-origin path is an open
 * redirect waiting to happen.
 */
function safeNext(search: string): string {
  const value = new URLSearchParams(search).get("next");
  if (!value || !value.startsWith("/") || value.startsWith("//")) return "/";
  return value;
}

export function SignInScreen() {
  return (
    <StartupGate
      resolveDestination={() => safeNext(window.location.search)}
    >
      <SignInPanel />
    </StartupGate>
  );
}

function SignInPanel() {
  const [notice, setNotice] = React.useState<NoticeKey | null>(null);
  const [failure, setFailure] = React.useState<AuthResult | null>(null);

  const {
    register,
    handleSubmit,
    setFocus,
    formState: { errors, isSubmitting },
  } = useForm<SignInValues>({ resolver: zodResolver(signInSchema) });

  React.useEffect(() => {
    setNotice(readNotice(window.location.search));
  }, []);

  const rejectedCredentials = failure?.ok === false && failure.kind === "credentials";

  const onSubmit = async (values: SignInValues) => {
    setNotice(null);
    setFailure(null);

    const result = await signIn(values);
    // `ok` means the session came back and is stored, not merely that the
    // request returned 200 — the navigation below has to land holding it.
    if (result.ok) {
      window.location.assign(safeNext(window.location.search));
      return;
    }

    setFailure(result);
    if (result.kind === "credentials") setFocus("email");
  };

  return (
    <AuthPage>
      <AuthColumn>
        <AuthBrand />

        <AuthPanel caption="SIGN IN — /login">
          <AuthHeading>Sign in</AuthHeading>

          {notice ? <AuthNotice>{NOTICES[notice]}</AuthNotice> : null}
          <FailureAlert failure={failure} />

          <form onSubmit={handleSubmit(onSubmit)} className="flex flex-col gap-3" noValidate>
            <TextField
              label="Email"
              type="email"
              autoComplete="username"
              autoFocus
              placeholder="you@example.com"
              error={errors.email?.message}
              invalid={rejectedCredentials}
              {...register("email")}
            />
            <PasswordField
              label="Password"
              autoComplete="current-password"
              error={errors.password?.message}
              {...register("password")}
            />
            <Button type="submit" className="w-full" loading={isSubmitting}>
              Sign in
            </Button>
          </form>

          <div className="flex flex-col gap-1.5">
            <span className="text-xs text-muted-foreground">
              New here?{" "}
              <a
                href="/signup"
                className="font-medium text-foreground underline-offset-4 hover:underline"
              >
                Create account
              </a>
            </span>
            {/*
              The design's "Forgot password?" link needs a recovery endpoint,
              and this server has none. A sentence beats a control that goes
              nowhere.
            */}
            <span className="text-[11px] leading-[15px] text-muted-foreground">
              Forgot your password? Ask an administrator to reset it.
            </span>
          </div>
        </AuthPanel>
      </AuthColumn>
    </AuthPage>
  );
}

function FailureAlert({ failure }: { failure: AuthResult | null }) {
  if (!failure || failure.ok) return null;

  if (failure.kind === "verification") {
    // No resend control: the server exposes no endpoint to resend against.
    return <InlineAlert tone="warning">Verify your email to continue.</InlineAlert>;
  }

  if (failure.kind === "unreachable") {
    return (
      <InlineAlert>
        Can&apos;t reach PlainQ at {failure.endpoint}. Check that the service is
        running.
      </InlineAlert>
    );
  }

  if (failure.kind === "degraded") {
    return (
      <div className="flex flex-col gap-1.5">
        <InlineAlert>The service is unavailable. Try again shortly.</InlineAlert>
        {failure.ref ? (
          <Micro className="text-[10px] text-subtle">ref {failure.ref}</Micro>
        ) : null}
      </div>
    );
  }

  if (failure.kind === "failed") {
    // Accepted, but nothing to sign in with. Saying "incorrect password" here
    // would send the operator after the wrong problem.
    return (
      <InlineAlert>
        The server accepted the sign-in but returned no session. Try again.
      </InlineAlert>
    );
  }

  return <InlineAlert>Incorrect email or password.</InlineAlert>;
}
