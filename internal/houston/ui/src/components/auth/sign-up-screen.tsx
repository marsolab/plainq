"use client";

import * as React from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";

import { Button, buttonVariants } from "@/components/ui/button";
import { InlineAlert } from "@/components/ui/feedback";
import { Micro } from "@/components/ui/value";
import { cn } from "@/lib/utils";
import { TextField, PasswordField } from "./form-fields";
import { AuthPage, AuthColumn, AuthPanel, AuthHeading, AuthNotice, AuthBrand } from "./auth-shell";
import { StartupGate } from "./startup-gate";
import { signUp, type AuthResult } from "./auth-transport";

/**
 * S04 — create account.
 *
 * No password rule is promised here. The server owns that policy and does not
 * publish it, so the only local check is that the two fields agree; anything
 * the server rejects comes back in its own words.
 *
 * A server with registration switched off answers 403, and the panel becomes
 * a locked state that says so — never a button that cannot work.
 */

const signUpSchema = z
  .object({
    name: z.string().trim().optional(),
    email: z.email("Enter a valid email address."),
    password: z.string().min(1, "Choose a password."),
    confirmPassword: z.string().min(1, "Repeat your password."),
  })
  .refine((values) => values.password === values.confirmPassword, {
    message: "Passwords do not match.",
    path: ["confirmPassword"],
  });

type SignUpValues = z.infer<typeof signUpSchema>;

export function SignUpScreen() {
  return (
    <StartupGate>
      <SignUpPanel />
    </StartupGate>
  );
}

function SignUpPanel() {
  const [failure, setFailure] = React.useState<AuthResult | null>(null);
  const [locked, setLocked] = React.useState(false);

  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
  } = useForm<SignUpValues>({ resolver: zodResolver(signUpSchema) });

  const onSubmit = async (values: SignUpValues) => {
    setFailure(null);

    const result = await signUp({
      email: values.email,
      password: values.password,
      name: values.name || undefined,
    });

    if (result.ok) {
      // Registration answers 201 with no body and no session, so the new
      // account is not signed in — saying otherwise would be the lie.
      window.location.replace("/login?reason=created");
      return;
    }

    if (result.kind === "registration-disabled") {
      setLocked(true);
      return;
    }

    setFailure(result);
  };

  return (
    <AuthPage>
      <AuthColumn>
        <AuthBrand />

        <AuthPanel caption="CREATE ACCOUNT — /signup">
          <AuthHeading>Create account</AuthHeading>

          {locked ? (
            <RegistrationLocked />
          ) : (
            <>
              <FailureAlert failure={failure} />

              <form
                onSubmit={handleSubmit(onSubmit)}
                className="flex flex-col gap-3"
                noValidate
              >
                <TextField
                  label="Name"
                  optional
                  autoComplete="name"
                  placeholder="Samir"
                  error={errors.name?.message}
                  {...register("name")}
                />
                <TextField
                  label="Email"
                  type="email"
                  autoComplete="email"
                  placeholder="you@example.com"
                  error={errors.email?.message}
                  {...register("email")}
                />
                <PasswordField
                  label="Password"
                  autoComplete="new-password"
                  error={errors.password?.message}
                  {...register("password")}
                />
                <PasswordField
                  label="Confirm password"
                  autoComplete="new-password"
                  error={errors.confirmPassword?.message}
                  {...register("confirmPassword")}
                />
                <Button type="submit" className="w-full" loading={isSubmitting}>
                  Create account
                </Button>
              </form>

              <div className="flex flex-col gap-1.5">
                <span className="text-xs text-muted-foreground">
                  Have an account?{" "}
                  <a
                    href="/login"
                    className="font-medium text-foreground underline-offset-4 hover:underline"
                  >
                    Sign in
                  </a>
                </span>
                <span className="text-[11px] leading-[15px] text-muted-foreground">
                  An administrator may need to grant queue access after you register.
                </span>
              </div>
            </>
          )}
        </AuthPanel>
      </AuthColumn>
    </AuthPage>
  );
}

function RegistrationLocked() {
  return (
    <>
      <AuthNotice>
        Registration is disabled on this server. Ask an administrator for an account.
      </AuthNotice>
      <a
        href="/login"
        className={cn(buttonVariants({ variant: "outline" }), "w-full")}
      >
        Go to sign in
      </a>
    </>
  );
}

function FailureAlert({ failure }: { failure: AuthResult | null }) {
  if (!failure || failure.ok) return null;

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

  if (failure.kind === "conflict") {
    // Deliberately not "that address is taken" — same wording whether the
    // address is registered or merely disallowed.
    return (
      <InlineAlert
        action={
          <a href="/login" className="underline-offset-4 hover:underline">
            Sign in
          </a>
        }
      >
        That email address can&apos;t be registered here.
      </InlineAlert>
    );
  }

  if (failure.kind === "rejected") {
    return <InlineAlert>{failure.message}</InlineAlert>;
  }

  return <InlineAlert>That account could not be created.</InlineAlert>;
}
