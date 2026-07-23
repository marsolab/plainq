"use client";

import * as React from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";

import { Panel, PanelBody } from "@/components/ui/panel";
import { PageHeader } from "@/components/ui/page-header";
import { LifecycleLegend } from "@/components/ui/empty-state";
import { Button } from "@/components/ui/button";
import { InlineAlert } from "@/components/ui/feedback";
import { Micro } from "@/components/ui/value";
import { Wordmark } from "@/components/layout/wordmark";
import { TextField, PasswordField } from "./form-fields";
import { StartupGate } from "./startup-gate";
import { completeOnboarding, type AuthResult } from "./auth-transport";

/**
 * S02 — first-run administrator setup.
 *
 * The left column is the one place the product explains itself; there is no
 * tour anywhere else.
 *
 * This posts to the onboarding endpoint, not to registration: it is the only
 * one that creates the account verified, gives it the admin role, and hands
 * back a session — which is exactly what the panel copy promises. Registration
 * would create an ordinary unverified account with no role and quietly succeed
 * on a server that was already set up.
 *
 * The local rules below mirror what that endpoint enforces (an address, eight
 * characters, a name under a hundred), so its rejections arrive as field errors
 * instead of an unexplained failure.
 */

const setupSchema = z
  .object({
    name: z.string().trim().max(100, "Use fewer than 100 characters.").optional(),
    email: z.email("Enter a valid email address."),
    password: z.string().min(8, "Use at least 8 characters."),
    confirmPassword: z.string().min(1, "Repeat the password."),
  })
  .refine((values) => values.password === values.confirmPassword, {
    message: "Passwords do not match.",
    path: ["confirmPassword"],
  });

type SetupValues = z.infer<typeof setupSchema>;

export function SetupScreen() {
  return (
    <StartupGate isSetupRoute>
      <SetupSplit />
    </StartupGate>
  );
}

function SetupSplit() {
  return (
    <main className="flex min-h-screen flex-col lg:flex-row">
      <aside className="flex w-full shrink-0 flex-col justify-center gap-5 border-b border-border px-8 py-10 lg:w-[520px] lg:border-r lg:border-b-0 lg:px-12 lg:py-14">
        <Wordmark size={28} />

        <PageHeader title="Set up PlainQ" className="mb-0" />

        <p className="max-w-[380px] text-[13px] leading-[1.6] text-strong">
          One binary, gRPC + HTTP, SQLite or PostgreSQL storage. Houston is its
          control plane: create queues, inspect traffic, test delivery, and recover
          from failures.
        </p>

        <LifecycleLegend className="mt-0" />

        <p className="max-w-[380px] text-xs leading-[1.55] text-muted-foreground">
          A received message turns invisible for its queue&apos;s visibility timeout.
          Acknowledge completes it; a timeout returns it to Visible and counts an
          attempt. Delivery is at least once — order is best effort.
        </p>
      </aside>

      <div className="flex flex-1 items-center justify-center px-6 py-12">
        <SetupPanel />
      </div>
    </main>
  );
}

function SetupPanel() {
  const [failure, setFailure] = React.useState<AuthResult | null>(null);

  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
  } = useForm<SetupValues>({ resolver: zodResolver(setupSchema) });

  const onSubmit = async (values: SetupValues) => {
    setFailure(null);

    const result = await completeOnboarding({
      email: values.email,
      password: values.password,
      name: values.name || undefined,
    });

    // Onboarding returns the new administrator's session, which the transport
    // has already stored — so this lands inside the app holding a credential,
    // not merely looking like it does.
    if (result.ok) {
      window.location.replace("/");
      return;
    }

    // Set up while this form was open. Nothing was created here; the operator
    // moves on to sign in rather than staying on a page with no job left.
    if (result.kind === "conflict") {
      window.location.replace("/login?reason=configured");
      return;
    }

    setFailure(result);
  };

  return (
    <Panel className="w-[400px] max-w-full">
      <PanelBody className="flex flex-col gap-4 p-7">
        <div>
          <h2 className="text-base leading-[22px] font-semibold">
            Create the first administrator
          </h2>
          <p className="mt-1 text-xs leading-[17px] text-muted-foreground">
            This account is created verified and manages access.
          </p>
        </div>

        <FailureAlert failure={failure} />

        <form
          onSubmit={handleSubmit(onSubmit)}
          className="flex flex-col gap-4"
          noValidate
        >
          <TextField
            label="Display name"
            optional
            autoComplete="name"
            placeholder="Maya"
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
            hint="At least 8 characters."
            error={errors.password?.message}
            {...register("password")}
          />
          <PasswordField
            label="Confirm password"
            autoComplete="new-password"
            error={errors.confirmPassword?.message}
            {...register("confirmPassword")}
          />
          {/* `loading` keeps the label and blocks a second submission. */}
          <Button type="submit" className="mt-1 w-full" loading={isSubmitting}>
            Create administrator
          </Button>
        </form>
      </PanelBody>
    </Panel>
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

  if (failure.kind === "rejected") {
    return <InlineAlert>{failure.message}</InlineAlert>;
  }

  return <InlineAlert>The administrator account could not be created.</InlineAlert>;
}
