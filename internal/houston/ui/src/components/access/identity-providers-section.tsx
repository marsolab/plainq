"use client";

import * as React from "react";
import { Eye, EyeOff, MoreHorizontal, Plus, ShieldCheck } from "lucide-react";
import { toast } from "sonner";

import { api } from "@/lib/api-client";
import { Button } from "@/components/ui/button";
import { EmptyState } from "@/components/ui/empty-state";
import { InlineAlert } from "@/components/ui/feedback";
import { Input, MonoInput } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Panel } from "@/components/ui/panel";
import { Skeleton } from "@/components/ui/skeleton";
import { Status } from "@/components/ui/status";
import { CopyableId, Timestamp } from "@/components/ui/value";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

import { Sheet, SheetContent } from "./sheet";
import {
  CLIENT_ID_KEY,
  CLIENT_SECRET_KEY,
  DISPLAY_NAME_KEY,
  IDENTITY_PROVIDER_TYPES,
  ISSUER_KEY,
  describeFailure,
  providerTypeLabel,
  toProvider,
  type IdentityProvider,
} from "./model";

/**
 * Registering a provider stores its configuration. It does not make anybody
 * able to sign in through it: PlainQ has no browser authorization-code flow and
 * no callback route, so the sign-in half is genuinely absent rather than hidden
 * behind a flag.
 */
const NO_BROWSER_FLOW =
  "Providers are stored and can be activated, but PlainQ has no browser sign-in flow: there is no authorization-code redirect and no callback route. Configuration here is used by the server's synchronization API, not by a “Sign in with…” button.";

interface IdentityProvidersSectionProps {
  blockedReason?: string;
}

export function IdentityProvidersSection({ blockedReason }: IdentityProvidersSectionProps) {
  const [providers, setProviders] = React.useState<IdentityProvider[] | null>(null);
  const [error, setError] = React.useState<string | null>(null);
  const [loading, setLoading] = React.useState(true);
  const [editing, setEditing] = React.useState<IdentityProvider | null>(null);
  const [creating, setCreating] = React.useState(false);
  const [deleteTarget, setDeleteTarget] = React.useState<IdentityProvider | null>(null);
  const [confirmName, setConfirmName] = React.useState("");
  const [busy, setBusy] = React.useState<string | null>(null);

  const load = React.useCallback(async () => {
    setLoading(true);

    try {
      const response = await api.oauth.providers.list();
      setProviders(
        (response.providers ?? []).map((provider) =>
          toProvider(provider, response.sync_stats ?? []),
        ),
      );
      setError(null);
    } catch (failure) {
      setError(describeFailure(failure, "read the identity providers"));
    } finally {
      setLoading(false);
    }
  }, []);

  React.useEffect(() => {
    void load();
  }, [load]);

  const remove = async (provider: IdentityProvider) => {
    setBusy(provider.providerId);

    try {
      await api.oauth.providers.delete(provider.providerId);
      setDeleteTarget(null);
      setConfirmName("");
      await load();
      toast.success(`${provider.name} deleted`);
    } catch (failure) {
      setError(describeFailure(failure, `delete ${provider.name}`));
    } finally {
      setBusy(null);
    }
  };

  const toggleActive = async (provider: IdentityProvider) => {
    setBusy(provider.providerId);

    try {
      await api.oauth.providers.update(provider.providerId, { is_active: !provider.active });
      await load();
      toast.success(`${provider.name} ${provider.active ? "deactivated" : "activated"}`);
    } catch (failure) {
      setError(
        describeFailure(failure, `${provider.active ? "deactivate" : "activate"} ${provider.name}`),
      );
    } finally {
      setBusy(null);
    }
  };

  if (loading && providers === null) {
    return (
      <Panel className="max-w-[720px] p-4">
        <Skeleton className="h-4 w-48" />
      </Panel>
    );
  }

  if (error && providers === null) {
    return (
      <Panel className="max-w-[720px]">
        <EmptyState
          icon={ShieldCheck}
          title="Identity providers could not be read"
          description={error}
          action={
            <Button variant="outline" onClick={() => void load()}>
              Try again
            </Button>
          }
        />
      </Panel>
    );
  }

  const rows = providers ?? [];

  return (
    <div className="flex max-w-[860px] flex-col gap-3">
      <InlineAlert tone="warning" className="items-start">
        {NO_BROWSER_FLOW}
      </InlineAlert>

      {error ? <InlineAlert className="items-start">{error}</InlineAlert> : null}

      <Panel>
        <div className="flex h-11 items-center justify-between gap-3 border-b border-border px-4">
          <span className="text-[13px] font-semibold">Identity providers</span>
          <Button size="sm" blockedReason={blockedReason} onClick={() => setCreating(true)}>
            <Plus aria-hidden />
            Add provider
          </Button>
        </div>

        {rows.length === 0 ? (
          <EmptyState
            icon={ShieldCheck}
            title="No identity providers"
            description="Accounts sign in locally until a provider is registered. Creating one stores the configuration the synchronization API uses."
          />
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Type</TableHead>
                <TableHead>Issuer</TableHead>
                <TableHead>Active</TableHead>
                <TableHead>Synchronized accounts</TableHead>
                <TableHead>Last synchronized</TableHead>
                <TableHead className="w-11" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.map((provider) => (
                <TableRow key={provider.providerId}>
                  <TableCell className="font-semibold">{provider.name}</TableCell>
                  <TableCell>{providerTypeLabel(provider.type)}</TableCell>
                  <TableCell className="font-mono text-[11px] text-muted-foreground">
                    {provider.issuer || <span className="text-subtle">not set</span>}
                  </TableCell>
                  <TableCell>
                    <Status
                      tone={provider.active ? "healthy" : "neutral"}
                      markerClassName="size-[7px]"
                      className={provider.active ? undefined : "text-muted-foreground"}
                    >
                      {provider.active ? "Active" : "Inactive"}
                    </Status>
                  </TableCell>
                  <TableCell className="font-mono tabular">{provider.userCount ?? "—"}</TableCell>
                  <TableCell>
                    {provider.lastSyncAt ? (
                      <Timestamp value={provider.lastSyncAt} />
                    ) : (
                      <span className="text-subtle">never</span>
                    )}
                  </TableCell>
                  <TableCell>
                    <DropdownMenu>
                      <DropdownMenuTrigger asChild>
                        <Button
                          variant="ghost"
                          size="icon-sm"
                          aria-label={`Actions for ${provider.name}`}
                          loading={busy === provider.providerId}
                        >
                          <MoreHorizontal aria-hidden />
                        </Button>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="end">
                        <DropdownMenuItem
                          disabled={Boolean(blockedReason)}
                          onSelect={() => {
                            window.requestAnimationFrame(() => setEditing(provider));
                          }}
                        >
                          {blockedReason ? "Edit provider — not permitted" : "Edit provider"}
                        </DropdownMenuItem>
                        <DropdownMenuItem
                          disabled={Boolean(blockedReason)}
                          onSelect={() => {
                            window.requestAnimationFrame(() => void toggleActive(provider));
                          }}
                        >
                          {provider.active ? "Deactivate" : "Activate"}
                        </DropdownMenuItem>
                        <DropdownMenuSeparator />
                        {/*
                          A disabled item takes no pointer events, so a title
                          tooltip would be unreachable — the reason has to be
                          readable in the label itself.
                        */}
                        <DropdownMenuItem
                          variant="destructive"
                          disabled={Boolean(blockedReason)}
                          onSelect={() => {
                            // The menu restores focus as it closes; opening the
                            // dialog in the same tick lets that dismissal close
                            // it again, so hand off to the next frame.
                            window.requestAnimationFrame(() => {
                              setDeleteTarget(provider);
                              setConfirmName("");
                            });
                          }}
                        >
                          {blockedReason
                            ? "Delete provider — not permitted"
                            : "Delete provider"}
                        </DropdownMenuItem>
                        {blockedReason ? (
                          <div className="max-w-56 px-2.5 pb-1.5 text-[11px] leading-[15px] text-muted-foreground">
                            {blockedReason}
                          </div>
                        ) : null}
                      </DropdownMenuContent>
                    </DropdownMenu>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}

        <div className="border-t border-border px-4 py-2.5 text-[11px] leading-[15px] text-subtle">
          Deleting a provider requires typing its exact name. Client secrets are never returned by
          the server: an edit that leaves the secret field blank keeps the stored one, and there is
          no "Test connection" because nothing here can perform a sign-in.
        </div>
      </Panel>

      <ProviderSheet
        key={editing?.providerId ?? "new"}
        open={creating || editing !== null}
        provider={editing}
        onOpenChange={(open) => {
          if (!open) {
            setCreating(false);
            setEditing(null);
          }
        }}
        onSaved={async (message) => {
          setCreating(false);
          setEditing(null);
          await load();
          toast.success(message);
        }}
      />

      <Dialog
        open={Boolean(deleteTarget)}
        onOpenChange={(open) => {
          if (!open) {
            setDeleteTarget(null);
            setConfirmName("");
          }
        }}
      >
        <DialogContent className="sm:max-w-[440px]">
          <DialogHeader>
            <DialogTitle>Delete {deleteTarget?.name}?</DialogTitle>
            <DialogDescription>
              Accounts synchronized from this provider keep their roles, but the server will no
              longer synchronize through it. Type the provider name to confirm.
            </DialogDescription>
          </DialogHeader>
          <Input
            value={confirmName}
            onChange={(event) => setConfirmName(event.target.value)}
            placeholder={deleteTarget?.name}
            aria-label="Provider name"
          />
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => {
                setDeleteTarget(null);
                setConfirmName("");
              }}
            >
              Cancel
            </Button>
            <Button
              variant="destructive"
              disabled={confirmName !== deleteTarget?.name}
              loading={busy === deleteTarget?.providerId}
              onClick={() => deleteTarget && void remove(deleteTarget)}
            >
              Delete provider
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

interface ProviderSheetProps {
  open: boolean;
  /** Null when registering a new provider. */
  provider: IdentityProvider | null;
  onOpenChange: (open: boolean) => void;
  onSaved: (message: string) => Promise<void>;
}

function ProviderSheet({ open, provider, onOpenChange, onSaved }: ProviderSheetProps) {
  const editingExisting = provider !== null;

  const [type, setType] = React.useState(provider?.type ?? IDENTITY_PROVIDER_TYPES[0]!);
  const [name, setName] = React.useState(provider?.name ?? "");
  const [issuer, setIssuer] = React.useState(provider?.issuer ?? "");
  const [clientId, setClientId] = React.useState(provider?.clientId ?? "");
  const [clientSecret, setClientSecret] = React.useState("");
  const [revealSecret, setRevealSecret] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);
  const [saving, setSaving] = React.useState(false);
  const [origin, setOrigin] = React.useState("");

  React.useEffect(() => {
    setOrigin(window.location.origin);
  }, []);

  const secretStored = provider?.redactedKeys.includes(CLIENT_SECRET_KEY) ?? false;
  const callbackUrl = `${origin}/auth/callback/${type}`;

  const submit = async () => {
    if (!name.trim() || !issuer.trim() || !clientId.trim()) {
      setError("Name, issuer and client ID are all required.");
      return;
    }

    if (!editingExisting && !clientSecret) {
      setError("A client secret is required when registering a provider.");
      return;
    }

    const config: Record<string, string> = {
      [DISPLAY_NAME_KEY]: name.trim(),
      [ISSUER_KEY]: issuer.trim(),
      [CLIENT_ID_KEY]: clientId.trim(),
    };

    // Only send a secret that was actually typed. The server keeps the stored
    // one for any secret key this request does not name, so an untouched field
    // leaves the credential alone instead of blanking it.
    if (clientSecret) config[CLIENT_SECRET_KEY] = clientSecret;

    setSaving(true);
    setError(null);

    try {
      if (provider) {
        await api.oauth.providers.update(provider.providerId, {
          provider_name: type,
          config,
        });
        await onSaved(`${name.trim()} updated`);
      } else {
        await api.oauth.providers.create({ provider_name: type, config });
        await onSaved(`${name.trim()} created`);
      }
    } catch (failure) {
      setError(
        describeFailure(failure, editingExisting ? "update the provider" : "create the provider"),
      );
    } finally {
      setSaving(false);
    }
  };

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent title={editingExisting ? `Edit ${provider.name}` : "Add identity provider"}>
        <div className="flex flex-col gap-3.5 px-5 py-4">
          {error ? <InlineAlert>{error}</InlineAlert> : null}

          <div className="grid grid-cols-2 gap-3">
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="idp-type">Type</Label>
              <Select value={type} onValueChange={setType}>
                <SelectTrigger id="idp-type" className="w-full">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {IDENTITY_PROVIDER_TYPES.map((option) => (
                    <SelectItem key={option} value={option}>
                      {providerTypeLabel(option)}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="idp-name">Name</Label>
              <Input
                id="idp-name"
                value={name}
                onChange={(event) => setName(event.target.value)}
                placeholder="Kinde production"
              />
            </div>
          </div>

          <div className="flex flex-col gap-1.5">
            <Label htmlFor="idp-issuer">Issuer / domain</Label>
            <MonoInput
              id="idp-issuer"
              value={issuer}
              onChange={(event) => setIssuer(event.target.value)}
              placeholder="https://acme.kinde.com"
            />
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="idp-client-id">Client ID</Label>
              <MonoInput
                id="idp-client-id"
                value={clientId}
                onChange={(event) => setClientId(event.target.value)}
                placeholder="kn_client_8f3a…"
              />
            </div>
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="idp-client-secret">Client secret</Label>
              <div className="relative">
                <Input
                  id="idp-client-secret"
                  type={revealSecret ? "text" : "password"}
                  value={clientSecret}
                  onChange={(event) => setClientSecret(event.target.value)}
                  placeholder={secretStored ? "Stored — leave blank to keep" : ""}
                  className="pr-8 font-mono"
                />
                <button
                  type="button"
                  onClick={() => setRevealSecret((shown) => !shown)}
                  aria-label={revealSecret ? "Hide client secret" : "Show client secret"}
                  className="absolute top-1/2 right-2 -translate-y-1/2 cursor-pointer text-muted-foreground hover:text-foreground"
                >
                  {revealSecret ? (
                    <EyeOff className="size-[13px]" aria-hidden />
                  ) : (
                    <Eye className="size-[13px]" aria-hidden />
                  )}
                </button>
              </div>
              <span className="text-[11px] text-muted-foreground">
                {secretStored
                  ? "A secret is stored. The server never returns it — leave this blank to keep it."
                  : "Write-only. The server never returns it after save."}
              </span>
            </div>
          </div>

          <div className="flex flex-col gap-1.5">
            <Label>Callback URL</Label>
            <CopyableId
              value={callbackUrl}
              label="Callback URL"
              className="w-full justify-between bg-muted px-2.5 py-[7px]"
            />
            <span className="text-[11px] text-muted-foreground">
              The URL a browser flow would use. PlainQ does not serve it yet, so registering it
              with the provider prepares for that flow rather than enabling one.
            </span>
          </div>

          <div className="flex justify-end gap-2 border-t border-border pt-3.5">
            <Button variant="outline" onClick={() => onOpenChange(false)}>
              Cancel
            </Button>
            <Button loading={saving} onClick={() => void submit()}>
              {editingExisting ? "Save provider" : "Create provider"}
            </Button>
          </div>
        </div>
      </SheetContent>
    </Sheet>
  );
}
