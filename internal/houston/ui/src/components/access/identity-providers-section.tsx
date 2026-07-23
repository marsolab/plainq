"use client";

import * as React from "react";
import { Eye, EyeOff, MoreHorizontal, Plus, ShieldCheck } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { EmptyState } from "@/components/ui/empty-state";
import { InlineAlert } from "@/components/ui/feedback";
import { Input, MonoInput } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Panel } from "@/components/ui/panel";
import { Status } from "@/components/ui/status";
import { CopyableId } from "@/components/ui/value";
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
  IDENTITY_PROVIDER_TYPES,
  type IdentityProvider,
} from "./mock-data";

const EDIT_BLOCKED_REASON =
  "Provider get and update endpoints aren't available yet, so there is no edit form.";

/** The provider slug the callback route is registered under. */
function slugOf(type: string): string {
  return type.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
}

interface IdentityProvidersSectionProps {
  providers: IdentityProvider[];
  /** Providers are scoped to the organization being administered. */
  organizationName: string;
  onProvidersChange: (providers: IdentityProvider[]) => void;
  blockedReason?: string;
}

export function IdentityProvidersSection({
  providers,
  organizationName,
  onProvidersChange,
  blockedReason,
}: IdentityProvidersSectionProps) {
  const [creating, setCreating] = React.useState(false);
  const [deleteTarget, setDeleteTarget] = React.useState<IdentityProvider | null>(null);
  const [confirmName, setConfirmName] = React.useState("");

  const remove = (provider: IdentityProvider) => {
    onProvidersChange(
      providers.filter((candidate) => candidate.providerId !== provider.providerId),
    );
    setDeleteTarget(null);
    setConfirmName("");
    toast.success(`${provider.name} deleted`);
  };

  return (
    <>
      <Panel className="max-w-[720px]">
        <div className="flex h-11 items-center justify-between gap-3 border-b border-border px-4">
          <span className="text-[13px] font-semibold">Identity providers</span>
          <Button size="sm" blockedReason={blockedReason} onClick={() => setCreating(true)}>
            <Plus aria-hidden />
            Add provider
          </Button>
        </div>

        {providers.length === 0 ? (
          <EmptyState
            icon={ShieldCheck}
            title="No identity providers"
            description="Accounts sign in locally until a provider is registered. Creating one stores the configuration; the browser sign-in flow still needs integration."
          />
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Type</TableHead>
                <TableHead>Scope</TableHead>
                <TableHead>Active</TableHead>
                <TableHead>Synchronization</TableHead>
                <TableHead className="w-11" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {providers.map((provider) => (
                <TableRow key={provider.providerId}>
                  <TableCell className="font-semibold">{provider.name}</TableCell>
                  <TableCell>{provider.type}</TableCell>
                  <TableCell className="text-muted-foreground">{provider.scope}</TableCell>
                  <TableCell>
                    <Status
                      tone={provider.active ? "healthy" : "neutral"}
                      markerClassName="size-[7px]"
                      className={provider.active ? undefined : "text-muted-foreground"}
                    >
                      {provider.active ? "Active" : "Inactive"}
                    </Status>
                  </TableCell>
                  <TableCell className="text-xs text-muted-foreground">
                    Unavailable — needs integration
                  </TableCell>
                  <TableCell>
                    <DropdownMenu>
                      <DropdownMenuTrigger asChild>
                        <Button
                          variant="ghost"
                          size="icon-sm"
                          aria-label={`Actions for ${provider.name}`}
                        >
                          <MoreHorizontal aria-hidden />
                        </Button>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="end">
                        <DropdownMenuItem disabled title={EDIT_BLOCKED_REASON}>
                          Edit provider — unavailable
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
          Deleting a provider requires typing its exact name. Editing stays unavailable until the
          get and update endpoints land — no fake edit form, no "Test connection", and no "Sign in
          with…" until the full browser flow works.
        </div>
      </Panel>

      <CreateProviderSheet
        open={creating}
        scope={organizationName}
        onOpenChange={setCreating}
        onCreate={(provider) => {
          onProvidersChange([...providers, provider]);
          setCreating(false);
          toast.success(`${provider.name} created`);
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
              Accounts synchronized from this provider keep their roles, but nobody can sign in
              through it again. Type the provider name to confirm.
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
              onClick={() => deleteTarget && remove(deleteTarget)}
            >
              Delete provider
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}

interface CreateProviderSheetProps {
  open: boolean;
  scope: string;
  onOpenChange: (open: boolean) => void;
  onCreate: (provider: IdentityProvider) => void;
}

function CreateProviderSheet({
  open,
  scope,
  onOpenChange,
  onCreate,
}: CreateProviderSheetProps) {
  const [type, setType] = React.useState(IDENTITY_PROVIDER_TYPES[0]!);
  const [name, setName] = React.useState("");
  const [issuer, setIssuer] = React.useState("");
  const [clientId, setClientId] = React.useState("");
  const [clientSecret, setClientSecret] = React.useState("");
  const [revealSecret, setRevealSecret] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);
  const [origin, setOrigin] = React.useState("");

  React.useEffect(() => {
    setOrigin(window.location.origin);
  }, []);

  React.useEffect(() => {
    if (!open) return;
    setType(IDENTITY_PROVIDER_TYPES[0]!);
    setName("");
    setIssuer("");
    setClientId("");
    setClientSecret("");
    setRevealSecret(false);
    setError(null);
  }, [open]);

  const callbackUrl = `${origin}/auth/callback/${slugOf(type)}`;

  const submit = () => {
    if (!name.trim() || !issuer.trim() || !clientId.trim() || !clientSecret) {
      setError("Name, issuer, client ID and client secret are all required.");
      return;
    }

    onCreate({
      providerId: `idp_${Date.now().toString(36)}`,
      name: name.trim(),
      type,
      scope,
      // A provider only becomes active once the browser sign-in flow exists.
      active: false,
    });
  };

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent title="Add identity provider">
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
                      {option}
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
                Write-only. Never shown again after save.
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
              Register this exact URL with the provider.
            </span>
          </div>

          <div className="flex justify-end gap-2 border-t border-border pt-3.5">
            <Button variant="outline" onClick={() => onOpenChange(false)}>
              Cancel
            </Button>
            <Button onClick={submit}>Create provider</Button>
          </div>
        </div>
      </SheetContent>
    </Sheet>
  );
}
