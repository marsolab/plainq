import * as React from "react";
import { Check, Copy } from "lucide-react";

import { Button } from "@/components/ui/button";

interface CopyButtonProps {
  /** Raw text to copy to the clipboard. */
  value: string;
  label?: string;
}

/** Small copy-to-clipboard button, used on terminal/code snippets. */
export default function CopyButton({ value, label = "Copy" }: CopyButtonProps) {
  const [copied, setCopied] = React.useState(false);

  const copy = React.useCallback(async () => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      setTimeout(() => setCopied(false), 1800);
    } catch {
      /* Clipboard API may be blocked; fail quietly. */
    }
  }, [value]);

  return (
    <Button
      variant="ghost"
      size="icon"
      onClick={copy}
      aria-label={copied ? "Copied" : label}
      title={copied ? "Copied" : label}
      className="h-8 w-8 text-[var(--color-muted-foreground)] hover:text-[var(--color-foreground)]"
    >
      {copied ? <Check className="text-[var(--color-success)]" /> : <Copy />}
    </Button>
  );
}
