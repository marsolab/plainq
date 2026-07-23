"use client";

import { ChevronLeft, ChevronRight } from "lucide-react";

import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Micro } from "@/components/ui/value";
import { PAGE_SIZES } from "@/lib/constants";

interface QueuePaginationProps {
  /** Rows asked for per request — the transport's `limit`, not a page size. */
  rowsPerRequest: number;
  hasPrevious: boolean;
  hasMore: boolean;
  disabled?: boolean;
  onPrevious: () => void;
  onNext: () => void;
  onRowsPerRequestChange: (rows: number) => void;
}

/**
 * The transport pages by cursor: it reports whether another page exists and
 * nothing else. There is no total, so there are no page numbers and no
 * "showing 1–20 of N" — the note says so out loud.
 */
export function QueuePagination({
  rowsPerRequest,
  hasPrevious,
  hasMore,
  disabled = false,
  onPrevious,
  onNext,
  onRowsPerRequestChange,
}: QueuePaginationProps) {
  return (
    <div className="flex items-center justify-between gap-4 border-t border-border px-4 py-2.5">
      <div className="flex items-center gap-2 text-xs text-muted-foreground">
        <label htmlFor="rows-per-request">Rows per request</label>
        <Select
          value={String(rowsPerRequest)}
          onValueChange={(value) => onRowsPerRequestChange(Number(value))}
          disabled={disabled}
        >
          <SelectTrigger
            id="rows-per-request"
            size="sm"
            className="font-mono text-xs tabular text-foreground"
          >
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {PAGE_SIZES.map((size) => (
              <SelectItem key={size} value={String(size)} className="font-mono tabular">
                {size}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Micro className="text-subtle">cursor pagination · no total count</Micro>
      </div>

      <div className="flex items-center gap-2">
        <Button
          variant="outline"
          size="sm"
          onClick={onPrevious}
          disabled={disabled || !hasPrevious}
        >
          <ChevronLeft aria-hidden />
          Previous
        </Button>
        <Button variant="outline" size="sm" onClick={onNext} disabled={disabled || !hasMore}>
          Next
          <ChevronRight aria-hidden />
        </Button>
      </div>
    </div>
  );
}
