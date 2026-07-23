"use client";

import { ChevronDown, Download } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Micro } from "@/components/ui/value";
import { downloadCsv, downloadJson, type ExportSubject } from "./export";
import { Segmented } from "./segmented";
import { RANGE_KEYS, type RangeKey } from "./telemetry-data";

/**
 * The range applies to the charts only. The overview routes take no range —
 * they answer with process-current counters — so the tiles and the health
 * table below do not move when this changes, and the note says so.
 *
 * There is no custom from/to control: the API client exposes only the `range=`
 * presets the server understands, and a picker that silently rounded a typed
 * window to the nearest preset would be a lie about what was requested.
 */
export function RangeToolbar({
  range,
  onRangeChange,
  exportSubject,
  canExport,
  blockedExportReason,
}: {
  range: RangeKey;
  onRangeChange: (range: RangeKey) => void;
  exportSubject: ExportSubject | null;
  canExport: boolean;
  blockedExportReason?: string;
}) {
  return (
    <div className="flex flex-wrap items-center gap-2">
      <Segmented
        label="Time range"
        value={range}
        onChange={onRangeChange}
        options={RANGE_KEYS.map((key) => ({ value: key, label: key }))}
      />

      <Micro>charts only · counters are process-current</Micro>

      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button
            variant="outline"
            disabled={!exportSubject}
            blockedReason={canExport ? undefined : blockedExportReason}
          >
            <Download aria-hidden />
            Export
            <ChevronDown className="size-3" aria-hidden />
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end">
          <DropdownMenuItem
            onClick={() => {
              if (!exportSubject) return;
              toast.success(`Exported ${downloadCsv(exportSubject)}`);
            }}
          >
            CSV — samples on screen
          </DropdownMenuItem>
          <DropdownMenuItem
            onClick={() => {
              if (!exportSubject) return;
              toast.success(`Exported ${downloadJson(exportSubject)}`);
            }}
          >
            JSON — samples on screen
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>
    </div>
  );
}
