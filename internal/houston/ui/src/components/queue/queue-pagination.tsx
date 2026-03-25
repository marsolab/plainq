import { Button } from "@/components/ui/button";
import { ChevronLeft, ChevronRight } from "lucide-react";
import { PAGE_SIZES } from "@/lib/constants";

interface QueuePaginationProps {
  hasMore: boolean;
  hasPrevious: boolean;
  pageSize: number;
  onNext: () => void;
  onPrevious: () => void;
  onPageSizeChange: (size: number) => void;
}

export function QueuePagination({
  hasMore,
  hasPrevious,
  pageSize,
  onNext,
  onPrevious,
  onPageSizeChange,
}: QueuePaginationProps) {
  return (
    <div className="flex items-center justify-between pt-4">
      <div className="flex items-center gap-2 text-sm text-muted-foreground">
        <span>Rows per page</span>
        <select
          value={pageSize}
          onChange={(e) => onPageSizeChange(Number(e.target.value))}
          className="h-8 rounded-md border border-input bg-surface px-2 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
        >
          {PAGE_SIZES.map((size) => (
            <option key={size} value={size}>
              {size}
            </option>
          ))}
        </select>
      </div>
      <div className="flex items-center gap-2">
        <Button
          variant="outline"
          size="icon"
          onClick={onPrevious}
          disabled={!hasPrevious}
        >
          <ChevronLeft className="size-4" />
        </Button>
        <Button
          variant="outline"
          size="icon"
          onClick={onNext}
          disabled={!hasMore}
        >
          <ChevronRight className="size-4" />
        </Button>
      </div>
    </div>
  );
}
