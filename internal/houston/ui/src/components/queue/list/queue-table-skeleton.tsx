import { TableCell, TableRow } from "@/components/ui/table";
import { Skeleton } from "@/components/ui/skeleton";

/**
 * Occupies the exact column layout the loaded rows will, including the
 * two-line identity and timestamp cells, so nothing shifts when data lands.
 */
export function QueueTableSkeleton({ rows = 4 }: { rows?: number }) {
  return (
    <>
      {Array.from({ length: rows }, (_, index) => (
        <TableRow key={index}>
          <TableCell>
            <Skeleton className="h-[13px] w-32" />
            <Skeleton className="mt-1.5 h-[11px] w-52" />
          </TableCell>
          <TableCell>
            <Skeleton className="h-[13px] w-20" />
          </TableCell>
          <TableCell numeric>
            <Skeleton className="ml-auto h-[13px] w-6" />
          </TableCell>
          <TableCell numeric>
            <Skeleton className="ml-auto h-[13px] w-10" />
          </TableCell>
          <TableCell numeric>
            <Skeleton className="ml-auto h-[13px] w-12" />
          </TableCell>
          <TableCell>
            <Skeleton className="h-[13px] w-24" />
            <Skeleton className="mt-1.5 h-[11px] w-16" />
          </TableCell>
          <TableCell>
            <Skeleton className="size-7" />
          </TableCell>
        </TableRow>
      ))}
    </>
  );
}
