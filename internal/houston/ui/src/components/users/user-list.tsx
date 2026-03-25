import {
  Table,
  TableHeader,
  TableBody,
  TableRow,
  TableHead,
  TableCell,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";

export function UserList() {
  return (
    <div>
      <div className="mb-6">
        <h2 className="text-lg font-semibold">Users & Access</h2>
        <p className="text-sm text-muted-foreground">
          Manage users and their roles
        </p>
      </div>

      <div className="flex h-48 items-center justify-center rounded-lg border border-dashed">
        <p className="text-sm text-muted-foreground">
          User management coming soon
        </p>
      </div>
    </div>
  );
}
