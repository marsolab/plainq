import { ListPlus, Package, Repeat2, RotateCcw, type LucideIcon } from "lucide-react";

type FeatureIconName = "delivery" | "retry" | "batch" | "payload";

type FeatureIconProps = {
  name: FeatureIconName;
};

const icons: Record<FeatureIconName, LucideIcon> = {
  delivery: Repeat2,
  retry: RotateCcw,
  batch: ListPlus,
  payload: Package,
};

export default function FeatureIcon({ name }: FeatureIconProps) {
  const Icon = icons[name];

  return <Icon aria-hidden="true" className="shrink-0 text-[var(--color-accent)]" size={22} strokeWidth={1.65} />;
}
