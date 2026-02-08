import { cn } from "@/lib/utils";
import { cva, type VariantProps } from "class-variance-authority";
import type { HTMLAttributes } from "react";

const badgeVariants = cva(
  "inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-semibold transition-colors",
  {
    variants: {
      variant: {
        default: "border-transparent bg-[var(--color-primary)] text-[var(--color-primary-foreground)]",
        success: "border-transparent bg-[var(--color-success)] text-white",
        destructive: "border-transparent bg-[var(--color-destructive)] text-white",
        warning: "border-transparent bg-[var(--color-warning)] text-white",
        outline: "text-[var(--color-foreground)]",
        muted: "border-transparent bg-[var(--color-muted)] text-[var(--color-muted-foreground)]",
      },
    },
    defaultVariants: { variant: "default" },
  },
);

export interface BadgeProps
  extends HTMLAttributes<HTMLDivElement>,
    VariantProps<typeof badgeVariants> {}

export function Badge({ className, variant, ...props }: BadgeProps) {
  return <div className={cn(badgeVariants({ variant }), className)} {...props} />;
}
