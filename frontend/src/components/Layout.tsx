import { Link, useLocation } from "react-router-dom";
import { Shield, Scan, BookOpen, LayoutDashboard } from "lucide-react";
import { cn } from "@/lib/utils";

const NAV = [
  { to: "/", label: "Dashboard", icon: LayoutDashboard },
  { to: "/scan", label: "Scan", icon: Scan },
  { to: "/rules", label: "Rules", icon: BookOpen },
];

export function Layout({ children }: { children: React.ReactNode }) {
  const { pathname } = useLocation();

  return (
    <div className="min-h-screen flex flex-col">
      {/* Top bar */}
      <header className="border-b bg-[var(--color-card)]">
        <div className="mx-auto flex h-14 max-w-6xl items-center px-4 gap-6">
          <Link to="/" className="flex items-center gap-2 font-bold text-lg">
            <Shield className="h-6 w-6 text-[var(--color-primary)]" />
            EURA
          </Link>

          <nav className="flex items-center gap-1 ml-6" aria-label="Main navigation">
            {NAV.map(({ to, label, icon: Icon }) => {
              const active = pathname === to || (to !== "/" && pathname.startsWith(to));
              return (
                <Link
                  key={to}
                  to={to}
                  className={cn(
                    "flex items-center gap-1.5 rounded-md px-3 py-1.5 text-sm font-medium transition-colors",
                    active
                      ? "bg-[var(--color-primary)] text-[var(--color-primary-foreground)]"
                      : "hover:bg-[var(--color-muted)]",
                  )}
                >
                  <Icon className="h-4 w-4" />
                  {label}
                </Link>
              );
            })}
          </nav>

          <div className="ml-auto text-xs text-[var(--color-muted-foreground)]">
            EU CRA &amp; AI Act Compliance
          </div>
        </div>
      </header>

      {/* Page content */}
      <main className="flex-1">
        <div className="mx-auto max-w-6xl px-4 py-8">{children}</div>
      </main>
    </div>
  );
}
