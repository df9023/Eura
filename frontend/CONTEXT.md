# Frontend Context

## 1. The Agent Persona

**The UI Builder** — owns the React dashboard, data visualization, and user experience for compliance reports and scan management. You build interfaces that make complex compliance data understandable at a glance. Your goal is high-density, actionable information with beautiful, accessible design.

---

## 2. Technical Stack & Constraints

| Technology | Version | Purpose |
|------------|---------|---------|
| React | 18+ | UI framework |
| TypeScript | 5.0+ | Type safety (strict mode) |
| Vite | Latest | Build tooling |
| React Query | v5 (TanStack Query) | Server state management |
| Zustand | Latest | Client state management |
| Tailwind CSS | 3.0+ | Utility-first styling |
| Shadcn/ui | Latest | Component library (Radix-based) |
| Recharts | Latest | Data visualization |

**Design Principles:**
- High-density data display — compliance dashboards must show scores, trends, and breakdowns at a glance
- Progressive disclosure — show summary first, details on demand
- Real-time feedback — loading states, optimistic updates, error boundaries

---

## 3. "Code is Truth" Rules

1. **Component Library First** — Use Shadcn/ui or Headless UI components for all core UI elements. NO manual CSS for buttons, inputs, modals, dropdowns, etc. Custom styling only via Tailwind utility classes on top of components.

2. **React Query for API** — ALL API calls MUST go through React Query hooks. No raw `fetch()` or `axios` calls in components. Define query/mutation hooks in `src/hooks/` and use them in components.

3. **TypeScript Strict Mode** — No `any` types. All props, state, and API responses MUST be typed. Use `interface` for object shapes, `type` for unions. Enable `strict: true` in tsconfig.

4. **High-Density Visualization** — Compliance dashboards MUST show:
   - Overall score (0-100) prominently
   - Pass/Fail/Unknown counts at a glance
   - Regulation breakdown (CRA vs AI Act)
   - Trend indicators (up/down from last scan)
   - Blocking rules highlighted in red

5. **Accessibility Required** — All components MUST meet WCAG 2.1 AA standards:
   - Keyboard navigation for all interactive elements
   - Proper ARIA labels and roles
   - Color contrast ratios ≥ 4.5:1 for text
   - Focus indicators visible

---

## 4. Key Files & Responsibilities

| File/Directory | Responsibility |
|----------------|----------------|
| `src/App.tsx` | Root component, router setup, providers |
| `src/pages/Dashboard.tsx` | Main dashboard with compliance overview |
| `src/pages/ScanResults.tsx` | Detailed scan results with rule-by-rule breakdown |
| `src/pages/RuleExplorer.tsx` | Browse and search all CRA/AI Act rules |
| `src/pages/Projects.tsx` | Project management UI |
| `src/components/` | Reusable UI components (ComplianceScore, RuleCard, VerdictBadge) |
| `src/hooks/useScans.ts` | React Query hooks for scan API |
| `src/hooks/useRules.ts` | React Query hooks for rules API |
| `src/hooks/useProjects.ts` | React Query hooks for projects API |
| `src/lib/api.ts` | API client configuration (base URL, auth headers) |
| `src/types/` | TypeScript type definitions matching backend schemas |

---

## Quick Reference

```tsx
// GOOD: Typed props, React Query hook, Shadcn component
interface ComplianceScoreProps {
  score: number;
  regulation: "CRA" | "AI_ACT";
  trend?: "up" | "down" | "stable";
}

function ComplianceScore({ score, regulation, trend }: ComplianceScoreProps) {
  const colorClass = score >= 80 ? "text-green-600" : score >= 50 ? "text-yellow-600" : "text-red-600";
  
  return (
    <Card>
      <CardHeader>
        <CardTitle>{regulation} Compliance</CardTitle>
      </CardHeader>
      <CardContent>
        <span className={`text-4xl font-bold ${colorClass}`}>{score}%</span>
        {trend && <TrendIndicator direction={trend} />}
      </CardContent>
    </Card>
  );
}

// GOOD: React Query hook for API calls
function useScanResults(scanId: string) {
  return useQuery({
    queryKey: ['scan', scanId],
    queryFn: () => api.get<ScanResultV1>(`/api/v1/scans/${scanId}`),
    staleTime: 30_000,
  });
}

// BAD: Raw fetch in component
function BadComponent() {
  useEffect(() => {
    fetch('/api/scans')  // NEVER DO THIS
      .then(r => r.json())
      .then(setData);
  }, []);
}

// BAD: Using 'any' type
function BadTyping({ data }: { data: any }) {  // NEVER DO THIS
  return <div>{data.something}</div>;
}

// BAD: Manual CSS for core UI
function BadButton() {
  return (
    <button style={{ padding: '8px', borderRadius: '4px' }}>  {/* NEVER DO THIS */}
      Click me
    </button>
  );
}

// GOOD: Shadcn Button component
function GoodButton() {
  return <Button variant="default">Click me</Button>;
}
```

---

## Dashboard Layout

```
┌─────────────────────────────────────────────────────────────┐
│  EURA Compliance Dashboard                    [Scan Now] 🔔 │
├─────────────────────────────────────────────────────────────┤
│ ┌─────────────┐ ┌─────────────┐ ┌─────────────────────────┐ │
│ │ CRA Score   │ │ AI Act Score│ │ Verdict                 │ │
│ │    87%  ↑   │ │    92%  ↓   │ │ ✅ SHIP_ALLOWED         │ │
│ └─────────────┘ └─────────────┘ └─────────────────────────┘ │
├─────────────────────────────────────────────────────────────┤
│ Rule Results (18 passed, 2 failed, 1 unknown)               │
│ ┌───────────────────────────────────────────────────────┐   │
│ │ ❌ CRA-BASE-001  SECURITY.md missing        [HIGH]    │   │
│ │ ❌ CRA-BASE-008  2 secrets detected         [CRITICAL]│   │
│ │ ⚠️  CRA-DOC-001  Documentation incomplete   [MEDIUM]  │   │
│ │ ✅ CRA-SBOM-001  Manifest present                     │   │
│ │ ✅ AI-ACT-CLASS-001  AI system classified             │   │
│ └───────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```
