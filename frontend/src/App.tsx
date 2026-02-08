import { BrowserRouter, Routes, Route } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { Layout } from "@/components/Layout";
import { DashboardPage } from "@/pages/DashboardPage";
import { ScanPage } from "@/pages/ScanPage";
import { ResultsPage } from "@/pages/ResultsPage";
import { RuleExplorer } from "@/pages/RuleExplorer";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: { retry: 1, refetchOnWindowFocus: false },
  },
});

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <Layout>
          <Routes>
            <Route path="/" element={<DashboardPage />} />
            <Route path="/scan" element={<ScanPage />} />
            <Route path="/results" element={<ResultsPage />} />
            <Route path="/rules" element={<RuleExplorer />} />
          </Routes>
        </Layout>
      </BrowserRouter>
    </QueryClientProvider>
  );
}
