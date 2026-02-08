import { useMutation, useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import type { ScanRequest, ScanResponse } from "@/types";

export function useScan(scanId: string | undefined) {
  return useQuery({
    queryKey: ["scan", scanId],
    queryFn: () => api.get<ScanResponse>(`/v1/scans/${scanId}`),
    enabled: !!scanId,
    staleTime: 30_000,
  });
}

export function useStartScan() {
  return useMutation({
    mutationFn: (body: ScanRequest) =>
      api.post<ScanResponse>("/v1/scan", body),
  });
}
