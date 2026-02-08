import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import type { RulesResponse } from "@/types";

export function useRules() {
  return useQuery({
    queryKey: ["rules"],
    queryFn: () => api.get<RulesResponse>("/v1/rules"),
    staleTime: 5 * 60 * 1000, // rules rarely change
  });
}
