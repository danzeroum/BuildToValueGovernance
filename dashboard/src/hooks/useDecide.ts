import { useMutation } from '@tanstack/react-query';
import { gateway, governance } from '../api/client';

export function useValidate() {
  return useMutation({
    mutationFn: async (params: { input: string; session_id?: string }) => {
      const { data } = await gateway.post('/v1/validate', params);
      return data;
    },
  });
}

export function useDecide() {
  return useMutation({
    mutationFn: async (params: { input: string; session_id?: string; profile?: string }) => {
      const { data } = await gateway.post('/v1/decide', {
        input_text: params.input,
        session_id: params.session_id,
        profile: params.profile,
      });
      return data;
    },
  });
}

export function useSanitize() {
  return useMutation({
    mutationFn: async (params: { text: string }) => {
      const { data } = await gateway.post('/v1/sanitize', params);
      return data;
    },
  });
}

export function useTrustScore() {
  return useMutation({
    mutationFn: async (sessionId: string) => {
      const { data } = await governance.get(`/v1/trust/${sessionId}`);
      return data;
    },
  });
}

export function useComplianceReport() {
  return useMutation({
    mutationFn: async (framework: string) => {
      const { data } = await governance.get(`/v1/compliance/report/${framework}`);
      return data;
    },
  });
}

export function useIntelligenceQuery() {
  return useMutation({
    mutationFn: async (params: { threat_type?: string; min_severity?: number }) => {
      const { data } = await governance.post('/v1/intelligence/query', params);
      return data;
    },
  });
}

export function useIntelligenceIngest() {
  return useMutation({
    mutationFn: async (threat: Record<string, unknown>) => {
      const { data } = await governance.post('/v1/intelligence/ingest', threat);
      return data;
    },
  });
}

export function useIntelligenceStats() {
  return useMutation({
    mutationFn: async () => {
      const { data } = await governance.get('/v1/intelligence/stats');
      return data;
    },
  });
}

export function useLedgerQuery() {
  return useMutation({
    mutationFn: async (params: Record<string, unknown>) => {
      const { data } = await governance.get('/v1/ledger/query', { params });
      return data;
    },
  });
}

export function useLedgerStats() {
  return useMutation({
    mutationFn: async () => {
      const { data } = await governance.get('/v1/ledger/stats');
      return data;
    },
  });
}

export function useSubmitAppeal() {
  return useMutation({
    mutationFn: async (params: { audit_trail_id: number; user_id: string; reason: string; evidence?: string }) => {
      const { data } = await governance.post('/v1/appeals', params);
      return data;
    },
  });
}

export function useListAppeals() {
  return useMutation({
    mutationFn: async (params?: { status?: string }) => {
      const { data } = await governance.get('/v1/appeals', { params });
      return data;
    },
  });
}

export function useAppealsMetrics() {
  return useMutation({
    mutationFn: async () => {
      const { data } = await governance.get('/v1/appeals/metrics');
      return data;
    },
  });
}

export function useWebhooksStatus() {
  return useMutation({
    mutationFn: async () => {
      const { data } = await governance.get('/v1/webhooks/status');
      return data;
    },
  });
}

export function useGenerateFria() {
  return useMutation({
    mutationFn: async (params: { agent_id: string; sector: string; capabilities: string[]; deployment_context: Record<string, boolean> }) => {
      const { data } = await governance.post('/v1/compliance/fria/generate', params);
      return data;
    },
  });
}

export function useHealthChecks() {
  return useMutation({
    mutationFn: async () => {
      const [gw, gov] = await Promise.all([
        gateway.get('/health').then(r => r.data).catch(() => ({ status: 'unreachable' })),
        governance.get('/health').then(r => r.data).catch(() => ({ status: 'unreachable' })),
      ]);
      const metricsText = await gateway.get('/metrics').then(r => r.data).catch(() => '');
      return { gateway: gw, governance: gov, metricsText };
    },
  });
}
