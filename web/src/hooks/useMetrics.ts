import { useState, useEffect, useCallback, useRef } from 'react';
import api, { apiErrorMessage } from '../services/api';
import i18n from '../i18n';

export interface TopFile {
  path: string;
  count: number;
}

export interface StatusBreakdown {
  status: string;
  count: number;
}

export interface StackBreakdown {
  stack: string;
  count: number;
}

export interface DashboardMetrics {
  total_products: number;
  active_engagements: number;
  open_findings: number;
  sla_breached: number;
  severity_counts: Record<string, number>;
  top_risky_products: Array<{ name: string; risk_score: number; trend: string }>;
  recent_engagements: Array<{ name: string; status: string; date: string }>;
  mttr: Record<string, string>;

  // Extended
  total_findings: number;
  resolved_findings: number;
  top_files: TopFile[];
  status_breakdown: StatusBreakdown[];
  stack_breakdown: StackBreakdown[];
  security_score: number;
  security_grade: string;
  total_engagements: number;
  last_successful_scan_at?: string | null;
  last_successful_verification_at?: string | null;
}

type RefreshOptions = { silent?: boolean };

export const useMetrics = (productId?: number) => {
  const requestSequence = useRef(0);
  const [metrics, setMetrics] = useState<DashboardMetrics | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [resultScope, setResultScope] = useState<number | undefined>(undefined);

  const fetchMetrics = useCallback(
    async (options?: RefreshOptions) => {
      const request = ++requestSequence.current;
      if (!options?.silent) setLoading(true);
      try {
        const { data } = await api.get(productId ? `/metrics?product_id=${productId}` : '/metrics');
        if (request !== requestSequence.current) return;
        setResultScope(productId);
        if (data.ok) {
          setMetrics(data.metrics);
          setError(null);
        } else {
          setMetrics(null);
          setError(data.error || i18n.t('errors.fetchMetrics'));
        }
      } catch (err: unknown) {
        if (request !== requestSequence.current) return;
        setResultScope(productId);
        setMetrics(null);
        setError(apiErrorMessage(err, i18n.t('errors.fetchMetrics')));
      } finally {
        if (request === requestSequence.current) setLoading(false);
      }
    },
    [productId],
  );

  useEffect(() => {
    const sequence = requestSequence;
    fetchMetrics();
    return () => {
      sequence.current++;
    };
  }, [fetchMetrics]);

  const matchesScope = resultScope === productId;
  return { metrics: matchesScope ? metrics : null, loading: loading || !matchesScope, error: matchesScope ? error : null, refresh: fetchMetrics };
};
