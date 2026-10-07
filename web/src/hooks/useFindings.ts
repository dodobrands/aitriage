import { useState, useEffect, useCallback, useRef } from 'react';
import type { Finding } from '../types';
import api, { apiErrorMessage } from '../services/api';
import i18n from '../i18n';
import { findingStatus } from '../lib/findingStatus';

type RefreshOptions = { silent?: boolean };

export const useFindings = (productId?: number) => {
  const requestSequence = useRef(0);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchFindings = useCallback(
    async (options?: RefreshOptions) => {
      const request = ++requestSequence.current;
      try {
        if (!options?.silent) setLoading(true);
        const url = productId ? `/findings?product_id=${productId}` : '/findings';
        const { data } = await api.get(url);
        if (request !== requestSequence.current) return;
        const raw: Finding[] = data?.findings || data || [];
        if (data?.ok === false || !Array.isArray(raw))
          throw new Error(data?.error || i18n.t('errors.fetchFindings'));
        // Use the same lifecycle rules as the dashboard counters and filters.
        const normalized = raw.map((f: Finding) => ({
          ...f,
          status: findingStatus(f),
        }));
        setFindings(normalized);
        setError(null);
      } catch (err: unknown) {
        if (request !== requestSequence.current) return;
        setError(apiErrorMessage(err, i18n.t('errors.fetchFindings')));
      } finally {
        if (request === requestSequence.current) setLoading(false);
      }
    },
    [productId],
  );

  useEffect(() => {
    const sequence = requestSequence;
    fetchFindings();
    return () => {
      sequence.current++;
    };
  }, [fetchFindings]);

  return { findings, loading, error, refresh: fetchFindings };
};
