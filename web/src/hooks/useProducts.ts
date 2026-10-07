import { useCallback, useEffect, useRef, useState } from 'react';
import type { Product } from '../types';
import api, { apiErrorMessage } from '../services/api';
import i18n from '../i18n';

export const useProducts = () => {
  const requestSequence = useRef(0);
  const [products, setProducts] = useState<Product[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // A scan can create a product (a path is registered the first time it is
  // scanned), so callers need to be able to refetch instead of waiting for a
  // page reload to notice the new repository.
  const fetchProducts = useCallback(async () => {
    const request = ++requestSequence.current;
    try {
      const { data } = await api.get<Product[]>('/products');
      if (request !== requestSequence.current) return;
      if (!Array.isArray(data)) throw new Error(i18n.t('errors.fetchProducts'));
      setProducts(data);
      setError(null);
    } catch (err: unknown) {
      if (request !== requestSequence.current) return;
      setError(apiErrorMessage(err, i18n.t('errors.fetchProducts')));
    } finally {
      if (request === requestSequence.current) setLoading(false);
    }
  }, []);

  useEffect(() => {
    const sequence = requestSequence;
    const load = async () => {
      await fetchProducts();
    };
    load();
    return () => {
      sequence.current++;
    };
  }, [fetchProducts]);

  const getProduct = async (id: number): Promise<Product | undefined> => {
    const { data } = await api.get<Product>(`/products?id=${id}`);
    return data;
  };

  return { products, loading, error, getProduct, refresh: fetchProducts };
};
