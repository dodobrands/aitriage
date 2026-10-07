import { useCallback, useMemo, type SetStateAction } from 'react';
import { useSearchParams } from 'react-router-dom';
import {
  readDashboardQuery,
  updateDashboardQuery,
  type DashboardQuery,
  type GroupBy,
  type SortBy,
} from '../lib/dashboardQuery';

export function useDashboardQuery() {
  const [params, setParams] = useSearchParams();
  const query = useMemo(() => readDashboardQuery(params), [params]);
  const update = useCallback(
    (patch: Parameters<typeof updateDashboardQuery>[1], replace = false) => {
      setParams((previous) => updateDashboardQuery(previous, patch), { replace });
    },
    [setParams],
  );
  const filter = (patch: Partial<DashboardQuery>, replace = false) =>
    update({ ...patch, requestedPage: 0 }, replace);
  return {
    ...query,
    scopeType: query.activeFilePath ? ('activeFile' as const) : ('all' as const),
    update,
    setProductFilter: (productFilter: number | null) =>
      filter({ productFilter, activeFilePath: '' }),
    setActiveFilter: (activeFilter: string | null) => filter({ activeFilter }),
    setStatusFilter: (statusFilter: string) => filter({ statusFilter }),
    setSearchQuery: (searchQuery: string) => filter({ searchQuery }, true),
    setGroupBy: (groupBy: GroupBy) => filter({ groupBy }),
    setSortBy: (sortBy: SortBy) => filter({ sortBy }),
    setActiveFilePath: (activeFilePath: string) => filter({ activeFilePath }),
    setPage: (requestedPage: number) => update({ requestedPage }),
    setExpandedIds: (value: SetStateAction<Set<number>>) =>
      update((current) => ({
        expandedIds: typeof value === 'function' ? value(current.expandedIds) : value,
      })),
    clearFilters: () =>
      filter({
        productFilter: null,
        activeFilter: null,
        statusFilter: 'active',
        searchQuery: '',
        activeFilePath: '',
      }),
    showHistory: () => filter({ activeFilter: null, statusFilter: 'all', searchQuery: '' }),
  };
}
