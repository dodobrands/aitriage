export type GroupBy = 'none' | 'severity' | 'title' | 'file' | 'scanner' | 'product';
export type SortBy = 'severity' | 'title' | 'file';
export type DashboardQuery = {
  productFilter: number | null;
  activeFilter: string | null;
  statusFilter: string;
  searchQuery: string;
  groupBy: GroupBy;
  sortBy: SortBy;
  requestedPage: number;
  activeFilePath: string;
  expandedIds: Set<number>;
};

const positiveInteger = (value: string | null) => {
  if (!value || !/^\d+$/.test(value)) return null;
  const number = Number(value);
  return Number.isSafeInteger(number) && number > 0 ? number : null;
};
const statuses = [
  'active',
  'all',
  'open',
  'confirmed',
  'triage',
  'resolved',
  'false_positive',
  'risk_accepted',
];
const groups: GroupBy[] = ['none', 'severity', 'title', 'file', 'scanner', 'product'];
const sorts: SortBy[] = ['severity', 'title', 'file'];

export function readDashboardQuery(params: URLSearchParams): DashboardQuery {
  const severity = params.get('severity')?.toLowerCase() || '';
  const status = params.get('status') || 'active';
  const group = params.get('group') as GroupBy;
  const sort = params.get('sort') as SortBy;
  const file = params.get('file') || '';
  return {
    productFilter: positiveInteger(params.get('project')),
    activeFilter: ['critical', 'high', 'medium', 'low'].includes(severity) ? severity : null,
    statusFilter: statuses.includes(status) ? status : 'active',
    searchQuery: (params.get('q') || '').slice(0, 500),
    groupBy: groups.includes(group) ? group : 'none',
    sortBy: sorts.includes(sort) ? sort : 'severity',
    requestedPage: Math.min(positiveInteger(params.get('page')) || 1, 1_000_000) - 1,
    activeFilePath: file.length <= 4096 ? file : '',
    expandedIds: new Set(
      (params.get('finding') || '')
        .split(',')
        .slice(0, 100)
        .map(positiveInteger)
        .filter((id): id is number => id !== null),
    ),
  };
}

type QueryPatch = Partial<DashboardQuery> | ((current: DashboardQuery) => Partial<DashboardQuery>);

// Each interaction makes one atomic URL update; tab and unrelated parameters survive.
export function updateDashboardQuery(previous: URLSearchParams, patch: QueryPatch) {
  const current = readDashboardQuery(previous);
  const next = { ...current, ...(typeof patch === 'function' ? patch(current) : patch) };
  const params = new URLSearchParams(previous);
  const write = (key: string, value: string | null) =>
    value ? params.set(key, value) : params.delete(key);
  write('project', next.productFilter === null ? null : String(next.productFilter));
  write('severity', next.activeFilter);
  write('status', next.statusFilter === 'active' ? null : next.statusFilter);
  write('q', next.searchQuery);
  write('group', next.groupBy === 'none' ? null : next.groupBy);
  write('sort', next.sortBy === 'severity' ? null : next.sortBy);
  write('page', next.requestedPage === 0 ? null : String(next.requestedPage + 1));
  write('file', next.activeFilePath);
  write('finding', [...next.expandedIds].join(','));
  return params;
}
