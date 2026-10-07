import { useTranslation } from 'react-i18next';
import type { DashboardQuery, GroupBy, SortBy } from '../../lib/dashboardQuery';

type Props = DashboardQuery & {
  products: { id: number; name: string }[];
  filePaths: string[];
  counts: Record<string, number>;
  count: number;
  allSelected: boolean;
  someSelected: boolean;
  onSelectAll: (checked: boolean) => void;
  onProject: (id: number | null) => void;
  onSeverity: (severity: string | null) => void;
  onStatus: (status: string) => void;
  onSearch: (query: string) => void;
  onGroup: (group: GroupBy) => void;
  onSort: (sort: SortBy) => void;
  onFile: (file: string) => void;
  onCollapse: () => void;
  onClear: () => void;
};

export function DashboardFilters(props: Props) {
  const { t } = useTranslation('pages');
  const {
    productFilter,
    activeFilter,
    statusFilter,
    searchQuery,
    groupBy,
    sortBy,
    activeFilePath,
    expandedIds,
  } = props;
  const product = props.products.find((item) => item.id === productFilter);
  const projectName = product?.name || `Project #${productFilter}`;
  const statusKeys: Record<string, string> = {
    active: 'review.active',
    resolved: 'status_fixed',
    all: 'statusAll',
    open: 'statusOpen',
    confirmed: 'review.confirmed',
    triage: 'statusTriage',
    false_positive: 'statusFalsePositive',
    risk_accepted: 'statusAccepted',
  };
  const optionsCount =
    Number(groupBy !== 'none') + Number(sortBy !== 'severity') + Number(!!activeFilePath);
  const hasFilters =
    productFilter !== null ||
    !!activeFilter ||
    statusFilter !== 'active' ||
    !!searchQuery ||
    !!activeFilePath;
  const chip = (label: string, clearLabel: string, clear: () => void) => (
    <span className="simple-filter-chip" title={label}>
      <span>{label}</span>
      <button type="button" aria-label={clearLabel} onClick={clear}>
        ×
      </button>
    </span>
  );
  return (
    <div className="dashboard-filters">
      <div className="dashboard-filters__primary">
        <input
          type="checkbox"
          aria-label={t('review.selectAll')}
          title={t('review.selectAll')}
          checked={props.allSelected}
          ref={(element) => {
            if (element) element.indeterminate = props.someSelected && !props.allSelected;
          }}
          onChange={(event) => props.onSelectAll(event.target.checked)}
        />
        <select
          data-project-filter
          aria-label={t('review.projectFilter')}
          title={productFilter === null ? t('allProjects') : projectName}
          value={productFilter ?? ''}
          onChange={(event) =>
            props.onProject(event.target.value ? Number(event.target.value) : null)
          }
        >
          <option value="">{t('allProjects')}</option>
          {productFilter !== null && !product && (
            <option value={productFilter}>{projectName}</option>
          )}
          {props.products.map((item) => (
            <option key={item.id} value={item.id}>
              {item.name}
            </option>
          ))}
        </select>
        <select
          aria-label={t('review.statusFilter')}
          value={statusFilter}
          onChange={(event) => props.onStatus(event.target.value)}
        >
          {Object.entries(statusKeys).map(([value, key]) => (
            <option key={value} value={value}>
              {t(key)}
            </option>
          ))}
        </select>
        <div
          className="dashboard-filters__severity"
          role="group"
          aria-label={t('review.severityFilter')}
        >
          {[null, 'critical', 'high', 'medium', 'low'].map((severity) => (
            <button
              key={severity || 'all'}
              type="button"
              aria-pressed={activeFilter === severity}
              onClick={() => props.onSeverity(severity)}
            >
              {severity
                ? t(`severity${severity[0].toUpperCase()}${severity.slice(1)}`)
                : t('filterAll')}
              <span> {props.counts[severity || 'all'] || 0}</span>
            </button>
          ))}
        </div>
        <input
          className="dashboard-filters__search"
          type="search"
          value={searchQuery}
          placeholder={t('searchPlaceholder')}
          aria-label={t('searchPlaceholder')}
          onChange={(event) => props.onSearch(event.target.value)}
        />
      </div>
      <div className="dashboard-filters__secondary">
        <details className="dashboard-list-settings">
          <summary>
            {t('review.listSettings')}
            {optionsCount > 0 && (
              <span className="dashboard-list-settings__count">{optionsCount}</span>
            )}
          </summary>
          <div className="dashboard-list-settings__controls">
            <label>
              {t('review.groupFilter')}
              <select
                value={groupBy}
                onChange={(event) => props.onGroup(event.target.value as GroupBy)}
              >
                {(['none', 'severity', 'title', 'file', 'scanner', 'product'] as const).map(
                  (value) => (
                    <option key={value} value={value}>
                      {t(
                        {
                          none: 'flatList',
                          severity: 'groupSeverity',
                          title: 'groupTitle',
                          file: 'groupFile',
                          scanner: 'groupScanner',
                          product: 'groupProject',
                        }[value],
                      )}
                    </option>
                  ),
                )}
              </select>
            </label>
            <label>
              {t('review.sortFilter')}
              <select
                value={sortBy}
                onChange={(event) => props.onSort(event.target.value as SortBy)}
              >
                {(['severity', 'title', 'file'] as const).map((value) => (
                  <option key={value} value={value}>
                    {t({ severity: 'sortSeverity', title: 'sortTitle', file: 'sortFile' }[value])}
                  </option>
                ))}
              </select>
            </label>
            <label className="dashboard-list-settings__file">
              {t('review.fileFilter')}
              <select
                title={activeFilePath || t('review.allFiles')}
                value={activeFilePath}
                onChange={(event) => props.onFile(event.target.value)}
              >
                <option value="">{t('review.allFiles')}</option>
                {activeFilePath && !props.filePaths.includes(activeFilePath) && (
                  <option value={activeFilePath}>{activeFilePath}</option>
                )}
                {props.filePaths.map((path) => (
                  <option key={path} value={path}>
                    {path}
                  </option>
                ))}
              </select>
            </label>
          </div>
        </details>
        {expandedIds.size > 0 && (
          <button type="button" onClick={props.onCollapse}>
            {t('review.collapseAll')}
          </button>
        )}
        <span className="dashboard-filters__count" role="status">
          {props.count} {t('review.findingCount', { count: props.count })}
        </span>
      </div>
      {hasFilters && (
        <div className="simple-active-filters">
          {productFilter !== null &&
            chip(projectName, t('review.clearProjectFilter'), () => props.onProject(null))}
          {activeFilter &&
            chip(
              t(`severity${activeFilter[0].toUpperCase()}${activeFilter.slice(1)}`),
              t('review.clearSeverityFilter'),
              () => props.onSeverity(null),
            )}
          {statusFilter !== 'active' &&
            chip(t(statusKeys[statusFilter]), t('review.clearStatusFilter'), () =>
              props.onStatus('active'),
            )}
          {searchQuery &&
            chip(`“${searchQuery}”`, t('review.clearSearchFilter'), () => props.onSearch(''))}
          {activeFilePath &&
            chip(activeFilePath, t('review.clearFileFilter'), () => props.onFile(''))}
          <button className="dashboard-filters__clear" type="button" onClick={props.onClear}>
            {t('SimpleDashboardPage.clearAll')}
          </button>
        </div>
      )}
    </div>
  );
}
