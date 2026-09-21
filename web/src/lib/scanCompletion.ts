/**
 * What has to be refetched when a scan finishes.
 *
 * A scan can create a product: a path is registered the first time it is
 * scanned. The dashboard used to refresh only findings and metrics, so the
 * freshly scanned repository existed in the database but appeared nowhere in the
 * interface — it showed up only after the whole Web UI was restarted. Several
 * call sites papered over this with `window.location.reload()`, which threw away
 * the scan results the user was reading.
 *
 * Keeping the set in one place means a new data source cannot be added to the
 * dashboard and silently forgotten here.
 */

export type Refresher = (() => void) | undefined | null;

export interface ScanCompletionRefreshers {
  /** Findings produced by the scan. */
  findings?: Refresher;
  /** Aggregate metrics shown on the dashboard. */
  metrics?: Refresher;
  /** Products — a scan can register a repository that did not exist before. */
  products?: Refresher;
  /** Generated report artifacts and their history. */
  reports?: Refresher;
}

/** The data sources a finished scan invalidates, in a stable order. */
export const SCAN_COMPLETION_SOURCES = ['findings', 'metrics', 'products', 'reports'] as const;

/**
 * Invokes every available refresher. Missing ones are skipped rather than
 * throwing: not every screen owns every data source, and a scan must never fail
 * because one panel is absent.
 */
export const runScanCompletionRefreshers = (refreshers: ScanCompletionRefreshers): string[] => {
  const invoked: string[] = [];
  for (const source of SCAN_COMPLETION_SOURCES) {
    const refresh = refreshers[source];
    if (typeof refresh === 'function') {
      refresh();
      invoked.push(source);
    }
  }
  return invoked;
};
