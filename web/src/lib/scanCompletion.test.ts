import { describe, it, expect, vi } from 'vitest';
import { runScanCompletionRefreshers, SCAN_COMPLETION_SOURCES } from './scanCompletion';

// A pilot user reported: "Уже завершенную проверку не сохраняет как отчет,
// только после перезапуска всей Web UI." The scan had in fact been saved — the
// product it created was never refetched, so it appeared nowhere until a reload.

describe('runScanCompletionRefreshers', () => {
  it('refreshes products, which is what made a new repository invisible', () => {
    const products = vi.fn();

    runScanCompletionRefreshers({ findings: vi.fn(), metrics: vi.fn(), products });

    expect(products).toHaveBeenCalledOnce();
  });

  it('refreshes every data source a scan invalidates', () => {
    const calls = {
      findings: vi.fn(),
      metrics: vi.fn(),
      products: vi.fn(),
      reports: vi.fn(),
    };

    const invoked = runScanCompletionRefreshers(calls);

    expect(invoked).toEqual([...SCAN_COMPLETION_SOURCES]);
    for (const refresh of Object.values(calls)) {
      expect(refresh).toHaveBeenCalledOnce();
    }
  });

  it('skips sources a screen does not own instead of throwing', () => {
    const findings = vi.fn();

    expect(() =>
      runScanCompletionRefreshers({ findings, metrics: undefined, products: null }),
    ).not.toThrow();
    expect(findings).toHaveBeenCalledOnce();
  });

  it('does nothing, quietly, when a screen owns no data sources', () => {
    expect(runScanCompletionRefreshers({})).toEqual([]);
  });

  it('names products as a source, so it cannot be dropped again', () => {
    // This is the regression itself: the original handler refreshed findings and
    // metrics only. Keeping the list asserted means removing products fails here.
    expect(SCAN_COMPLETION_SOURCES).toContain('products');
  });
});
