import { describe, expect, it } from 'vitest';
import { readDashboardQuery, updateDashboardQuery } from './dashboardQuery';

describe('dashboard URL context', () => {
  it('restores every review control, Unicode paths and multiple open findings', () => {
    const params = new URLSearchParams(
      'project=2&severity=HIGH&status=all&q=missing+lock&group=file&sort=title&page=3&file=apps/касса/package.json&finding=9,4,9',
    );
    const state = readDashboardQuery(params);
    expect(state).toMatchObject({
      productFilter: 2,
      activeFilter: 'high',
      statusFilter: 'all',
      searchQuery: 'missing lock',
      groupBy: 'file',
      sortBy: 'title',
      requestedPage: 2,
      activeFilePath: 'apps/касса/package.json',
    });
    expect([...state.expandedIds]).toEqual([9, 4]);
    expect(readDashboardQuery(updateDashboardQuery(params, {}))).toEqual(state);
  });
  it('clears filters atomically without losing tab, list preferences or open findings', () => {
    const previous = new URLSearchParams(
      'project=7&severity=high&status=all&q=test&file=a/package.json&page=3&tab=reports&custom=keep&finding=9&group=file',
    );
    const next = updateDashboardQuery(previous, {
      productFilter: null,
      activeFilter: null,
      statusFilter: 'active',
      searchQuery: '',
      activeFilePath: '',
      requestedPage: 0,
    });
    expect(next.toString()).toBe('tab=reports&custom=keep&finding=9&group=file');
    expect(previous.get('project')).toBe('7');
  });
  it('ignores malformed parameters and bounds oversized inputs', () => {
    const state = readDashboardQuery(
      new URLSearchParams(
        'project=1e3&severity=urgent&status=nope&group=bad&sort=bad&page=-5&finding=-1,NaN,2.5,9007199254740992,3&q=' +
          'x'.repeat(1000),
      ),
    );
    expect(state).toMatchObject({
      productFilter: null,
      activeFilter: null,
      statusFilter: 'active',
      groupBy: 'none',
      sortBy: 'severity',
      requestedPage: 0,
    });
    expect([...state.expandedIds]).toEqual([3]);
    expect(state.searchQuery).toHaveLength(500);
  });
  it('toggles findings against the current URL without mutating the old state', () => {
    const previous = new URLSearchParams('finding=1,2&project=3');
    const next = updateDashboardQuery(previous, (current) => {
      const ids = new Set(current.expandedIds);
      ids.delete(1);
      ids.add(4);
      return { expandedIds: ids };
    });
    expect(next.get('finding')).toBe('2,4');
    expect(previous.get('finding')).toBe('1,2');
  });
});
