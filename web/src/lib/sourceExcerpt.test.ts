import { describe, expect, it } from 'vitest';
import { parseSourceExcerpt, readSourceLines } from './sourceExcerpt';
import { formatResultTime } from './resultTime';

describe('source evidence', () => {
  it('copies code without prompt fences or line annotations', () => {
    const lines = parseSourceExcerpt(
      'File: apps/a.go\n```text\n   8: const safe = true;\n>> 9: dangerous();\n```',
    );
    expect(lines).toEqual([
      { number: 8, text: 'const safe = true;', highlight: false },
      { number: 9, text: 'dangerous();', highlight: true },
    ]);
    expect(lines.map((line) => line.text).join('\n')).toBe('const safe = true;\ndangerous();');
  });
  it('does not invent file line numbers for stored or partially annotated snippets', () => {
    expect(parseSourceExcerpt('const secret = "[REDACTED]";')[0]).toEqual({
      number: null,
      text: 'const secret = "[REDACTED]";',
      highlight: false,
    });
    expect(
      parseSourceExcerpt('>> 9: foo\nbar').every((line) => line.number === null && !line.highlight),
    ).toBe(true);
  });
  it('rejects malformed structured source without rendering object contents', () => {
    expect(readSourceLines([{ number: -1, text: {}, highlight: true }])).toBeNull();
    expect(
      readSourceLines([{ number: 4, text: '<script>alert(1)</script>', highlight: true }]),
    ).toEqual([{ number: 4, text: '<script>alert(1)</script>', highlight: true }]);
  });
});

describe('result timestamps', () => {
  it('shows absent or invalid times as unavailable and normalizes legacy UTC dates', () => {
    expect(formatResultTime(undefined, 'en')).toBeNull();
    expect(formatResultTime('bad date', 'en')).toBeNull();
    expect(formatResultTime('2026-10-07 12:00:00', 'en')).toBe(
      formatResultTime('2026-10-07T12:00:00Z', 'en'),
    );
  });
});
