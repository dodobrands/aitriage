export type SourceLine = { number: number | null; text: string; highlight: boolean };

// Legacy responses used numbered prompt text; plain stored snippets have no
// trustworthy start line, so they are displayed without invented file numbers.
export function parseSourceExcerpt(source: string): SourceLine[] {
  const body = source.replace(/^File: [^\n]*\n```[^\n]*\n/, '').replace(/\n```\s*$/, '');
  const lines = body.split('\n');
  const annotated = lines.every((line) => /^(?:>> |\s*)\d+: /.test(line));
  return lines.map((line) => {
    if (!annotated) return { number: null, text: line, highlight: false };
    const match = /^(>> |\s*)(\d+): (.*)$/.exec(line)!;
    return { number: Number(match[2]), text: match[3], highlight: match[1] === '>> ' };
  });
}

export function readSourceLines(value: unknown): SourceLine[] | null {
  if (!Array.isArray(value) || value.length === 0) return null;
  if (
    !value.every(
      (line) =>
        line &&
        Number.isSafeInteger(line.number) &&
        line.number > 0 &&
        typeof line.text === 'string' &&
        typeof line.highlight === 'boolean',
    )
  )
    return null;
  return value.map((line) => ({
    number: line.number as number,
    text: line.text as string,
    highlight: line.highlight as boolean,
  }));
}
