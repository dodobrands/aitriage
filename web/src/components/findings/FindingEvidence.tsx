import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { parseSourceExcerpt, readSourceLines, type SourceLine } from '../../lib/sourceExcerpt';

type EvidenceFinding = {
  id: number;
  code_snippet?: string;
  file_path?: string;
  file?: string;
  line_number?: number;
};
type EvidenceResult = { key: string; attempt: number; lines: SourceLine[]; error: boolean };
type CopyResult = { key: string; item: 'code' | 'path'; failed: boolean };

export function FindingEvidence({ finding }: { finding: EvidenceFinding }) {
  const { t } = useTranslation('pages');
  const [attempt, setAttempt] = useState(0);
  const [result, setResult] = useState<EvidenceResult | null>(null);
  const [copyResult, setCopyResult] = useState<CopyResult | null>(null);
  const path = finding.file_path || finding.file;
  const key = `${finding.id}:${path || ''}:${finding.line_number || ''}`;
  const current = result?.key === key && result.attempt === attempt ? result : null;
  const loading = !current;
  useEffect(() => {
    const controller = new AbortController();
    fetch(`/api/findings/${finding.id}/source`, { signal: controller.signal })
      .then(async (response) => {
        if (!response.ok) throw new Error('Source request failed');
        const data = await response.json();
        if (!data.ok) throw new Error('Source unavailable');
        return data;
      })
      .then((data) => {
        if (!controller.signal.aborted)
          setResult({
            key,
            attempt,
            lines: data.source_available
              ? readSourceLines(data.lines) ||
                parseSourceExcerpt(typeof data.source === 'string' ? data.source : '')
              : [],
            error: false,
          });
      })
      .catch(() => {
        if (!controller.signal.aborted) setResult({ key, attempt, lines: [], error: true });
      });
    return () => controller.abort();
  }, [finding.id, key, attempt]);
  useEffect(() => {
    if (!copyResult) return;
    const timeout = window.setTimeout(() => setCopyResult(null), 3000);
    return () => window.clearTimeout(timeout);
  }, [copyResult]);
  const lines = current?.lines.length
    ? current.lines
    : finding.code_snippet
      ? parseSourceExcerpt(finding.code_snippet)
      : [];
  const code = lines.map((line) => line.text).join('\n');
  const location = path
    ? `${path}${finding.line_number && finding.line_number > 0 ? `:${finding.line_number}` : ''}`
    : '';
  const copy = async (item: 'code' | 'path', value: string) => {
    try {
      await navigator.clipboard.writeText(value);
      setCopyResult({ key, item, failed: false });
    } catch {
      setCopyResult({ key, item, failed: true });
    }
  };
  const copied = copyResult?.key === key && !copyResult.failed ? copyResult.item : null;
  return (
    <section className="finding-evidence" aria-label={t('review.evidence')} aria-busy={loading}>
      <div className="finding-evidence__header">
        <h4>{t('review.evidence')}</h4>
        <div className="finding-evidence__actions">
          {location && (
            <button type="button" onClick={() => void copy('path', location)}>
              {copied === 'path' ? t('review.copied') : t('review.copyLocation')}
            </button>
          )}
          {code && (
            <button type="button" onClick={() => void copy('code', code)}>
              {copied === 'code' ? t('review.copied') : t('review.copyCode')}
            </button>
          )}
        </div>
      </div>
      {location && <p className="finding-evidence__path">{location}</p>}
      {lines.length > 0 && (
        <pre tabIndex={0} aria-label={t('review.evidence')}>
          <code>
            {lines.map((line, index) => (
              <span
                key={index}
                className={`finding-evidence__line${line.highlight ? ' finding-evidence__line--target' : ''}`}
                data-source-target={line.highlight || undefined}
              >
                <span className="finding-evidence__line-number" aria-hidden="true">
                  {line.number ?? ''}
                </span>
                <span>{line.text || ' '}</span>
                {'\n'}
              </span>
            ))}
          </code>
        </pre>
      )}
      {!current?.lines.length && finding.code_snippet && (
        <p className="finding-evidence__note">{t('review.storedSnippet')}</p>
      )}
      {current?.error ? (
        <div role="alert">
          <p>{t('review.sourceError')}</p>
          <button type="button" onClick={() => setAttempt((value) => value + 1)}>
            {t('review.retry')}
          </button>
        </div>
      ) : (
        !lines.length && (
          <p role="status">{loading ? t('review.loadingSource') : t('review.sourceMissing')}</p>
        )
      )}
      {copyResult?.key === key && (
        <p role={copyResult.failed ? 'alert' : 'status'} className="finding-evidence__copy-status">
          {copyResult.failed ? t('review.copyFailed') : t('review.copied')}
        </p>
      )}
    </section>
  );
}
