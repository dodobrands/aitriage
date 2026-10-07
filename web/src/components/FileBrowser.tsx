import { ModalDialog } from '../ui/ModalDialog';
import React, { useState, useEffect, useRef } from 'react';
import { useTranslation } from 'react-i18next';

interface FileBrowserProps {
  onSelect: (path: string) => void;
  onCancel: () => void;
}

export const FileBrowser: React.FC<FileBrowserProps> = ({ onSelect, onCancel }) => {
  const { t } = useTranslation('components');
  const sequence = useRef(0);
  const [path, setPath] = useState('.');
  const [entries, setEntries] = useState<{ name: string; is_dir: boolean; path: string }[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [hoveredIdx, setHoveredIdx] = useState<number | null>(null);

  const fetchEntries = async (targetPath: string) => {
    const request = ++sequence.current;
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`/api/browser?path=${encodeURIComponent(targetPath)}`);
      const data = await res.json();
      if (request !== sequence.current) return;
      if (res.ok && data.ok) {
        setEntries(
          (data.entries || []).sort(
            (a: { is_dir: boolean; name: string }, b: { is_dir: boolean; name: string }) =>
              (b.is_dir ? 1 : 0) - (a.is_dir ? 1 : 0) || a.name.localeCompare(b.name),
          ),
        );
        setPath(data.path);
      } else {
        setError(data.error || 'Failed to fetch directory content');
      }
    } catch {
      if (request === sequence.current) setError('Connection error');
    } finally {
      if (request === sequence.current) setLoading(false);
    }
  };

  useEffect(() => {
    fetchEntries('.');
  }, []);

  const navigateUp = () => {
    const parts = path.split('/').filter(Boolean);
    if (parts.length > 1) {
      parts.pop();
      fetchEntries('/' + parts.join('/'));
    } else {
      // Already at / — go to root
      fetchEntries('/');
    }
  };

  // Build breadcrumb segments
  const pathSegments =
    path === '/'
      ? [{ name: '/', fullPath: '/' }]
      : (() => {
          const parts = path.split('/').filter(Boolean);
          return [
            { name: '/', fullPath: '/' },
            ...parts.map((part, idx) => ({
              name: part,
              fullPath: '/' + parts.slice(0, idx + 1).join('/'),
            })),
          ];
        })();

  return (
    <ModalDialog label={t('components.fileBrowser.title')} onClose={onCancel} className="file-browser-dialog">
      <div className="w-full max-w-2xl max-h-[80vh] flex flex-col overflow-hidden border border-outline bg-surface-container">
        {/* Header */}
        <div className="px-5 py-4 border-b border-outline-variant/20 bg-surface-variant">
          <div className="flex justify-between items-start mb-3">
            <div className="flex items-center gap-3">
              <div className="w-9 h-9 flex items-center justify-center bg-surface-container-high">
                <span
                  className="material-symbols-outlined text-ai-accent"
                  style={{ fontSize: '20px' }}
                >
                  folder_open
                </span>
              </div>
              <div>
                <div className="text-sm font-semibold text-primary">{t('components.fileBrowser.title')}</div>
                <div className="text-[11px] text-on-surface-variant/40 mt-0.5">
                  {t('components.fileBrowser.subtitle')}
                </div>
              </div>
            </div>
            <button
              onClick={onCancel}
              aria-label={t('components.fileBrowser.cancel')}
              className="w-8 h-8 flex items-center justify-center text-on-surface-variant/40 hover:text-primary hover:bg-surface-container transition-none"
            >
              <span className="material-symbols-outlined" style={{ fontSize: '20px' }}>
                close
              </span>
            </button>
          </div>
          {/* Breadcrumb + Go Up */}
          <div className="flex items-center gap-2">
            <button
              onClick={navigateUp}
              className="w-7 h-7 flex items-center justify-center text-on-surface-variant/50 hover:text-ai-accent hover:bg-ai-accent/10 transition-none shrink-0"
              title={t('components.fileBrowser.goUp')}
            >
              <span className="material-symbols-outlined" style={{ fontSize: '18px' }}>
                arrow_upward
              </span>
            </button>
            <div
              className="flex items-center gap-0.5 overflow-x-auto flex-1 py-1 px-2"
              style={{ background: 'rgba(255,255,255,0.03)' }}
            >
              {pathSegments.map((seg, idx) => (
                <React.Fragment key={seg.fullPath}>
                  {idx > 0 && <span className="text-on-surface-variant/20 text-xs mx-0.5">/</span>}
                  <button
                    onClick={() => fetchEntries(seg.fullPath)}
                    className="text-[12px] px-1.5 py-0.5 hover:bg-ai-accent/10 hover:text-ai-accent transition-none whitespace-nowrap"
                    style={{ color: idx === pathSegments.length - 1 ? 'var(--v2-fg)' : 'var(--v2-muted)' }}
                  >
                    {seg.name}
                  </button>
                </React.Fragment>
              ))}
            </div>
          </div>
        </div>

        {/* File List */}
        <div className="flex-1 overflow-y-auto cyber-scrollbar p-2 min-h-[300px]">
          {loading ? (
            <div className="p-8 flex flex-col items-center gap-3">
              <span
                className="material-symbols-outlined text-ai-accent/40 animate-spin"
                style={{ fontSize: '28px' }}
              >
                progress_activity
              </span>
              <span className="text-sm text-on-surface-variant/40">{t('components.fileBrowser.scanning')}</span>
            </div>
          ) : error ? (
            <div className="p-8 flex flex-col items-center gap-3">
              <span className="material-symbols-outlined text-error" style={{ fontSize: '28px' }}>
                error_outline
              </span>
              <span className="text-sm text-error/80">{error}</span>
              <button
                onClick={() => fetchEntries(path)}
                className="text-xs text-ai-accent hover:underline mt-1"
              >
                {t('components.fileBrowser.retry')}
              </button>
            </div>
          ) : entries.length === 0 ? (
            <div className="p-8 flex flex-col items-center gap-2">
              <span
                className="material-symbols-outlined text-on-surface-variant/30"
                style={{ fontSize: '28px' }}
              >
                folder_off
              </span>
              <span className="text-sm text-on-surface-variant/40">{t('components.fileBrowser.emptyDirectory')}</span>
            </div>
          ) : (
            <div className="flex flex-col gap-0.5">
              {entries.map((e, idx) => (
                <button
                  key={e.path}
                  onClick={() => (e.is_dir ? fetchEntries(e.path) : onSelect(e.path))}
                  onMouseEnter={() => setHoveredIdx(idx)}
                  onMouseLeave={() => setHoveredIdx(null)}
                  className="flex items-center justify-between px-4 py-2.5 text-left transition-none group"
                  style={{
                    background:
                      hoveredIdx === idx
                        ? e.is_dir
                          ? 'var(--accent-color-soft)'
                          : 'rgba(255, 255, 255, 0.03)'
                        : 'transparent',
                  }}
                >
                  <div className="flex items-center gap-3">
                    <span
                      className="material-symbols-outlined transition-none"
                      style={{
                        fontSize: '20px',
                        color:
                          hoveredIdx === idx
                            ? e.is_dir
                              ? 'var(--accent-color-hover)'
                              : 'var(--v2-fg-2)'
                            : e.is_dir
                              ? 'var(--accent-color)'
                              : 'var(--v2-muted)',
                        fontVariationSettings:
                          e.is_dir && hoveredIdx === idx ? "'FILL' 1" : "'FILL' 0",
                      }}
                    >
                      {e.is_dir ? 'folder' : 'description'}
                    </span>
                    <span
                      className={`text-sm transition-none ${hoveredIdx === idx ? 'text-primary' : 'text-on-surface/80'}`}
                    >
                      {e.name}
                    </span>
                    {e.name.startsWith('.') && (
                      <span className="text-[10px] px-1.5 py-0.5 bg-surface-container text-on-surface-variant/40">
                        {t('components.fileBrowser.hidden')}
                      </span>
                    )}
                  </div>
                  {e.is_dir && hoveredIdx === idx && (
                    <div className="flex items-center gap-2">
                      <button
                        onClick={(ev) => {
                          ev.stopPropagation();
                          onSelect(e.path);
                        }}
                        className="px-3 py-1 text-[11px] font-medium bg-ai-accent text-white hover:bg-ai-accent/80 transition-none"
                      >
                        {t('components.fileBrowser.scan')}
                      </button>
                      <span
                        className="material-symbols-outlined text-on-surface-variant/30"
                        style={{ fontSize: '16px' }}
                      >
                        chevron_right
                      </span>
                    </div>
                  )}
                </button>
              ))}
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-5 py-3 border-t border-outline-variant/20 flex items-center justify-between bg-surface-container-lowest">
          <div className="flex items-center gap-2 text-[11px] text-on-surface-variant/40">
            <span className="material-symbols-outlined" style={{ fontSize: '14px' }}>
              info
            </span>
            {t('components.fileBrowser.footerHint')}
          </div>
          <div className="flex gap-2">
            <button
              onClick={onCancel}
              className="px-4 py-2 text-sm text-on-surface-variant hover:text-primary hover:bg-surface-container border border-outline-variant/20 transition-none"
            >
              {t('components.fileBrowser.cancel')}
            </button>
            <button
              onClick={() => onSelect(path)}
              className="px-5 py-2 text-sm font-medium bg-primary text-on-primary transition-none hover:brightness-110"
              disabled={loading || Boolean(error)}
            >
              {t('components.fileBrowser.scanCurrent')}
            </button>
          </div>
        </div>
      </div>
    </ModalDialog>
  );
};
