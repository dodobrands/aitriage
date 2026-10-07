import { useDashboardQuery } from '../hooks/useDashboardQuery';
import { DashboardFilters } from '../components/findings/DashboardFilters';
import { formatResultTime } from '../lib/resultTime';
import { ModalDialog } from '../ui/ModalDialog';
import { isActive, isResolved, isSuppressed, terminalStatuses } from '../lib/findingStatus';
import { FindingEvidence } from '../components/findings/FindingEvidence';
import React, { useState, useMemo, useEffect, useCallback, useRef } from 'react';
import { motion, AnimatePresence, useReducedMotion } from 'framer-motion';
import Markdown from 'react-markdown';
import { useTranslation } from 'react-i18next';
import { useFindings } from '../hooks/useFindings';
import { useMetrics } from '../hooks/useMetrics';
import { useProducts } from '../hooks/useProducts';
import { securityService } from '../services/securityService';
import type { Finding, Product } from '../types';
import { AgentHandoffPanel } from '../components/securecoder/AgentHandoffPanel';
import { downloadRunwayArtifact } from '../services/runwayArtifacts';
import { decideRestore } from '../lib/runwayRestore';
import { runScanCompletionRefreshers } from '../lib/scanCompletion';
import './SimpleDashboardPage.css';

interface SimpleDashboardPageProps {
  onNavigateToChat?: (findingOrPrompt?: Finding | string) => void;
  onNavigateToReports?: (sessionId?: number) => void;
}

/* ── Path Input with Browse ── */
type BrowserEntry = { name: string; is_dir: boolean; path: string };




const displayPath = (p: string) => p.replace(/^\/host/, '~');

const PathInput: React.FC<{ value: string; onChange: (p: string) => void }> = ({ value, onChange }) => {
  const { t } = useTranslation('pages');
  const [browsing, setBrowsing] = useState(false);
  const [entries, setEntries] = useState<BrowserEntry[]>([]);
  const [browsePath, setBrowsePath] = useState('/host');
  const [loading, setLoading] = useState(false);

  const browse = async (path: string) => {
    setLoading(true);
    try {
      const res = await fetch(`/api/browser?path=${encodeURIComponent(path)}`);
      const data = await res.json();
      if (data.ok) {
        setEntries(data.entries?.filter((e: BrowserEntry) => e.is_dir) || []);
        setBrowsePath(data.path || path);
      }
    } catch { /* ignore */ }
    setLoading(false);
  };

  const openBrowser = () => {
    setBrowsing(true);
    browse(value && value !== '/project' ? value : '/host');
  };

  const goUp = () => {
    if (browsePath === '/host' || browsePath === '/') return;
    const parts = browsePath.split('/');
    parts.pop();
    const parent = parts.join('/') || '/';
    browse(parent);
  };

  const selectEntry = (entry: BrowserEntry) => browse(entry.path);

  const confirmBrowse = () => {
    onChange(browsePath);
    setBrowsing(false);
  };

  // Breadcrumb segments
  const breadcrumbs = useMemo(() => {
    const parts = browsePath.split('/').filter(Boolean);
    const result: { label: string; path: string }[] = [];
    let acc = '';
    parts.forEach((p, i) => {
      acc += '/' + p;
      result.push({ label: i === 0 && p === 'host' ? '~' : p, path: acc });
    });
    return result;
  }, [browsePath]);

  return (
    <div className="space-y-2">
      {/* Text input */}
      <div className="flex gap-1.5">
        <div className="relative flex-1">
          <span className="material-symbols-outlined text-[14px] text-[#3f3f46] absolute left-2.5 top-1/2 -translate-y-1/2">folder</span>
          <input
            value={value}
            onChange={e => onChange(e.target.value)}
            aria-label={t('review.scanPath')} placeholder="/host/Desktop/my-project"
            className="w-full bg-surface-bright border border-[rgba(255,255,255,0.06)] rounded-lg pl-8 pr-3 py-2 text-[12px] text-[#f4f4f5] font-mono placeholder:text-[#3f3f46] outline-none focus:border-[rgba(255,255,255,0.12)] transition-colors"
          />
        </div>
        <button
          onClick={openBrowser}
          className="shrink-0 w-8 h-8 flex items-center justify-center rounded-lg border border-[rgba(255,255,255,0.06)] text-[#52525b] hover:text-[#a1a1aa] hover:bg-[rgba(255,255,255,0.03)] transition-colors"
          title={t('review.browse')} aria-label={t('review.browse')}
        >
          <span className="material-symbols-outlined text-[16px]">folder_open</span>
        </button>
      </div>

      {/* Browse panel */}
      {browsing && (
        <div className="border border-[rgba(255,255,255,0.08)] rounded-lg overflow-hidden">
          {/* Header */}
          <div className="flex items-center gap-2 px-3 py-2 border-b border-[rgba(255,255,255,0.06)] bg-[rgba(255,255,255,0.02)]">
            <span className="material-symbols-outlined text-[13px] text-[#3f3f46]">folder_special</span>
            <span className="text-[11px] text-[#52525b]">{t('SimpleDashboardPage.scanRoot', 'SCAN_ROOT')}</span>
            <div className="flex-1" />
            <button onClick={() => browse('/host')} className="text-[10px] text-[#52525b] hover:text-[#a1a1aa] transition-colors">{t('SimpleDashboardPage.root')}</button>
          </div>

          {/* Breadcrumb path */}
          <div className="flex items-center gap-0.5 px-3 py-1.5 border-b border-[rgba(255,255,255,0.04)] overflow-x-auto" style={{ scrollbarWidth: 'none' }}>
            <button onClick={() => browse('/host')} className="text-[11px] text-[#52525b] hover:text-[#a1a1aa] shrink-0">~</button>
            {breadcrumbs.slice(1).map((b, i) => (
              <React.Fragment key={b.path}>
                <span className="text-[10px] text-[#3f3f46] mx-0.5">/</span>
                <button onClick={() => browse(b.path)}
                  className={`text-[11px] shrink-0 transition-colors ${i === breadcrumbs.length - 2 ? 'text-[#a1a1aa]' : 'text-[#52525b] hover:text-[#a1a1aa]'}`}>
                  {b.label}
                </button>
              </React.Fragment>
            ))}
          </div>

          {/* Entries */}
          <div className="max-h-[200px] overflow-y-auto" style={{ scrollbarWidth: 'thin', scrollbarColor: 'rgba(255,255,255,0.06) transparent' }}>
            {/* Go up */}
            {browsePath !== '/host' && browsePath !== '/' && (
              <button onClick={goUp}
                className="w-full flex items-center gap-2 px-3 py-1.5 text-left hover:bg-[rgba(255,255,255,0.03)] transition-colors border-b border-[rgba(255,255,255,0.03)]">
                <span className="material-symbols-outlined text-[13px] text-[#3f3f46]">arrow_upward</span>
                <span className="text-[11px] text-[#52525b]">..</span>
              </button>
            )}
            {loading ? (
              <div className="flex items-center justify-center py-4">
                <div className="w-3 h-3 border border-surface-container-highest border-t-[#52525b] rounded-full animate-spin" />
              </div>
            ) : entries.length === 0 ? (
              <div className="py-4 text-center text-[11px] text-[#3f3f46]">{t('SimpleDashboardPage.emptyDirectory')}</div>
            ) : (
              entries.map(e => (
                <button
                  key={e.path}
                  onClick={() => selectEntry(e)}
                  className="w-full flex items-center gap-2 px-3 py-1.5 text-left hover:bg-[rgba(255,255,255,0.03)] transition-colors"
                >
                  <span className="material-symbols-outlined text-[13px] text-[#52525b]">folder</span>
                  <span className="text-[12px] text-[#a1a1aa] truncate">{e.name}</span>
                </button>
              ))
            )}
          </div>

          {/* Actions */}
          <div className="flex items-center gap-2 px-3 py-2 border-t border-[rgba(255,255,255,0.06)] bg-[rgba(255,255,255,0.01)]">
            <span className="text-[10px] text-[#3f3f46] font-mono truncate flex-1">{displayPath(browsePath)}</span>
            <button onClick={() => setBrowsing(false)} className="text-[11px] text-[#52525b] hover:text-[#a1a1aa] px-2 py-1">{t('SimpleDashboardPage.cancel')}</button>
            <button onClick={confirmBrowse} className="text-[11px] text-[#f4f4f5] bg-surface-container-high hover:bg-surface-container-highest border border-outline hover:border-[var(--accent-color-line)] px-3 py-1 rounded transition-colors">
              {t('review.select')}
            </button>
          </div>
        </div>
      )}
    </div>
  );
};

/** Status of the accepted baseline, as reported by GET /api/baseline. */
interface BaselineStatus {
  exists: boolean;
  path: string;
  total: number;
  by_severity?: Record<string, number>;
  created_at?: string;
  updated_at?: string;
}

/* ── Scan Panel (right column) ── */
type ScanStatus = { state: 'idle' | 'scanning' | 'done' | 'error'; findings?: number; duration?: string; coverage?: string; error?: string };

interface ScanPanelProps {
  onScanComplete?: () => void;
}

const ScanPanel: React.FC<ScanPanelProps> = ({ onScanComplete }) => {
  const { t } = useTranslation('pages');
  const [external, setExternal] = useState(true);
  const [scanPath, setScanPath] = useState('.');
  const [projects, setProjects] = useState<BrowserEntry[]>([]);
  const [loadingProjects, setLoadingProjects] = useState(true);
  const [showCustomPath, setShowCustomPath] = useState(false);
  const [showScanners, setShowScanners] = useState(false);
  const [scanStatuses, setScanStatuses] = useState<Record<string, ScanStatus>>({});
  const [activeScans, setActiveScans] = useState(0); // for Scan All progress
  const [totalScans, setTotalScans] = useState(0);
  const [elapsed, setElapsed] = useState(0);
  const [scanningProject, setScanningProject] = useState<string | null>(null);
  const [toolStatus, setToolStatus] = useState<Record<string, boolean>>({});

  const [currentPath, setCurrentPath] = useState('.');
  // Which project the primary action will scan. Clicking a row used to only
  // highlight it while the button still scanned everything, so "I picked a repo"
  // produced a report covering all of them.
  const [selectedPath, setSelectedPath] = useState<string | null>(null);

  const loadPath = useCallback((path: string) => {
    setLoadingProjects(true);
    fetch(`/api/browser?path=${encodeURIComponent(path)}`)
      .then(r => r.json())
      .then(d => { 
        if (d.ok) {
          setProjects(d.entries?.filter((e: BrowserEntry) => e.is_dir) || []);
        } 
      })
      .catch(() => {})
      .finally(() => setLoadingProjects(false));
  }, []);

  useEffect(() => {
    loadPath(currentPath);
  }, [currentPath, loadPath]);

  useEffect(() => {
    fetch('/api/health').then(r => r.json()).then(d => { if (d.ok && d.tools) setToolStatus(d.tools); }).catch(() => {});
  }, []);

  // Elapsed time is real; scanner stages are reported only after completion.
  useEffect(() => {
    if (!scanningProject) return;
    const timer = setInterval(() => setElapsed(value => value + 1), 1000);
    return () => clearInterval(timer);
  }, [scanningProject]);

  const runScan = async (path: string): Promise<boolean> => {
    setElapsed(0);
    setScanningProject(path);
    setScanStatuses(prev => ({ ...prev, [path]: { state: 'scanning' } }));
    try {
      const res = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ path, external }),
      });
      const data = await res.json();
      if (data.ok) {
        setScanStatuses(prev => ({ ...prev, [path]: { state: 'done', findings: data.findings?.length ?? 0, duration: data.duration, coverage: data.scanner_coverage } }));
        return true;
      } else {
        setScanStatuses(prev => ({ ...prev, [path]: { state: 'error', error: data.error || 'Failed' } }));
        return false;
      }
    } catch {
      setScanStatuses(prev => ({ ...prev, [path]: { state: 'error', error: 'Connection error' } }));
      return false;
    } finally {
      setScanningProject(null);
    }
  };

  const scanAll = async () => {
    setTotalScans(projects.length);
    setActiveScans(0);
    for (let i = 0; i < projects.length; i++) {
      setActiveScans(i + 1);
      await runScan(projects[i].path);
    }
    // A finished scan must be reflected by refetching state, never by reloading
    // the page: a reload drops scan results the user is still looking at.
    onScanComplete?.();
  };

  const scanOne = async (path: string) => {
    setTotalScans(1);
    setActiveScans(1);
    await runScan(path);
    onScanComplete?.();
  };

  const isAnyScanRunning = !!scanningProject;
  const completedCount = Object.values(scanStatuses).filter(s => s.state === 'done').length;
  const totalFindings = Object.values(scanStatuses).filter(s => s.state === 'done').reduce((sum, s) => sum + (s.findings ?? 0), 0);

  const toolList = [
    { key: 'semgrep', label: 'Semgrep', desc: 'SAST analysis' },
    { key: 'gitleaks', label: 'Gitleaks', desc: 'Secret detection' },
    { key: 'trivy', label: 'Trivy', desc: 'Dependency scan' },
    { key: 'bandit', label: 'Bandit', desc: 'Python security' },
  ];

  return (
    <div className="flex flex-col h-full bg-surface text-on-surface">
      {/* Header */}
      <div className="flex items-center gap-2 px-4 py-3 border-b border-[rgba(255,255,255,0.06)] bg-surface-container-low">
        {currentPath !== '/host' && (
          <button 
            onClick={() => {
              const parts = currentPath.split('/');
              parts.pop();
              const parent = parts.join('/') || '/host';
              setCurrentPath(parent === '/' ? '/host' : parent);
            }}
            className="w-5 h-5 flex items-center justify-center rounded border border-[rgba(255,255,255,0.06)] text-[#71717a] hover:text-[#a1a1aa] hover:bg-[rgba(255,255,255,0.02)] transition-colors cursor-pointer mr-0.5 shrink-0"
            title={t('review.goBack')}
          >
            <span className="material-symbols-outlined text-[13px]">arrow_back</span>
          </button>
        )}
        <div className="flex-1 min-w-0">
          <span className="text-[12px] font-bold text-[#f4f4f5] tracking-wide block truncate uppercase">
            {currentPath === '/host' ? t('SimpleDashboardPage.projects') : currentPath.replace(/^\/host\/?/, '') || 'Projects'}
          </span>
        </div>
        <span className="text-[10px] text-[#3f3f46] tabular-nums shrink-0 font-mono">
          {projects.length} DIRS
        </span>
      </div>

      {/* Scan progress panel */}
      {isAnyScanRunning && (
        <div className="border-b border-[rgba(255,255,255,0.06)] bg-surface-container-low/80">
          {/* Current scanner phase */}
          <div className="px-4 py-2.5">
            <div className="flex items-center justify-between mb-1">
              <div className="flex items-center gap-1.5">
                <div className="w-4 h-4 border-2 border-[#3f3f46] border-t-[#22c55e] rounded-full animate-spin" />
                <span className="text-[11px] text-[#f4f4f5] font-medium">{scanningProject?.split('/').pop()}</span>
              </div>
              <span className="text-[10px] text-[#52525b] tabular-nums">{t('SimpleDashboardPage.elapsed', { seconds: elapsed })}</span>
            </div>
            <p className="review-help">{t('review.scanRunning')}</p>
            {/* Batch progress */}
            {totalScans > 1 && (
              <div className="flex items-center justify-between mt-2">
                <span className="text-[9px] text-[#3f3f46]">{t('SimpleDashboardPage.scanProgress', { active: activeScans, total: totalScans })}</span>
                <div className="w-20 h-0.5 bg-surface-bright rounded-full overflow-hidden">
                  <div className="h-full bg-[#52525b] rounded-full transition-all" style={{ width: `${(activeScans / totalScans) * 100}%` }} />
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      <div className="flex-1 overflow-y-auto" style={{ scrollbarWidth: 'thin', scrollbarColor: 'rgba(255,255,255,0.06) transparent' }}>
        {/* Project list */}
        <div className="p-1.5 space-y-0.5">
          {loadingProjects ? (
            <div className="flex items-center justify-center py-8">
              <div className="w-3 h-3 border border-surface-container-highest border-t-[#52525b] rounded-full animate-spin" />
            </div>
          ) : projects.length === 0 ? (
            <div className="py-6 text-center text-[11px] text-[#3f3f46]">{t('SimpleDashboardPage.noProjects')}</div>
          ) : (
            projects.map(p => {
              const status = scanStatuses[p.path];
              const isActive = scanningProject === p.path;
              const isDimmed = isAnyScanRunning && !isActive;
              const isSelected = selectedPath === p.path;
              return (
                <div key={p.path}
                  className={`flex items-center gap-2.5 px-3 py-2 rounded-lg transition-all duration-300 ${
                    isActive ? 'bg-[rgba(34,197,94,0.06)] border-l-2 border-l-[#22c55e] border-y border-r border-[rgba(34,197,94,0.1)]'
                    : status?.state === 'done' ? 'border-l-2 border-l-[#22c55e]/40 border-y border-r border-transparent'
                    : status?.state === 'error' ? 'border-l-2 border-l-[#ef4444]/40 border-y border-r border-transparent'
                    : isSelected ? 'bg-[var(--accent-color-soft)] border border-[var(--accent-color-line)]'
                    : 'border border-transparent hover:bg-surface-bright/40'
                  } ${isDimmed ? 'opacity-30' : ''}`}
                >
                  <div
                    onClick={() => !isAnyScanRunning && setSelectedPath(prev => (prev === p.path ? null : p.path))}
                    className="flex-1 flex items-center gap-2.5 min-w-0 cursor-pointer group"
                  >
                    {/* Icon */}
                    {isActive ? (
                      <div className="w-4 h-4 border-2 border-surface-container-highest border-t-[#22c55e] rounded-full animate-spin shrink-0" />
                    ) : status?.state === 'done' ? (
                      <span className="material-symbols-outlined text-[16px] text-[#22c55e] shrink-0">check_circle</span>
                    ) : status?.state === 'error' ? (
                      <span className="material-symbols-outlined text-[16px] text-[#ef4444] shrink-0">error</span>
                    ) : (
                      <span className="material-symbols-outlined text-[15px] text-[#52525b] group-hover:text-[var(--accent-color)] transition-colors shrink-0">folder</span>
                    )}
                    <div className="flex-1 min-w-0">
                      <div className={`text-[12px] truncate group-hover:text-[#f4f4f5] transition-colors ${isActive ? 'text-[#f4f4f5] font-medium' : 'text-[#a1a1aa]'}`}>{p.name}</div>
                      {status?.state === 'done' && (
                        <div className="text-[10px] text-[#52525b] mt-0.5">
                          <span className="text-[#22c55e]">{status.findings}</span> {t('issues')} · {status.duration}
                          {status.coverage && <> · <span className={status.coverage === 'full' ? 'text-[#22c55e]' : 'text-[#f59e0b]'}>{status.coverage.toUpperCase()}</span></>}
                        </div>
                      )}
                      {status?.state === 'error' && (
                        <div className="text-[10px] text-[#ef4444] mt-0.5 truncate">{status.error}</div>
                      )}
                    </div>
                  </div>
                  
                  {!isActive && (
                    <button
                      onClick={() => scanOne(p.path)}
                      disabled={isAnyScanRunning}
                      className="shrink-0 text-[11px] font-medium text-[#f4f4f5] bg-surface-container-high hover:bg-surface-container-highest border border-outline hover:border-[var(--accent-color-line)] rounded-md px-3 py-1 transition-all disabled:opacity-20 cursor-pointer"
                    >
                      {status?.state === 'done' ? 'Rescan' : 'Scan'}
                    </button>
                  )}
                </div>
              );
            })
          )}
        </div>

        {/* Custom path */}
        <div className="px-4 pt-2 pb-1">
          <button onClick={() => setShowCustomPath(!showCustomPath)}
            className="text-[10px] text-[#3f3f46] hover:text-[#52525b] transition-colors flex items-center gap-1">
            <span className="material-symbols-outlined text-[12px]">{showCustomPath ? 'expand_less' : 'expand_more'}</span>
            Custom path
          </button>
          <AnimatePresence initial={false}>
            {showCustomPath && (
              <motion.div
                key="custom-path"
                initial={{ height: 0, opacity: 0 }}
                animate={{ height: "auto", opacity: 1 }}
                exit={{ height: 0, opacity: 0 }}
                transition={{ duration: 0.2 }}
                className="overflow-hidden"
              >
                <div className="mt-2"><PathInput value={scanPath} onChange={setScanPath} /></div>
              </motion.div>
            )}
          </AnimatePresence>
        </div>

        {/* Scanners */}
        <div className="px-4 pt-2 pb-2">
          <button onClick={() => setShowScanners(!showScanners)}
            className="w-full flex items-center justify-between text-[10px] text-[#3f3f46] hover:text-[#52525b] transition-colors">
            <span className="flex items-center gap-1">
              <span className="material-symbols-outlined text-[12px]">{showScanners ? 'expand_less' : 'expand_more'}</span>
              {t('review.scanners')}
            </span>
            <span>{Object.values(toolStatus).filter(Boolean).length}/{toolList.length} {t('SimpleDashboardPage.active')}</span>
          </button>
          <AnimatePresence initial={false}>
            {showScanners && (
              <motion.div
                key="scanners"
                initial={{ height: 0, opacity: 0 }}
                animate={{ height: "auto", opacity: 1 }}
                exit={{ height: 0, opacity: 0 }}
                transition={{ duration: 0.2 }}
                className="overflow-hidden"
              >
                <div className="mt-2 space-y-0.5">
                  <label className="flex items-center gap-3 py-2 text-sm text-on-surface">
                    <input type="checkbox" checked={external} disabled={isAnyScanRunning} onChange={event => setExternal(event.target.checked)} />
                    {t('review.externalScanners')}
                  </label>
                  {toolList.map(tool => <div key={tool.key} className="flex items-center justify-between gap-2 px-2 py-2 text-xs text-on-surface-variant">
                    <span>{tool.label}</span><span>{toolStatus[tool.key] ? t('review.available') : t('review.unavailable')}</span>
                  </div>)}

                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </div>

        {/* Scan summary */}
        {completedCount > 0 && !isAnyScanRunning && (
          <div className="mx-3 mb-2 px-3 py-2 rounded-lg bg-[rgba(34,197,94,0.06)] border border-[rgba(34,197,94,0.12)]">
            <div className="text-[11px] text-[#22c55e] font-medium">{completedCount} project{completedCount > 1 ? 's' : ''} scanned</div>
            <div className="text-[10px] text-[#52525b] mt-0.5">{totalFindings} total {t('issues')} found</div>
          </div>
        )}
      </div>

      {/* Action button */}
      <div className="p-3 border-t border-[rgba(255,255,255,0.06)] bg-surface-container-low">
        <button
          onClick={() => {
            if (showCustomPath) return scanOne(scanPath);
            if (selectedPath) return scanOne(selectedPath);
            return scanAll();
          }}
          disabled={isAnyScanRunning || (showCustomPath ? !scanPath.trim() : !selectedPath && projects.length === 0)}
          className="w-full flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg bg-[var(--accent-color)] text-[var(--accent-color-on-text)] text-[13px] font-medium hover:bg-[var(--accent-color-hover)] disabled:opacity-40 transition-all shadow-[0_0_14px_var(--accent-color-soft)]"
        >
          {isAnyScanRunning ? (
            <>
              <div className="w-3.5 h-3.5 border-2 border-current/30 border-t-current rounded-full animate-spin" />
              Scanning {scanningProject?.split('/').pop()}...
            </>
          ) : (
            <>
              <span className="material-symbols-outlined text-[16px]">play_arrow</span>
              {showCustomPath
                ? 'Run Scan'
                : selectedPath
                  ? `Scan ${selectedPath.split('/').filter(Boolean).pop() || selectedPath}`
                  : `Scan All (${projects.length})`}
            </>
          )}
        </button>
      </div>
    </div>
  );
};

/* ── Main Dashboard ── */
const PAGE_SIZE = 25;


const SecureCoderPanel: React.FC<{
  activeProducts: any[];
  onClose: () => void;
  onNavigateToReports?: (sessionId?: number) => void;
}> = ({ activeProducts, onClose, onNavigateToReports }) => {
  const { t, i18n } = useTranslation('pages');
  const reduceMotion = useReducedMotion();
  const [expandedCat, setExpandedCat] = useState<string | null>(null);
  
  // Agent Runway state
  const [runwayOpen, setRunwayOpen] = useState(false);
  const [runwayStep, setRunwayStep] = useState(0); // 0: Select project, 1: Threat Model, 2: Security Plan, 3: Remediation, 4: Scanner & PoC, 5: Report, 6: Complete
  const [runwayProgressMessage, setRunwayProgressMessage] = useState('');
  const [runwayProject, setRunwayProject] = useState<any | null>(null);
  const [runwayLoading, setRunwayLoading] = useState(false);
  const runwayLoadingRef = useRef(false);
  const [runwayError, setRunwayError] = useState('');
  const [runwayAutoMode, setRunwayAutoMode] = useState(false);
  
  const [runwayThreatModel, setRunwayThreatModel] = useState('');
  const [runwaySecurityPlan, setRunwaySecurityPlan] = useState('');
  const [runwayRemediation, setRunwayRemediation] = useState('');
  const [runwayPoC, setRunwayPoC] = useState('');
  const [runwayAuditReport, setRunwayAuditReport] = useState('');
  const [runwayScanCountBefore, setRunwayScanCountBefore] = useState(0);
  const [runwayScanCountAfter, setRunwayScanCountAfter] = useState(0);
  const [runwaySessionId, setRunwaySessionId] = useState<number | null>(null);
  const [runwayExporting, setRunwayExporting] = useState(false);

  // Ignore state
  const [ignoredFindings, setIgnoredFindings] = useState<any[]>([]);
  const [loadingIgnored, setLoadingIgnored] = useState(false);
  
  // Scan state
  const [scanPath, setScanPath] = useState('');
  const [scanResult, setScanResult] = useState<any>(null);
  const [scanning, setScanning] = useState(false);
  const [quickScanType, setQuickScanType] = useState<'file' | 'dir'>('file');
  
  // Dep state
  const [depRegistry, setDepRegistry] = useState('npm');
  const [depPackage, setDepPackage] = useState('');
  const [depResult, setDepResult] = useState<any>(null);
  const [depScanning, setDepScanning] = useState(false);

  // SecureCoder Configuration states
  const [configEnabled, setConfigEnabled] = useState(true);
  const [configScannerBackend, setConfigScannerBackend] = useState('semgrep');
  const [configRuleSet, setConfigRuleSet] = useState('fast');
  const [configAutostartFixes, setConfigAutostartFixes] = useState(true);
  const [configIgnoreMode, setConfigIgnoreMode] = useState('workspace');
  const [configDebug, setConfigDebug] = useState(false);
  const [configLoading, setConfigLoading] = useState(false);
  const [configSaving, setConfigSaving] = useState(false);
  const [configError, setConfigError] = useState('');
  const [configSuccess, setConfigSuccess] = useState(false);

  // Onboarding Wizard states
  const [onboardingOpen, setOnboardingOpen] = useState(false);
  const [onboardingStep, setOnboardingStep] = useState(0);
  const [wizAgreementChecked, setWizAgreementChecked] = useState(false);
  const [onboardingIgnoreContent, setOnboardingIgnoreContent] = useState(
    '# Default glob patterns\n*test.*\n*_test.*\n**/*_test.*\n**/test/**\nnode_modules/\nvendor/\n.git/'
  );

  // Wiz CLI Authentication states
  const [wizStatus, setWizStatus] = useState<any>({ authenticated: false });
  const [wizAuthLoading, setWizAuthLoading] = useState(false);
  const [wizLoginSession, setWizLoginSession] = useState<any>(null);
  const [pollingInterval, setPollingInterval] = useState<any>(null);

  // Ignore File Editor states
  const [ignoreEditorOpen, setIgnoreEditorOpen] = useState(false);
  const [ignoreEditorContent, setIgnoreEditorContent] = useState('');
  const [ignoreEditorSaving, setIgnoreEditorSaving] = useState(false);

  const fetchIgnored = useCallback(async () => {
    setLoadingIgnored(true);
    try {
      const res = await fetch('/api/securecoder/ignored');
      const data = await res.json();
      if (data.entries) setIgnoredFindings(data.entries);
    } catch (e) {
      console.error(e);
    }
    setLoadingIgnored(false);
  }, []);

  const fetchConfig = useCallback(async () => {
    setConfigLoading(true);
    setConfigError('');
    try {
      const res = await fetch('/api/securecoder/config');
      const data = await res.json();
      setConfigEnabled(data.enabled ?? true);
      setConfigScannerBackend(data.scannerBackend ?? 'semgrep');
      setConfigRuleSet(data.ruleSet ?? 'fast');
      setConfigAutostartFixes(data.autostartFixes ?? true);
      setConfigIgnoreMode(data.ignoreMode ?? 'workspace');
      setConfigDebug(data.debug ?? false);
    } catch (e) {
      console.error(e);
      setConfigError('Failed to load configuration.');
    } finally {
      setConfigLoading(false);
    }
  }, []);

  const handleSaveConfig = async (overrideSettings?: any) => {
    setConfigSaving(true);
    setConfigError('');
    setConfigSuccess(false);
    try {
      const res = await fetch('/api/securecoder/config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          enabled: overrideSettings?.enabled ?? configEnabled,
          scannerBackend: overrideSettings?.scannerBackend ?? configScannerBackend,
          ruleSet: overrideSettings?.ruleSet ?? configRuleSet,
          autostartFixes: overrideSettings?.autostartFixes ?? configAutostartFixes,
          ignoreMode: overrideSettings?.ignoreMode ?? configIgnoreMode,
          debug: overrideSettings?.debug ?? configDebug
        })
      });
      const data = await res.json();
      if (data.ok) {
        setConfigSuccess(true);
        setTimeout(() => setConfigSuccess(false), 3000);
      } else {
        setConfigError(data.error || 'Failed to save configuration.');
      }
    } catch (e) {
      console.error(e);
      setConfigError('Network error occurred.');
    } finally {
      setConfigSaving(false);
    }
  };

  const fetchWizStatus = useCallback(async () => {
    setWizAuthLoading(true);
    try {
      const res = await fetch('/api/securecoder/wiz/status');
      const data = await res.json();
      setWizStatus(data);
    } catch (e) {
      console.error(e);
    } finally {
      setWizAuthLoading(false);
    }
  }, []);

  const handleWizStartLogin = async () => {
    try {
      const res = await fetch('/api/securecoder/wiz/login', { method: 'POST' });
      const data = await res.json();
      setWizLoginSession(data);

      if (pollingInterval) clearInterval(pollingInterval);
      const interval = setInterval(async () => {
        try {
          const pollRes = await fetch('/api/securecoder/wiz/login/poll');
          const pollData = await pollRes.json();
          setWizLoginSession(pollData);
          if (pollData.completed || pollData.status === 'success' || pollData.status === 'failed') {
            clearInterval(interval);
            fetchWizStatus();
          }
        } catch (e) {
          console.error(e);
          clearInterval(interval);
        }
      }, 2000);
      setPollingInterval(interval);
    } catch (e) {
      console.error(e);
    }
  };

  const handleWizLogout = async () => {
    try {
      await fetch('/api/securecoder/wiz/logout', { method: 'POST' });
      setWizLoginSession(null);
      fetchWizStatus();
    } catch (e) {
      console.error(e);
    }
  };

  const fetchIgnoreFile = async () => {
    try {
      const res = await fetch('/api/securecoder/ignore-file');
      const data = await res.json();
      setIgnoreEditorContent(data.content || '');
    } catch (e) {
      console.error(e);
    }
  };

  const handleSaveIgnoreFile = async (contentToSave: string) => {
    setIgnoreEditorSaving(true);
    try {
      await fetch('/api/securecoder/ignore-file', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ content: contentToSave })
      });
    } catch (e) {
      console.error(e);
    } finally {
      setIgnoreEditorSaving(false);
    }
  };

  const handleClearAllIgnored = async () => {
    try {
      const res = await fetch('/api/securecoder/ignored', { method: 'DELETE' });
      const data = await res.json();
      if (data.ok) {
        setIgnoredFindings([]);
      }
    } catch (e) {
      console.error(e);
    }
  };

  const handleScan = async () => {
    if (!scanPath) return;
    setScanning(true);
    try {
      const endpoint = quickScanType === 'file' ? '/api/securecoder/scan' : '/api/securecoder/scan-directory';
      const body = quickScanType === 'file' 
        ? { filePath: scanPath }
        : { path: scanPath, external: true };

      const res = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
      });
      const data = await res.json();
      setScanResult(data.findings || []);
    } catch (e) {
      console.error(e);
    }
    setScanning(false);
  };

  const handleDepScan = async () => {
    if (!depPackage) return;
    setDepScanning(true);
    try {
      let pkgName = depPackage.trim();
      let pkgVersion = '';

      if (pkgName.includes('@')) {
        const parts = pkgName.split('@');
        if (pkgName.startsWith('@')) {
          pkgName = '@' + parts[1];
          pkgVersion = parts[2] || '';
        } else {
          pkgName = parts[0];
          pkgVersion = parts[1] || '';
        }
      }

      const res = await fetch('/api/securecoder/dependency/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ registry: depRegistry, packages: [{ package: pkgName, version: pkgVersion }] })
      });
      const data = await res.json();
      setDepResult(data.unsafeDependencies || []);
    } catch (e) {
      console.error(e);
    }
    setDepScanning(false);
  };

  // Baseline: accept today's findings as the starting line so the gate reports
  // only new work. It existed only in the CLI, so the people most likely to need
  // it — those working entirely here — could not reach it.
  const [baselineStatus, setBaselineStatus] = useState<BaselineStatus | null>(null);
  const [baselineBusy, setBaselineBusy] = useState(false);

  const fetchBaseline = useCallback(async () => {
    try {
      const res = await fetch('/api/baseline');
      const data = await res.json();
      if (data.ok) setBaselineStatus(data);
    } catch { /* leave the previous status visible */ }
  }, []);

  const writeBaseline = useCallback(async () => {
    setBaselineBusy(true);
    try {
      const res = await fetch('/api/baseline', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      });
      const data = await res.json();
      if (data.ok) setBaselineStatus(data);
    } catch { /* status stays as it was */ }
    setBaselineBusy(false);
  }, []);

  const clearBaseline = useCallback(async () => {
    setBaselineBusy(true);
    try {
      const res = await fetch('/api/baseline', { method: 'DELETE' });
      const data = await res.json();
      if (data.ok) setBaselineStatus(data);
    } catch { /* status stays as it was */ }
    setBaselineBusy(false);
  }, []);

  // Quick checks: one question at a time, without paying for a full audit.
  // The AI IDE tools have offered these all along; the Web UI could only run
  // everything, so people skipped the check entirely.
  const [checkResult, setCheckResult] = useState<{ check: string; count: number; summary: string } | null>(null);
  const [checkRunning, setCheckRunning] = useState<string | null>(null);

  const runQuickCheck = useCallback(async (kind: 'nfr' | 'deploy' | 'entropy') => {
    setCheckRunning(kind);
    setCheckResult(null);
    try {
      const res = await fetch(`/api/check/${kind}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ path: '.' }),
      });
      const data = await res.json();
      if (data.ok) {
        setCheckResult({ check: data.check, count: data.count, summary: data.summary });
      } else {
        setCheckResult({ check: kind, count: 0, summary: data.error || 'Check failed' });
      }
    } catch {
      setCheckResult({ check: kind, count: 0, summary: 'Could not reach the server' });
    }
    setCheckRunning(null);
  }, []);

  useEffect(() => {
    if (expandedCat === 'ignore') fetchIgnored();
    if (expandedCat === 'config') fetchConfig();
    if (expandedCat === 'baseline') fetchBaseline();
  }, [expandedCat, fetchIgnored, fetchConfig, fetchBaseline]);

  useEffect(() => {
    if (configScannerBackend === 'wiz') {
      fetchWizStatus();
    }
  }, [configScannerBackend, fetchWizStatus]);

  useEffect(() => {
    return () => {
      if (pollingInterval) clearInterval(pollingInterval);
    };
  }, [pollingInterval]);



  // True once the operator has deliberately started or reset an audit. From then
  // on the background poller may refresh the run it is watching, but must never
  // pull the screen back to a different, already finished one.
  const runwayUserDrivenRef = useRef(false);
  // Mirrors runwaySessionId for the polling closure, which would otherwise read
  // the value captured when the interval was created.
  const runwaySessionIdRef = useRef<number | null>(null);

  const restoreRunwayFromSession = useCallback((session: any, options?: { takeOver?: boolean }) => {
    if (!session) return;
    const takeOver = options?.takeOver ?? true;
    const status = String(session.status || '').toLowerCase();
    const rawStep = Number(session.current_step || 0);
    const displayStep = (status === 'running' || status === 'in_progress') && rawStep === 0 ? 1 : rawStep;

    setRunwaySessionId(session.id);
    runwaySessionIdRef.current = session.id;
    setRunwayStep(displayStep);
    setRunwayProgressMessage(session.progress_message || '');
    setRunwayAutoMode(session.auto_mode || false);
    setRunwayThreatModel(session.threat_model || '');
    setRunwaySecurityPlan(session.security_plan || '');
    setRunwayRemediation(session.remediation || '');
    setRunwayPoC(session.poc || '');
    setRunwayAuditReport(session.audit_report || '');
    setRunwayScanCountBefore(session.scan_count_before || 0);
    setRunwayScanCountAfter(session.scan_count_after || 0);
    setRunwayError(session.error_message || (status === 'failed' ? t('SimpleDashboardPage.runway.auditFailed') : ''));
    setRunwayLoading(false);
    runwayLoadingRef.current = false;

    // Restore project from activeProducts
    const proj = activeProducts.find(p => p.id === session.product_id);
    if (proj) {
      setRunwayProject(proj);
      // A finished audit is history: show it if the operator opens Runway, but
      // never force it back onto the screen while they are doing something else.
      if (takeOver && status !== 'completed' && status !== 'failed') {
        setRunwayOpen(true);
      }
    }
  }, [activeProducts, t]);

  // Restore runway session from DB on mount + poll for cross-tab sync
  useEffect(() => {
    if (activeProducts.length === 0) return;
    let cancelled = false;

    const fetchLatestSession = async () => {
      for (const prod of activeProducts) {
        try {
          const res = await fetch(`/api/runway?product_id=${prod.id}`);
          const data = await res.json();
          const status = String(data.session?.status || '').toLowerCase();
          const shouldRestore = data.session && (
            data.session.current_step > 0 ||
            data.session.error_message ||
            data.session.progress_message ||
            status === 'running' ||
            status === 'failed' ||
            status === 'completed'
          );
          if (!cancelled && data.ok && shouldRestore) {
            const decision = decideRestore({
              status: data.session.status,
              sessionId: data.session.id,
              onScreenSessionId: runwaySessionIdRef.current,
              userDriven: runwayUserDrivenRef.current,
            });
            if (!decision.apply) {
              return false;
            }

            restoreRunwayFromSession(data.session, { takeOver: decision.takeOver });
            return true;
          }
        } catch (e) { /* ignore */ }
      }
      return false;
    };

    // Initial restore
    fetchLatestSession();

    // Poll every 5s for cross-tab sync and backend completion.
    const pollId = setInterval(() => {
      if (cancelled) return;
      fetchLatestSession();
    }, 5000);

    return () => { cancelled = true; clearInterval(pollId); };
  }, [activeProducts, restoreRunwayFromSession]);

  const triggerBackendOrchestrator = async () => {
    if (!runwayProject) return;
    runwayUserDrivenRef.current = true;
    setRunwayAutoMode(true);
    setRunwayLoading(true);
    runwayLoadingRef.current = true;
    setRunwayError('');
    setRunwayProgressMessage('preparing_context');

    let sessionId = runwaySessionId;
    if (!sessionId) {
      try {
        const createRes = await fetch('/api/runway', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ product_id: runwayProject.id, auto_mode: true })
        });
        const createData = await createRes.json();
        if (createData.ok && createData.session) {
          sessionId = createData.session.id;
          setRunwaySessionId(sessionId);
          runwaySessionIdRef.current = sessionId;
        } else {
          throw new Error('Failed to create session');
        }
      } catch (e) {
        setRunwayError('Failed to create runway session in DB');
        setRunwayLoading(false);
        runwayLoadingRef.current = false;
        return;
      }
    }

    try {
      // The audit narrative is written in the language the operator is reading.
      const res = await fetch(`/api/runway/start/${sessionId}?lang=${encodeURIComponent(i18n.language || 'en')}`, { method: 'POST' });
      const data = await res.json();
      if (!data.ok) throw new Error(data.error || 'Failed to start scan.');
      setRunwayStep(prev => (prev > 0 ? prev : 1));
      setRunwayProgressMessage(prev => prev || 'preparing_context');
      setRunwayLoading(false);
      runwayLoadingRef.current = false;
    } catch (e: any) {
      setRunwayError(e.message || 'Failed to trigger scan on backend.');
      setRunwayLoading(false);
      runwayLoadingRef.current = false;
    }
  };

  const handleRunwayAutoRun = triggerBackendOrchestrator;
  const runwayRunInProgress = runwayLoading || (runwaySessionId !== null && runwayStep > 0 && runwayStep < 7 && !runwayError);
  const runwayStageInfo = useMemo(() => {
    const stageKey = runwayProgressMessage || (
      runwayStep <= 1 ? 'building_threat_model' :
      runwayStep === 2 ? 'verifying_poc' :
      runwayStep === 3 ? 'computing_health_check' :
      runwayStep === 4 ? 'generating_report' :
      runwayStep === 5 ? 'generating_fix_spec' :
      runwayStep === 6 ? 'generating_summary' :
      runwayStep >= 7 ? 'completed' :
      'preparing_context'
    );

    const stages: Record<string, { icon: string; title: string; detail: string }> = {
      preparing_context: {
        icon: 'folder_search',
        title: t('SimpleDashboardPage.runway.progressPreparingContext'),
        detail: t('SimpleDashboardPage.runway.progressPreparingContextDetail')
      },
      building_threat_model: {
        icon: 'psychology',
        title: t('SimpleDashboardPage.runway.progressThreatModel'),
        detail: t('SimpleDashboardPage.runway.progressThreatModelDetail')
      },
      verifying_poc: {
        icon: 'science',
        title: t('SimpleDashboardPage.runway.progressPoc'),
        detail: t('SimpleDashboardPage.runway.progressPocDetail')
      },
      computing_health_check: {
        icon: 'monitor_heart',
        title: t('SimpleDashboardPage.runway.progressHealthCheck'),
        detail: t('SimpleDashboardPage.runway.progressHealthCheckDetail')
      },
      generating_report: {
        icon: 'description',
        title: t('SimpleDashboardPage.runway.progressReport'),
        detail: t('SimpleDashboardPage.runway.progressReportDetail')
      },
      generating_fix_spec: {
        icon: 'construction',
        title: t('SimpleDashboardPage.runway.progressFixSpec'),
        detail: t('SimpleDashboardPage.runway.progressFixSpecDetail')
      },
      generating_summary: {
        icon: 'summarize',
        title: t('SimpleDashboardPage.runway.progressSummary'),
        detail: t('SimpleDashboardPage.runway.progressSummaryDetail')
      },
      completed: {
        icon: 'check_circle',
        title: t('SimpleDashboardPage.runway.progressCompleted'),
        detail: t('SimpleDashboardPage.runway.progressCompletedDetail')
      },
      failed: {
        icon: 'error',
        title: t('SimpleDashboardPage.runway.progressFailed'),
        detail: t('SimpleDashboardPage.runway.progressFailedDetail')
      }
    };

    return stages[stageKey] || stages.preparing_context;
  }, [runwayProgressMessage, runwayStep, t]);

  const handleResetRunway = async () => {
    // Delete session from DB
    if (runwaySessionId) {
      try {
        await fetch(`/api/runway/${runwaySessionId}`, { method: 'DELETE' });
      } catch (e) {
        console.error('Failed to delete runway session:', e);
      }
    }
    // Mark the operator as driving before clearing state, so the 5s poller
    // cannot immediately restore the session that was just dismissed.
    runwayUserDrivenRef.current = true;
    runwaySessionIdRef.current = null;

    setRunwaySessionId(null);
    setRunwayStep(0);
    setRunwayProgressMessage('');
    setRunwayProject(null);
    setRunwayThreatModel('');
    setRunwaySecurityPlan('');
    setRunwayRemediation('');
    setRunwayPoC('');
    setRunwayAuditReport('');
    setRunwayScanCountBefore(0);
    setRunwayScanCountAfter(0);
    setRunwayError('');
    setRunwayAutoMode(false);
  };

  const handleDownloadMarkdown = async () => {
    if (!runwayProject) return;

    if (runwaySessionId) {
      try {
        const downloaded = await downloadRunwayArtifact(
          runwaySessionId,
          'summary_markdown',
          `runway-${runwaySessionId}-summary.md`,
        );
        if (downloaded) return;
      } catch {
        // Sessions created before canonical artifacts use the compatibility report below.
      }
    }
    
    let md = `# 🛡️ AITriage Security Audit Report\n\n`;
    md += `**Project**: ${runwayProject.name}\n`;
    md += `**Date**: ${new Date().toLocaleString()}\n`;
    md += `**Session ID**: ${runwaySessionId || 'N/A'}\n`;
    md += `**Findings**: ${runwayScanCountBefore} before → ${runwayScanCountAfter} after\n\n`;
    md += `---\n\n`;

    if (runwayThreatModel) {
      md += `## 1. STRIDE Threat Model\n\n${runwayThreatModel}\n\n---\n\n`;
    }
    if (runwaySecurityPlan) {
      md += `## 2. Security Implementation Plan\n\n${runwaySecurityPlan}\n\n---\n\n`;
    }
    if (runwayRemediation) {
      md += `## 3. Remediation Patches\n\n${runwayRemediation}\n\n---\n\n`;
    }
    if (runwayPoC) {
      md += `## 4. Proof of Concept Verification\n\n${runwayPoC}\n\n---\n\n`;
    }
    if (runwayAuditReport) {
      md += `## 5. Audit Report\n\n${runwayAuditReport}\n\n---\n\n`;
    }
    md += `\n*Generated by AITriage SecureCoder Agent*\n`;

    const blob = new Blob([md], { type: 'text/markdown;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute("href", url);
    const dateStr = new Date().toISOString().split('T')[0];
    downloadAnchor.setAttribute("download", `runway-report-${runwaySessionId || 'session'}-${dateStr}.md`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
    URL.revokeObjectURL(url);
  };

  const handleExportToProject = async () => {
    if (!runwaySessionId) return;
    setRunwayExporting(true);
    try {
      const res = await fetch(`/api/runway/export/${runwaySessionId}`, { method: 'POST' });
      const data = await res.json();
      if (data.ok) {
        alert(t('SimpleDashboardPage.runway.exportSuccess', { path: data.saved_to || 'aitriage/' }));
      } else {
        alert(data.error || 'Failed to export report.');
      }
    } catch (e) {
      alert('Error exporting report: network failure.');
    } finally {
      setRunwayExporting(false);
    }
  };

  const activeViewMeta = expandedCat ? ({
    scan: {
      icon: 'document_scanner',
      title: t('SimpleDashboardPage.runway.quickTargetScan'),
      detail: `${t('SimpleDashboardPage.runway.file')} / ${t('SimpleDashboardPage.runway.directory')}`
    },
    deps: {
      icon: 'package_2',
      title: t('SimpleDashboardPage.runway.dependencyScanner'),
      detail: 'npm · PyPI · Go'
    },
    ignore: {
      icon: 'visibility_off',
      title: t('SimpleDashboardPage.runway.ignoredFindings'),
      detail: String(ignoredFindings.length)
    },
    config: {
      icon: 'settings',
      title: t('SimpleDashboardPage.runway.configurationSettings'),
      detail: `${configScannerBackend.toUpperCase()} · ${configRuleSet.toUpperCase()}`
    }
  } as const)[expandedCat] : null;

  return (
    <div className="simple-securecoder-panel overflow-hidden">
      <header className="simple-securecoder-panel__header">
        <div className="simple-securecoder-panel__identity">
          <div className="simple-securecoder-panel__mark">
            <span className="material-symbols-outlined" style={{ fontVariationSettings: "'FILL' 1" }}>security</span>
          </div>
          <div>
            <h2>SecureCoder</h2>
            <p>{t('SimpleDashboardPage.runway.aiAgentCompatibilityLayer')}</p>
          </div>
        </div>
        <button type="button" className="simple-securecoder-panel__close" onClick={onClose} aria-label="Close SecureCoder">
          <span className="material-symbols-outlined" aria-hidden="true">close</span>
        </button>
      </header>

      <section className="simple-securecoder-panel__launch">
        <div className="simple-securecoder-panel__launch-copy">
          <span className="material-symbols-outlined" aria-hidden="true">auto_fix_high</span>
          <div>
            <strong>{t('SimpleDashboardPage.runway.agentRunway')}</strong>
            <p>{t('SimpleDashboardPage.runway.selectProjectStartDesc')}</p>
          </div>
        </div>
        <button
          onClick={() => setRunwayOpen(!runwayOpen)}
          className="simple-securecoder-panel__runway"
        >
          <span className="material-symbols-outlined">{runwayOpen ? 'close' : 'bolt'}</span>
          {runwayOpen ? t('SimpleDashboardPage.runway.closeRunway') : t('SimpleDashboardPage.runway.runwayWizard')}
        </button>
        <div className="simple-securecoder-panel__readiness" aria-label="SecureCoder status">
          <span><i className={configEnabled ? 'is-ready' : ''} />{t('SimpleDashboardPage.runway.enableIntegration')}</span>
          <span><i className="is-ready" />{configScannerBackend.toUpperCase()}</span>
          <span>{configRuleSet.toUpperCase()}</span>
        </div>
      </section>

      {runwayOpen ? (
        <div className="simple-securecoder-runway p-6 space-y-4">
          <div className="flex items-center justify-between border-b border-[rgba(255,255,255,0.06)] pb-3">
            <span className="text-[11px] font-bold text-[#a1a1aa] uppercase tracking-wider">{t('SimpleDashboardPage.runway.agentRunway')}</span>
            <div className="flex items-center gap-3">
              {runwayAutoMode && (
                <span className="text-[9px] text-[var(--accent-color)] font-mono uppercase tracking-widest animate-pulse flex items-center gap-1">
                  <span className="material-symbols-outlined text-[10px]">auto_mode</span>
                  AUTO
                </span>
              )}
              <span className="text-[10px] text-[var(--accent-color)] font-mono">{t('SimpleDashboardPage.runway.stepIndicator', { current: runwayStep })}</span>
            </div>
          </div>

          {/* Stepper progress bar */}
          <div className="flex gap-1">
            {Array.from({ length: 7 }).map((_, i) => {
              const stepNum = i + 1;
              const isCompleted = stepNum < runwayStep || (stepNum === runwayStep && runwayStep === 7);
              const isActive = stepNum === runwayStep && runwayStep < 7;
              return (
                <div
                  key={i}
	                  className={`h-1.5 flex-1 rounded-full transition-[background-color,opacity] duration-200 relative overflow-hidden ${
	                    isCompleted
	                      ? 'bg-[var(--accent-color)]'
	                      : isActive && runwayRunInProgress
	                      ? 'bg-[rgba(255,255,255,0.06)]'
	                      : isActive
	                      ? 'bg-[var(--accent-color)] opacity-40'
	                      : 'bg-[rgba(255,255,255,0.06)]'
	                  }`}
                >
                  {isActive && runwayRunInProgress && (
                    <div className="absolute inset-0 bg-gradient-to-r from-[var(--accent-color)] via-[var(--accent-color-hover)] to-transparent animate-[shimmer_1.5s_ease-in-out_infinite]" style={{ backgroundSize: '200% 100%' }} />
                  )}
                </div>
              );
            })}
          </div>

          {/* Auto-mode current status */}
          {runwaySessionId && runwayStep > 0 && runwayStep < 7 && !runwayError && (
            <div 
              className="flex items-center justify-center gap-4 py-10 px-4 rounded-lg border"
              style={{
                backgroundColor: 'var(--accent-color-soft)',
                borderColor: 'var(--accent-color-line)'
              }}
            >
              <div className="relative w-10 h-10 shrink-0 flex items-center justify-center">
                <div className="absolute inset-0 border-2 border-[rgba(255,255,255,0.08)] border-t-[var(--accent-color)] rounded-full animate-spin" />
                <span className="material-symbols-outlined text-[18px]" style={{ color: 'var(--accent-color)' }}>{runwayStageInfo.icon}</span>
              </div>
              <div className="min-w-0">
                <span className="text-[14px] text-white font-semibold uppercase tracking-wider block">{runwayStageInfo.title}</span>
                <span className="text-[11px] text-[#71717a] font-mono mt-1 block">{runwayStageInfo.detail}</span>
              </div>
            </div>
          )}

          {runwayError && (
            <div className="p-3 bg-[rgba(239,68,68,0.08)] border border-[rgba(239,68,68,0.15)] rounded text-[11px] text-[#ef4444] font-medium flex items-center gap-2 mt-4">
              <span className="material-symbols-outlined text-[14px]">error</span>
              {runwayError}
              <button onClick={handleRunwayAutoRun} className="ml-auto text-[10px] text-[#ef4444] hover:text-[#f87171] uppercase font-mono font-bold underline">{t('SimpleDashboardPage.runway.retry')}</button>
            </div>
          )}

          {/* STEP 0: Project selection */}
          {runwayStep === 0 && (
            <div className="space-y-4 pt-2">
              <p className="text-[11px] text-[#71717a] leading-relaxed">{t('SimpleDashboardPage.runway.selectProjectStartDesc')}</p>
              <div className="flex gap-2">
                <select
                  value={runwayProject ? runwayProject.id : ''}
                  onChange={e => {
                    const id = Number(e.target.value);
                    setRunwayProject(activeProducts.find(p => p.id === id) || null);
                  }}
                  className="flex-1 bg-[rgba(255,255,255,0.02)] border border-[rgba(255,255,255,0.06)] rounded px-3 py-2 text-[12px] text-white outline-none focus:border-[var(--accent-color)] cursor-pointer"
                >
                  <option value="">{t('SimpleDashboardPage.runway.chooseProject')}</option>
                  {activeProducts.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}
                </select>
              </div>
              <div>
                <button
                  onClick={handleRunwayAutoRun}
                  disabled={!runwayProject || runwayRunInProgress}
                  className="w-full px-4 py-2.5 bg-[var(--accent-color)] hover:bg-[var(--accent-color-hover)] text-[var(--accent-color-on-text)] rounded text-[12px] font-bold uppercase tracking-wider disabled:opacity-30 transition-[background-color,transform] duration-150 flex items-center justify-center gap-2 active:scale-[0.97]"
                >
                  {runwayLoading ? (
                    <span className="w-3.5 h-3.5 border-2 border-current/30 border-t-current rounded-full animate-spin" />
                  ) : (
                    <span className="material-symbols-outlined text-[16px]">play_arrow</span>
                  )}
                  {runwayLoading ? t('SimpleDashboardPage.runway.startingAudit') : t('SimpleDashboardPage.runway.startAutomatedAudit')}
                </button>
              </div>
            </div>
          )}

          {/* STEP 7: Completed Success */}
          {runwayStep === 7 && (
            <div className="space-y-4 pt-2 py-4">
              <div className="simple-runway-result">
                <div className="simple-runway-result__message">
                  <span className="material-symbols-outlined" aria-hidden="true">task_alt</span>
                  <div>
                    <h4>{t('SimpleDashboardPage.runway.reportReady')}</h4>
                    <p>{t('SimpleDashboardPage.runway.reportReadyDesc')}</p>
                  </div>
                </div>
                <div className="simple-runway-result__actions">
                  {onNavigateToReports && (
                    <button type="button" className="simple-runway-result__open" onClick={() => onNavigateToReports(runwaySessionId ?? undefined)}>
                      <span className="material-symbols-outlined" aria-hidden="true">description</span>
                      {t('SimpleDashboardPage.runway.openFullReport')}
                    </button>
                  )}
                  <button type="button" className="simple-runway-result__download" onClick={() => void handleDownloadMarkdown()}>
                    <span className="material-symbols-outlined" aria-hidden="true">download</span>
                    {t('SimpleDashboardPage.runway.downloadCICDSummary')}
                  </button>
                </div>
              </div>

              <AgentHandoffPanel sessionId={runwaySessionId} compact />

              <div className="flex flex-col gap-2 max-w-xs mx-auto">
                <button
                  onClick={handleExportToProject}
                  disabled={runwayExporting}
                  className="px-4 py-1.5 bg-[rgba(255,255,255,0.04)] border border-[rgba(255,255,255,0.08)] hover:bg-[rgba(255,255,255,0.07)] text-[#c4c4cc] rounded text-[11px] font-semibold transition-colors flex items-center justify-center gap-1.5 cursor-pointer disabled:opacity-50"
                >
                  <span className="material-symbols-outlined text-[13px]">ios_share</span>
                  {runwayExporting ? t('SimpleDashboardPage.runway.syncing') : t('SimpleDashboardPage.runway.exportToProject')}
                </button>
                <button
                  onClick={handleResetRunway}
                  className="px-4 py-1.5 bg-[rgba(255,255,255,0.02)] border border-[rgba(255,255,255,0.06)] hover:bg-[rgba(255,255,255,0.05)] text-[#a1a1aa] rounded text-[11px] font-bold uppercase tracking-wider transition-colors"
                >
                  {t('SimpleDashboardPage.runway.runAgain')}
                </button>
              </div>
            </div>
          )}
        </div>
      ) : (
        <div className="simple-securecoder-menu" data-active-view={expandedCat || 'overview'}>
          {activeViewMeta && (
            <div className="simple-securecoder-subview__bar">
              <button type="button" onClick={() => setExpandedCat(null)} aria-label="Back to SecureCoder overview">
                <span className="material-symbols-outlined" aria-hidden="true">arrow_back</span>
              </button>
              <span className="material-symbols-outlined simple-securecoder-subview__icon" aria-hidden="true">{activeViewMeta.icon}</span>
              <div><strong>{activeViewMeta.title}</strong><span>{activeViewMeta.detail}</span></div>
            </div>
          )}
          {/* Quick Target Scan */}
          <div className="simple-securecoder-menu__section" data-view="scan">
            <button onClick={() => setExpandedCat(expandedCat === 'scan' ? null : 'scan')} className="simple-securecoder-menu__trigger w-full flex items-center gap-3 px-6 py-3 group" aria-expanded={expandedCat === 'scan'}>
              <span className={`material-symbols-outlined text-[16px] transition-colors ${expandedCat === 'scan' ? 'text-[var(--accent-color)]' : 'text-[#3f3f46] group-hover:text-[var(--accent-color)]'}`}>document_scanner</span>
              <span className="simple-securecoder-menu__label"><strong>{t('SimpleDashboardPage.runway.quickTargetScan')}</strong><small>{t('SimpleDashboardPage.runway.file')} / {t('SimpleDashboardPage.runway.directory')}</small></span>
              <span className="material-symbols-outlined">chevron_right</span>
            </button>
            <AnimatePresence initial={false}>
              {expandedCat === 'scan' && (
                <motion.div initial={false} animate={{ opacity: 1 }} exit={{ opacity: 0 }} transition={{ duration: reduceMotion ? 0 : 0.1 }} className="simple-securecoder-menu__content overflow-hidden">
                  <div className="px-6 pb-4 pt-2">
                    <div className="flex gap-4 mb-2.5">
                      <label className="flex items-center gap-1.5 text-[10px] text-[#a1a1aa] cursor-pointer">
                        <input
                          type="radio"
                          name="quickScanTarget"
                          checked={quickScanType === 'file'}
                          onChange={() => { setQuickScanType('file'); setScanResult(null); }}
                          className="accent-[var(--accent-color)]"
                        />
                        {t('SimpleDashboardPage.runway.file')}
                      </label>
                      <label className="flex items-center gap-1.5 text-[10px] text-[#a1a1aa] cursor-pointer">
                        <input
                          type="radio"
                          name="quickScanTarget"
                          checked={quickScanType === 'dir'}
                          onChange={() => { setQuickScanType('dir'); setScanResult(null); }}
                          className="accent-[var(--accent-color)]"
                        />
                        {t('SimpleDashboardPage.runway.directory')}
                      </label>
                    </div>
                    <div className="flex gap-2">
                      <input
                        type="text"
                        value={scanPath}
                        onChange={e => setScanPath(e.target.value)}
                        placeholder={quickScanType === 'file' ? '/path/to/file.ts' : '/path/to/directory'}
                        className="flex-1 bg-[rgba(255,255,255,0.02)] border border-[rgba(255,255,255,0.06)] rounded px-3 py-1.5 text-[11px] text-white outline-none focus:border-[var(--accent-color)]"
                      />
                      <button onClick={handleScan} disabled={scanning} className="px-4 py-1.5 bg-[var(--accent-color)] hover:bg-[var(--accent-color-hover)] text-[var(--accent-color-on-text)] rounded text-[11px] font-bold uppercase tracking-wider disabled:opacity-50 transition-colors">
                        {scanning ? t('SimpleDashboardPage.runway.scanning') : t('SimpleDashboardPage.runway.scan')}
                      </button>
                    </div>
                    {scanResult && (
                      <div className="mt-3 bg-[rgba(0,0,0,0.2)] border border-[rgba(255,255,255,0.04)] rounded p-3 max-h-48 overflow-y-auto" style={{ scrollbarWidth: 'thin' }}>
                        {scanResult.length === 0 ? (
                          <div className="text-[10px] text-[#a1a1aa]">{t('SimpleDashboardPage.runway.noVulnsFound')}</div>
                        ) : (
                          <div className="space-y-2">
                            {scanResult.map((f: any, i: number) => (
                              <div key={i} className="text-[10px] border-b border-[rgba(255,255,255,0.03)] pb-1.5 last:border-0 last:pb-0">
                                <div className="flex items-center justify-between">
                                  <span className="text-[#a1a1aa] font-mono font-bold truncate pr-2">{f.subcategory || f.ruleId}</span>
                                  <span className="text-red-400 font-bold uppercase shrink-0 text-[8px] border border-red-500/20 px-1 rounded">{f.labels?.severity}</span>
                                </div>
                                <div className="text-[#71717a] mt-0.5 select-text leading-snug">{f.message}</div>
                                {f.location?.path && (
                                  <div className="text-[8px] text-[#52525b] font-mono mt-0.5 truncate" title={f.location.path}>
                                    {f.location.path.split('/').pop()}:{f.location.range?.textRange?.startLine || f.location.range?.startLine}
                                  </div>
                                )}
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </div>

          {/* Dependency Scan */}
          <div className="simple-securecoder-menu__section" data-view="deps">
            <button onClick={() => setExpandedCat(expandedCat === 'deps' ? null : 'deps')} className="simple-securecoder-menu__trigger w-full flex items-center gap-3 px-6 py-3 group" aria-expanded={expandedCat === 'deps'}>
              <span className={`material-symbols-outlined text-[16px] transition-colors ${expandedCat === 'deps' ? 'text-[var(--accent-color)]' : 'text-[#3f3f46] group-hover:text-[var(--accent-color)]'}`}>package_2</span>
              <span className="simple-securecoder-menu__label"><strong>{t('SimpleDashboardPage.runway.dependencyScanner')}</strong><small>npm · PyPI · Go</small></span>
              <span className="material-symbols-outlined">chevron_right</span>
            </button>
            <AnimatePresence initial={false}>
              {expandedCat === 'deps' && (
                <motion.div initial={false} animate={{ opacity: 1 }} exit={{ opacity: 0 }} transition={{ duration: reduceMotion ? 0 : 0.1 }} className="simple-securecoder-menu__content overflow-hidden">
                  <div className="px-6 pb-4 pt-2">
                    <div className="flex gap-2">
                      <select value={depRegistry} onChange={e => setDepRegistry(e.target.value)} className="bg-[rgba(255,255,255,0.02)] border border-[rgba(255,255,255,0.06)] rounded px-2 text-[11px] text-white outline-none focus:border-[var(--accent-color)]">
                        <option value="npm">npm</option>
                        <option value="pypi">PyPI</option>
                        <option value="gomodproxy">Go</option>
                      </select>
                      <input type="text" value={depPackage} onChange={e => setDepPackage(e.target.value)} placeholder={t('SimpleDashboardPage.runway.packageName')} className="flex-1 bg-[rgba(255,255,255,0.02)] border border-[rgba(255,255,255,0.06)] rounded px-3 py-1.5 text-[11px] text-white outline-none focus:border-[var(--accent-color)]" />
                      <button onClick={handleDepScan} disabled={depScanning} className="px-4 py-1.5 bg-[var(--accent-color)] hover:bg-[var(--accent-color-hover)] text-[var(--accent-color-on-text)] rounded text-[11px] font-bold uppercase tracking-wider disabled:opacity-50 transition-colors">
                        {depScanning ? t('SimpleDashboardPage.runway.scanning') : t('SimpleDashboardPage.runway.scan')}
                      </button>
                    </div>
                    {depResult && (
                      <div className="mt-3 bg-[rgba(0,0,0,0.3)] border border-[rgba(255,255,255,0.04)] rounded p-3 max-h-40 overflow-y-auto">
                        {depResult.length === 0 ? (
                          <div className="text-[10px] text-[#a1a1aa]">{t('SimpleDashboardPage.runway.packageAppearsSafe')}</div>
                        ) : (
                          <div className="space-y-2">
                            {depResult.map((d: any, i: number) => (
                              <div key={i} className="text-[10px]">
                                <span className="text-orange-400 font-bold uppercase">{d.package}</span>
                                <div className="text-[#71717a] mt-0.5">{d.reason}</div>
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </div>

          {/* Quick checks */}
          <div className="simple-securecoder-menu__section" data-view="checks">
            <button onClick={() => setExpandedCat(expandedCat === 'checks' ? null : 'checks')} className="simple-securecoder-menu__trigger w-full flex items-center gap-3 px-6 py-3 group" aria-expanded={expandedCat === 'checks'}>
              <span className={`material-symbols-outlined text-[16px] transition-colors ${expandedCat === 'checks' ? 'text-[var(--accent-color)]' : 'text-[#3f3f46] group-hover:text-[var(--accent-color)]'}`}>bolt</span>
              <span className="simple-securecoder-menu__label">
                <strong>{i18n.language?.startsWith('ru') ? 'Быстрые проверки' : 'Quick checks'}</strong>
                <small>{i18n.language?.startsWith('ru') ? 'без полного аудита' : 'without a full audit'}</small>
              </span>
              <span className="material-symbols-outlined">chevron_right</span>
            </button>
            <AnimatePresence initial={false}>
              {expandedCat === 'checks' && (
                <motion.div initial={false} animate={{ opacity: 1 }} exit={{ opacity: 0 }} transition={{ duration: reduceMotion ? 0 : 0.1 }} className="simple-securecoder-menu__content overflow-hidden">
                  <div className="px-6 pb-4 pt-2 space-y-3">
                    <div className="flex gap-2">
                      {([
                        { id: 'nfr' as const, ru: 'Требования', en: 'Requirements', icon: 'checklist' },
                        { id: 'deploy' as const, ru: 'Инфраструктура', en: 'Infrastructure', icon: 'deployed_code' },
                        { id: 'entropy' as const, ru: 'История git', en: 'Git history', icon: 'history' },
                      ]).map(check => (
                        <button
                          key={check.id}
                          onClick={() => void runQuickCheck(check.id)}
                          disabled={checkRunning !== null}
                          className="flex-1 py-1.5 bg-[rgba(255,255,255,0.03)] hover:bg-[rgba(255,255,255,0.06)] border border-[rgba(255,255,255,0.06)] hover:border-[rgba(255,255,255,0.12)] text-[#f4f4f5] rounded text-[10px] font-bold uppercase tracking-wider transition-colors flex items-center justify-center gap-1.5 disabled:opacity-40 cursor-pointer"
                        >
                          <span className="material-symbols-outlined text-[12px]">{check.icon}</span>
                          {checkRunning === check.id
                            ? (i18n.language?.startsWith('ru') ? '...' : '...')
                            : (i18n.language?.startsWith('ru') ? check.ru : check.en)}
                        </button>
                      ))}
                    </div>
                    {checkResult && (
                      <div className="text-[11px] leading-relaxed text-[#a1a1aa] border-l-2 border-[var(--accent-color-line)] pl-3">
                        <strong className="text-[#f4f4f5]">{checkResult.count}</strong> — {checkResult.summary}
                      </div>
                    )}
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </div>

          {/* Baseline */}
          <div className="simple-securecoder-menu__section" data-view="baseline">
            <button onClick={() => setExpandedCat(expandedCat === 'baseline' ? null : 'baseline')} className="simple-securecoder-menu__trigger w-full flex items-center gap-3 px-6 py-3 group" aria-expanded={expandedCat === 'baseline'}>
              <span className={`material-symbols-outlined text-[16px] transition-colors ${expandedCat === 'baseline' ? 'text-[var(--accent-color)]' : 'text-[#3f3f46] group-hover:text-[var(--accent-color)]'}`}>flag</span>
              <span className="simple-securecoder-menu__label">
                <strong>{i18n.language?.startsWith('ru') ? 'Точка отсчёта' : 'Baseline'}</strong>
                <small>{baselineStatus?.exists
                  ? (i18n.language?.startsWith('ru') ? `${baselineStatus.total} принято` : `${baselineStatus.total} accepted`)
                  : (i18n.language?.startsWith('ru') ? 'не задана' : 'not set')}</small>
              </span>
              <span className="material-symbols-outlined">chevron_right</span>
            </button>
            <AnimatePresence initial={false}>
              {expandedCat === 'baseline' && (
                <motion.div initial={false} animate={{ opacity: 1 }} exit={{ opacity: 0 }} transition={{ duration: reduceMotion ? 0 : 0.1 }} className="simple-securecoder-menu__content overflow-hidden">
                  <div className="px-6 pb-4 pt-2 space-y-3">
                    <p className="text-[11px] leading-relaxed text-[#71717a]">
                      {i18n.language?.startsWith('ru')
                        ? 'Принимает текущие находки за точку отсчёта. Они остаются видны в отчётах, но гейт начинает судить только новые. Это штатный способ подключить сканер к существующей кодовой базе, не утонув в накопленном долге.'
                        : 'Accepts the current findings as the starting line. They stay visible in reports, but the gate judges only new ones — the standard way to adopt scanning on an existing codebase without drowning in accumulated debt.'}
                    </p>
                    {baselineStatus?.exists && (
                      <div className="text-[10px] text-[#a1a1aa] font-mono space-y-0.5">
                        <div>{i18n.language?.startsWith('ru') ? 'Принято' : 'Accepted'}: <span className="text-[#f4f4f5]">{baselineStatus.total}</span></div>
                        {baselineStatus.created_at && <div>{i18n.language?.startsWith('ru') ? 'Создана' : 'Created'}: {String(baselineStatus.created_at).replace('T', ' ').replace('Z', '')}</div>}
                        {baselineStatus.updated_at && <div>{i18n.language?.startsWith('ru') ? 'Обновлена' : 'Updated'}: {String(baselineStatus.updated_at).replace('T', ' ').replace('Z', '')}</div>}
                      </div>
                    )}
                    <div className="flex gap-2">
                      <button
                        onClick={() => void writeBaseline()}
                        disabled={baselineBusy}
                        className="flex-1 py-1.5 bg-[rgba(255,255,255,0.03)] hover:bg-[rgba(255,255,255,0.06)] border border-[rgba(255,255,255,0.06)] hover:border-[rgba(255,255,255,0.12)] text-[#f4f4f5] rounded text-[10px] font-bold uppercase tracking-wider transition-colors flex items-center justify-center gap-1.5 disabled:opacity-40 cursor-pointer"
                      >
                        <span className="material-symbols-outlined text-[12px]">flag</span>
                        {baselineStatus?.exists
                          ? (i18n.language?.startsWith('ru') ? 'Обновить' : 'Update')
                          : (i18n.language?.startsWith('ru') ? 'Принять текущее' : 'Accept current')}
                      </button>
                      <button
                        onClick={() => void clearBaseline()}
                        disabled={baselineBusy || !baselineStatus?.exists}
                        className="flex-1 py-1.5 bg-[rgba(239,68,68,0.06)] border border-[rgba(239,68,68,0.12)] hover:bg-[rgba(239,68,68,0.12)] text-[#ef4444] rounded text-[10px] font-bold uppercase tracking-wider transition-colors flex items-center justify-center gap-1.5 disabled:opacity-30 disabled:cursor-not-allowed cursor-pointer"
                      >
                        <span className="material-symbols-outlined text-[12px]">delete_sweep</span>
                        {i18n.language?.startsWith('ru') ? 'Очистить' : 'Clear'}
                      </button>
                    </div>
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </div>

          {/* Ignored Findings */}
          <div className="simple-securecoder-menu__section" data-view="ignore">
            <button onClick={() => setExpandedCat(expandedCat === 'ignore' ? null : 'ignore')} className="simple-securecoder-menu__trigger w-full flex items-center gap-3 px-6 py-3 group" aria-expanded={expandedCat === 'ignore'}>
              <span className={`material-symbols-outlined text-[16px] transition-colors ${expandedCat === 'ignore' ? 'text-[var(--accent-color)]' : 'text-[#3f3f46] group-hover:text-[var(--accent-color)]'}`}>visibility_off</span>
              <span className="simple-securecoder-menu__label"><strong>{t('SimpleDashboardPage.runway.ignoredFindings')}</strong><small>{ignoredFindings.length}</small></span>
              <span className="text-[10px] text-[#3f3f46] mr-1">{ignoredFindings.length}</span>
              <span className="material-symbols-outlined">chevron_right</span>
            </button>
            <AnimatePresence initial={false}>
              {expandedCat === 'ignore' && (
                <motion.div initial={false} animate={{ opacity: 1 }} exit={{ opacity: 0 }} transition={{ duration: reduceMotion ? 0 : 0.1 }} className="simple-securecoder-menu__content overflow-hidden">
                  <div className="px-6 pb-4 pt-2 space-y-3">
                    <div className="flex gap-2">
                      <button
                        onClick={async () => {
                          await fetchIgnoreFile();
                          setIgnoreEditorOpen(true);
                        }}
                        className="flex-1 py-1.5 bg-[rgba(255,255,255,0.03)] hover:bg-[rgba(255,255,255,0.06)] border border-[rgba(255,255,255,0.06)] hover:border-[rgba(255,255,255,0.12)] text-[#f4f4f5] rounded text-[10px] font-bold uppercase tracking-wider transition-colors flex items-center justify-center gap-1.5 cursor-pointer"
                      >
                        <span className="material-symbols-outlined text-[12px]">edit</span>
                        {t('SimpleDashboardPage.runway.ignoreFile')}
                      </button>
                      <button
                        onClick={handleClearAllIgnored}
                        disabled={ignoredFindings.length === 0}
                        className="flex-1 py-1.5 bg-[rgba(239,68,68,0.06)] border border-[rgba(239,68,68,0.12)] hover:bg-[rgba(239,68,68,0.12)] text-[#ef4444] rounded text-[10px] font-bold uppercase tracking-wider transition-colors flex items-center justify-center gap-1.5 disabled:opacity-30 disabled:cursor-not-allowed cursor-pointer"
                      >
                        <span className="material-symbols-outlined text-[12px]">delete_sweep</span>
                        {t('SimpleDashboardPage.runway.clearSuppressions')}
                      </button>
                    </div>
                    {loadingIgnored ? (
                      <div className="text-[10px] text-[#71717a]">{t('SimpleDashboardPage.runway.loading')}</div>
                    ) : ignoredFindings.length === 0 ? (
                      <div className="text-[10px] text-[#71717a]">{t('SimpleDashboardPage.runway.noSuppressedFindings')}</div>
                    ) : (
                      <div className="space-y-2 max-h-60 overflow-y-auto pr-2" style={{ scrollbarWidth: 'thin', scrollbarColor: 'rgba(255,255,255,0.06) transparent' }}>
                        {ignoredFindings.map((f: any, i: number) => (
                          <div key={i} className="bg-[rgba(255,255,255,0.02)] border border-[rgba(255,255,255,0.04)] p-2.5 rounded group/ignore">
                            <div className="flex justify-between items-start mb-1">
                              <div className="text-[10px] font-mono text-[#e4e4e7] truncate flex-1">{f.ruleId}</div>
                              <button
                                onClick={async (e) => {
                                  e.stopPropagation();
                                  try {
                                    await fetch(`/api/securecoder/ignored?vulnId=${encodeURIComponent(f.vulnId)}`, { method: 'DELETE' });
                                    fetchIgnored();
                                  } catch (err) {
                                    console.error(err);
                                  }
                                }}
                                className="text-[9px] text-[#71717a] hover:text-red-400 transition-colors ml-1 uppercase border border-[rgba(255,255,255,0.04)] px-1.5 py-0.5 rounded cursor-pointer"
                              >
                                {t('SimpleDashboardPage.runway.restore')}
                              </button>
                            </div>
                            <div className="text-[9px] text-[#71717a] font-mono truncate">{f.filePath}:{f.lineNumber}</div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </div>

          {/* Config / Settings */}
          <div className="simple-securecoder-menu__section" data-view="config">
            <button onClick={() => setExpandedCat(expandedCat === 'config' ? null : 'config')} className="simple-securecoder-menu__trigger w-full flex items-center gap-3 px-6 py-3 group" aria-expanded={expandedCat === 'config'}>
              <span className={`material-symbols-outlined text-[16px] transition-colors ${expandedCat === 'config' ? 'text-[var(--accent-color)]' : 'text-[#3f3f46] group-hover:text-[var(--accent-color)]'}`}>settings</span>
              <span className="simple-securecoder-menu__label"><strong>{t('SimpleDashboardPage.runway.configurationSettings')}</strong><small>{configScannerBackend.toUpperCase()} · {configRuleSet.toUpperCase()}</small></span>
              <span className="material-symbols-outlined">chevron_right</span>
            </button>
            <AnimatePresence initial={false}>
              {expandedCat === 'config' && (
                <motion.div initial={false} animate={{ opacity: 1 }} exit={{ opacity: 0 }} transition={{ duration: reduceMotion ? 0 : 0.1 }} className="simple-securecoder-menu__content overflow-hidden">
                  <div className="px-6 pb-4 pt-2 space-y-4">
                    {configLoading ? (
                      <div className="text-[10px] text-[#71717a]">{t('SimpleDashboardPage.runway.loadingConfig')}</div>
                    ) : (
                      <>
                        {configError && (
                          <div className="p-2 bg-[rgba(239,68,68,0.08)] border border-[rgba(239,68,68,0.15)] rounded text-[10px] text-[#ef4444]">{configError}</div>
                        )}
                        {configSuccess && (
                          <div className="p-2 bg-[rgba(34,197,94,0.08)] border border-[rgba(34,197,94,0.15)] rounded text-[10px] text-[#22c55e]">{t('SimpleDashboardPage.runway.configSavedSuccess')}</div>
                        )}
                        
                        {/* Enabled Switch */}
                        <div className="flex items-center justify-between">
                          <label className="text-[11px] text-[#a1a1aa] font-medium">{t('SimpleDashboardPage.runway.enableIntegration')}</label>
                          <input type="checkbox" checked={configEnabled} onChange={e => setConfigEnabled(e.target.checked)} className="accent-[var(--accent-color)] cursor-pointer" />
                        </div>

                        {/* Scanner Backend */}
                        <div className="space-y-1">
                          <label className="text-[10px] text-[#71717a] font-bold uppercase tracking-wider">{t('SimpleDashboardPage.runway.scannerBackend')}</label>
                          <select value={configScannerBackend} onChange={e => setConfigScannerBackend(e.target.value)} className="w-full bg-[rgba(255,255,255,0.02)] border border-[rgba(255,255,255,0.06)] rounded px-3 py-1.5 text-[11px] text-white outline-none focus:border-[var(--accent-color)] cursor-pointer">
                            <option value="semgrep">{t('SimpleDashboardPage.runway.scannerSemgrep')}</option>
                            <option value="wiz">{t('SimpleDashboardPage.runway.scannerWiz')}</option>
                            <option value="aitriage">{t('SimpleDashboardPage.runway.scannerAitriage')}</option>
                          </select>
                        </div>

                        {/* Wiz Authentication Details (Only if Wiz is selected) */}
                        {configScannerBackend === 'wiz' && (
                          <div className="border border-[rgba(255,255,255,0.06)] bg-[rgba(255,255,255,0.015)] rounded-lg p-3 space-y-3">
                            <div className="flex items-center justify-between">
                              <span className="text-[10px] font-bold text-[#71717a] uppercase tracking-wider">{t('SimpleDashboardPage.runway.wizCliAuth')}</span>
                              {wizAuthLoading ? (
                                <span className="text-[9px] text-[#71717a]">{t('SimpleDashboardPage.runway.checking')}</span>
                              ) : wizStatus?.authenticated ? (
                                <span className="px-2 py-0.5 bg-[rgba(34,197,94,0.1)] border border-[rgba(34,197,94,0.2)] text-[#22c55e] text-[9px] font-bold rounded uppercase">{t('SimpleDashboardPage.runway.authorized')}</span>
                              ) : (
                                <span className="px-2 py-0.5 bg-[rgba(239,68,68,0.1)] border border-[rgba(239,68,68,0.2)] text-[#ef4444] text-[9px] font-bold rounded uppercase">{t('SimpleDashboardPage.runway.noAuth')}</span>
                              )}
                            </div>

                            {wizStatus?.authenticated ? (
                              <div className="space-y-2">
                                <div className="text-[10px] text-[#a1a1aa] leading-relaxed">
                                  {t('SimpleDashboardPage.runway.expiresIn', { hours: wizStatus.hoursRemaining })}
                                </div>
                                <button
                                  onClick={handleWizLogout}
                                  className="w-full py-1.5 bg-[rgba(239,68,68,0.08)] hover:bg-[rgba(239,68,68,0.15)] border border-[rgba(239,68,68,0.15)] text-[#ef4444] rounded text-[10px] font-bold uppercase tracking-wider transition-colors cursor-pointer"
                                >
                                  {t('SimpleDashboardPage.runway.disconnectWiz')}
                                </button>
                              </div>
                            ) : (
                              <div className="space-y-2">
                                {wizLoginSession ? (
                                  <div className="space-y-2.5 p-2.5 bg-[rgba(0,0,0,0.3)] border border-[rgba(255,255,255,0.04)] rounded text-[10px]">
                                    {wizLoginSession.status === 'starting' && (
                                      <div className="text-[#a1a1aa] flex items-center gap-2">
                                        <span className="w-2.5 h-2.5 border-2 border-white/20 border-t-white rounded-full animate-spin"></span>
                                        {t('SimpleDashboardPage.runway.initializingCli')}
                                      </div>
                                    )}
                                    {wizLoginSession.status === 'prompt' && (
                                      <div className="space-y-2">
                                        <div className="text-[#e4e4e7] font-semibold text-[10px] uppercase">{t('SimpleDashboardPage.runway.deviceVerificationCode')}</div>
                                        <div className="bg-black/60 border border-white/10 rounded px-3 py-1.5 text-center font-mono text-[14px] text-sky-400 font-bold select-all tracking-wider">
                                          {wizLoginSession.userCode}
                                        </div>
                                        <div className="text-[#71717a] leading-normal text-[10px]">
                                          {t('SimpleDashboardPage.runway.goToAuthPage')}
                                        </div>
                                        <a
                                          href={wizLoginSession.verificationUrl}
                                          target="_blank"
                                          rel="noopener noreferrer"
                                          className="block text-center py-1.5 bg-[var(--accent-color)] hover:bg-[var(--accent-color-hover)] text-[var(--accent-color-on-text)] rounded text-[10px] font-bold uppercase tracking-wider transition-colors"
                                        >
                                          {t('SimpleDashboardPage.runway.openVerificationLink')}
                                        </a>
                                      </div>
                                    )}
                                    {wizLoginSession.status === 'failed' && (
                                      <div className="text-red-400 text-[10px]">
                                        {t('SimpleDashboardPage.runway.errorPrefix')}{wizLoginSession.error || t('SimpleDashboardPage.runway.authAborted')}
                                      </div>
                                    )}
                                    {wizLoginSession.status === 'success' && (
                                      <div className="text-[#22c55e] text-[10px] font-bold">
                                        {t('SimpleDashboardPage.runway.wizCliAuthenticated')}
                                      </div>
                                    )}
                                  </div>
                                ) : (
                                  <button
                                    onClick={handleWizStartLogin}
                                    className="w-full py-1.5 bg-[var(--accent-color)] hover:bg-[var(--accent-color-hover)] text-[var(--accent-color-on-text)] rounded text-[10px] font-bold uppercase tracking-wider transition-colors cursor-pointer"
                                  >
                                    {t('SimpleDashboardPage.runway.authenticateCli')}
                                  </button>
                                )}
                              </div>
                            )}
                          </div>
                        )}

                        {/* Scan Mode / Rule Set */}
                        <div className="space-y-1">
                          <label className="text-[10px] text-[#71717a] font-bold uppercase tracking-wider">{t('SimpleDashboardPage.runway.scanMode')}</label>
                          <select value={configRuleSet} onChange={e => setConfigRuleSet(e.target.value)} className="w-full bg-[rgba(255,255,255,0.02)] border border-[rgba(255,255,255,0.06)] rounded px-3 py-1.5 text-[11px] text-white outline-none focus:border-[var(--accent-color)] cursor-pointer">
                            <option value="fast">{t('SimpleDashboardPage.runway.scanModeFast')}</option>
                            <option value="all">{t('SimpleDashboardPage.runway.scanModeAll')}</option>
                          </select>
                        </div>

                        {/* Ignore Mode */}
                        <div className="space-y-1">
                          <label className="text-[10px] text-[#71717a] font-bold uppercase tracking-wider">{t('SimpleDashboardPage.runway.ignoreMode')}</label>
                          <select value={configIgnoreMode} onChange={e => setConfigIgnoreMode(e.target.value)} className="w-full bg-[rgba(255,255,255,0.02)] border border-[rgba(255,255,255,0.06)] rounded px-3 py-1.5 text-[11px] text-white outline-none focus:border-[var(--accent-color)] cursor-pointer">
                            <option value="workspace">{t('SimpleDashboardPage.runway.ignoreModeWorkspace')}</option>
                            <option value="comment">{t('SimpleDashboardPage.runway.ignoreModeComment')}</option>
                          </select>
                        </div>

                        {/* Autostart Fixes */}
                        <div className="flex items-center justify-between">
                          <label className="text-[11px] text-[#a1a1aa] font-medium">{t('SimpleDashboardPage.runway.autostartFixes')}</label>
                          <input type="checkbox" checked={configAutostartFixes} onChange={e => setConfigAutostartFixes(e.target.checked)} className="accent-[var(--accent-color)] cursor-pointer" />
                        </div>

                        {/* Debug Mode */}
                        <div className="flex items-center justify-between">
                          <label className="text-[11px] text-[#a1a1aa] font-medium">{t('SimpleDashboardPage.runway.debugMode')}</label>
                          <input type="checkbox" checked={configDebug} onChange={e => setConfigDebug(e.target.checked)} className="accent-[var(--accent-color)] cursor-pointer" />
                        </div>

                        <div className="flex gap-2 pt-1">
                          <button
                            onClick={() => {
                              setOnboardingStep(0);
                              setOnboardingOpen(true);
                            }}
                            className="flex-1 px-3 py-2 bg-[rgba(255,255,255,0.03)] border border-[rgba(255,255,255,0.06)] hover:bg-[rgba(255,255,255,0.06)] text-[#f4f4f5] rounded text-[10px] font-bold uppercase tracking-wider transition-colors cursor-pointer flex items-center justify-center gap-1.5"
                          >
                            <span className="material-symbols-outlined text-[12px]">explore</span>
                            {t('SimpleDashboardPage.runway.onboarding')}
                          </button>
                          <button onClick={() => handleSaveConfig()} disabled={configSaving} className="flex-[2] px-4 py-2 bg-[var(--accent-color)] hover:bg-[var(--accent-color-hover)] text-[var(--accent-color-on-text)] rounded text-[10px] font-bold uppercase tracking-wider transition-colors disabled:opacity-50 cursor-pointer">
                            {configSaving ? t('SimpleDashboardPage.runway.saving') : t('SimpleDashboardPage.runway.saveConfiguration')}
                          </button>
                        </div>
                      </>
                    )}
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        </div>
      )}

      {/* ── MODALS ── */}

      {/* Onboarding slideshow modal */}
      <AnimatePresence>
        {onboardingOpen && (
          <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-[100] flex items-center justify-center p-4">
            <motion.div
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              className="bg-[#0e0e11] border border-[rgba(255,255,255,0.08)] rounded-xl w-[480px] p-6 shadow-[0_24px_50px_rgba(0,0,0,0.85)] flex flex-col space-y-4 text-left relative overflow-hidden"
            >
              {/* Step indicator */}
              <div className="flex justify-between items-center text-[10px] font-bold text-[#71717a] tracking-wider uppercase">
                <span>{t('SimpleDashboardPage.runway.setupTitle')}</span>
                <span>{t('SimpleDashboardPage.runway.setupStepIndicator', { current: onboardingStep + 1, total: 4 })}</span>
              </div>

              {/* Step 0: Welcome */}
              {onboardingStep === 0 && (
                <div className="space-y-3">
                  <div className="w-10 h-10 rounded-lg bg-[rgba(255,255,255,0.03)] border border-[rgba(255,255,255,0.06)] flex items-center justify-center text-sky-400">
                    <span className="material-symbols-outlined text-[24px]">shield</span>
                  </div>
                  <h3 className="text-[14px] font-bold text-white uppercase tracking-wider">{t('SimpleDashboardPage.runway.setupWelcomeTitle')}</h3>
                  <p className="text-[11px] text-[#a1a1aa] leading-relaxed">
                    {t('SimpleDashboardPage.runway.setupWelcomeDesc')}
                  </p>
                </div>
              )}

              {/* Step 1: How it Works */}
              {onboardingStep === 1 && (
                <div className="space-y-3">
                  <h3 className="text-[14px] font-bold text-white uppercase tracking-wider">{t('SimpleDashboardPage.runway.setupFeaturesTitle')}</h3>
                  <div className="space-y-2 text-[11px] text-[#a1a1aa]">
                    <div className="flex items-start gap-2.5">
                      <span className="material-symbols-outlined text-[14px] text-sky-400 mt-0.5">bolt</span>
                      <div>
                        <strong className="text-white">{t('SimpleDashboardPage.runway.setupFeatureRunwayTitle')}</strong> {t('SimpleDashboardPage.runway.setupFeatureRunwayDesc')}
                      </div>
                    </div>
                    <div className="flex items-start gap-2.5">
                      <span className="material-symbols-outlined text-[14px] text-sky-400 mt-0.5">package_2</span>
                      <div>
                        <strong className="text-white">{t('SimpleDashboardPage.runway.setupFeatureDepTitle')}</strong> {t('SimpleDashboardPage.runway.setupFeatureDepDesc')}
                      </div>
                    </div>
                    <div className="flex items-start gap-2.5">
                      <span className="material-symbols-outlined text-[14px] text-sky-400 mt-0.5">sync</span>
                      <div>
                        <strong className="text-white">{t('SimpleDashboardPage.runway.setupFeatureIdeTitle')}</strong> {t('SimpleDashboardPage.runway.setupFeatureIdeDesc')}
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {/* Step 2: Scanner Configuration */}
              {onboardingStep === 2 && (
                <div className="space-y-3">
                  <h3 className="text-[14px] font-bold text-white uppercase tracking-wider">{t('SimpleDashboardPage.runway.setupScannerBackendTitle')}</h3>
                  <p className="text-[11px] text-[#71717a]">
                    {t('SimpleDashboardPage.runway.setupScannerBackendDesc')}
                  </p>
                  <div className="space-y-2">
                    <div
                      onClick={() => setConfigScannerBackend('semgrep')}
                      className={`p-3 rounded-lg border cursor-pointer transition-colors flex items-center justify-between ${
                        configScannerBackend === 'semgrep'
                          ? 'bg-[rgba(255,255,255,0.03)] border-[var(--accent-color)] text-white'
                          : 'bg-transparent border-[rgba(255,255,255,0.06)] text-[#a1a1aa] hover:border-[rgba(255,255,255,0.12)]'
                      }`}
                    >
                      <div className="text-left">
                        <div className="text-[11px] font-bold uppercase tracking-wider">{t('SimpleDashboardPage.runway.scannerSemgrep')}</div>
                        <div className="text-[10px] text-[#71717a] mt-0.5">{t('SimpleDashboardPage.runway.setupSemgrepDesc')}</div>
                      </div>
                      {configScannerBackend === 'semgrep' && <span className="material-symbols-outlined text-[16px] text-[var(--accent-color)]">check_circle</span>}
                    </div>

                    <div
                      onClick={() => setConfigScannerBackend('wiz')}
                      className={`p-3 rounded-lg border cursor-pointer transition-colors flex items-center justify-between ${
                        configScannerBackend === 'wiz'
                          ? 'bg-[rgba(255,255,255,0.03)] border-[var(--accent-color)] text-white'
                          : 'bg-transparent border-[rgba(255,255,255,0.06)] text-[#a1a1aa] hover:border-[rgba(255,255,255,0.12)]'
                      }`}
                    >
                      <div className="text-left">
                        <div className="text-[11px] font-bold uppercase tracking-wider flex items-center gap-1.5">
                          {t('SimpleDashboardPage.runway.setupWizTitle')}
                          <span className="px-1.5 py-0.5 bg-sky-950 border border-sky-800 text-sky-400 text-[8px] font-bold rounded uppercase">{t('SimpleDashboardPage.runway.setupWizTag')}</span>
                        </div>
                        <div className="text-[10px] text-[#71717a] mt-0.5">{t('SimpleDashboardPage.runway.setupWizDesc')}</div>
                      </div>
                      {configScannerBackend === 'wiz' && <span className="material-symbols-outlined text-[16px] text-[var(--accent-color)]">check_circle</span>}
                    </div>
                  </div>

                  {configScannerBackend === 'wiz' && (
                    <div className="flex items-start gap-2 pt-1">
                      <input
                        type="checkbox"
                        id="wiz-agreement"
                        checked={wizAgreementChecked}
                        onChange={e => setWizAgreementChecked(e.target.checked)}
                        className="mt-0.5 accent-[var(--accent-color)] cursor-pointer"
                      />
                      <label htmlFor="wiz-agreement" className="text-[9px] text-[#71717a] leading-normal cursor-pointer select-none">
                        {t('SimpleDashboardPage.runway.setupWizAgreement')}
                      </label>
                    </div>
                  )}
                </div>
              )}

              {/* Step 3: Ignore patterns setup */}
              {onboardingStep === 3 && (
                <div className="space-y-3">
                  <h3 className="text-[14px] font-bold text-white uppercase tracking-wider">{t('SimpleDashboardPage.runway.setupIgnoreTitle')}</h3>
                  <p className="text-[11px] text-[#71717a]">
                    {t('SimpleDashboardPage.runway.setupIgnoreDesc')}
                  </p>
                  <textarea
                    value={onboardingIgnoreContent}
                    onChange={e => setOnboardingIgnoreContent(e.target.value)}
                    className="bg-[#08080a] border border-[rgba(255,255,255,0.06)] rounded p-3 text-[11px] text-[#e4e4e7] font-mono outline-none focus:border-[var(--accent-color)] w-full h-32 resize-none"
                    style={{ scrollbarWidth: 'thin', scrollbarColor: 'rgba(255,255,255,0.06) transparent' }}
                  />
                </div>
              )}

              {/* Navigation controls */}
              <div className="flex justify-between items-center pt-2 border-t border-[rgba(255,255,255,0.06)]">
                <button
                  onClick={() => setOnboardingOpen(false)}
                  className="px-3.5 py-1.5 bg-[rgba(255,255,255,0.02)] border border-[rgba(255,255,255,0.06)] hover:bg-[rgba(255,255,255,0.05)] text-[#a1a1aa] hover:text-white rounded-lg text-[10px] font-bold uppercase tracking-wider transition-colors cursor-pointer"
                >
                  {t('SimpleDashboardPage.runway.cancel')}
                </button>
                <div className="flex gap-2">
                  {onboardingStep > 0 && (
                    <button
                      onClick={() => setOnboardingStep(prev => prev - 1)}
                      className="px-3.5 py-1.5 bg-[rgba(255,255,255,0.02)] border border-[rgba(255,255,255,0.06)] hover:bg-[rgba(255,255,255,0.05)] text-[#f4f4f5] rounded-lg text-[10px] font-bold uppercase tracking-wider transition-colors cursor-pointer"
                    >
                      {t('SimpleDashboardPage.runway.back')}
                    </button>
                  )}
                  {onboardingStep < 3 ? (
                    <button
                      onClick={() => {
                        if (onboardingStep === 2 && configScannerBackend === 'wiz' && !wizAgreementChecked) {
                          alert(t('SimpleDashboardPage.runway.setupWizAgreementAlert'));
                          return;
                        }
                        setOnboardingStep(prev => prev + 1);
                      }}
                      className="px-4 py-1.5 bg-[var(--accent-color)] hover:bg-[var(--accent-color-hover)] text-[var(--accent-color-on-text)] rounded-lg text-[10px] font-bold uppercase tracking-wider transition-colors cursor-pointer"
                    >
                      {t('SimpleDashboardPage.runway.next')}
                    </button>
                  ) : (
                    <button
                      onClick={async () => {
                        await handleSaveIgnoreFile(onboardingIgnoreContent);
                        await handleSaveConfig({
                          enabled: true,
                          scannerBackend: configScannerBackend,
                          ruleSet: configRuleSet,
                          autostartFixes: configAutostartFixes,
                          ignoreMode: configIgnoreMode,
                          debug: configDebug
                        });
                        setOnboardingOpen(false);
                      }}
                      className="px-4 py-1.5 bg-[#22c55e] hover:bg-[#16a34a] text-white rounded-lg text-[10px] font-bold uppercase tracking-wider transition-colors cursor-pointer"
                    >
                      {t('SimpleDashboardPage.runway.finishAndSave')}
                    </button>
                  )}
                </div>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

      {/* Ignore File Editor Modal */}
      <AnimatePresence>
        {ignoreEditorOpen && (
          <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-[100] flex items-center justify-center p-4">
            <motion.div
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              className="bg-[#0e0e11] border border-[rgba(255,255,255,0.08)] rounded-xl w-[500px] p-6 shadow-[0_24px_50px_rgba(0,0,0,0.85)] flex flex-col space-y-4 text-left relative overflow-hidden"
            >
              <div className="flex justify-between items-center">
                <h3 className="text-[12px] font-bold text-white uppercase tracking-wider">{t('SimpleDashboardPage.runway.editIgnoreTitle')}</h3>
                <span className="px-2 py-0.5 bg-zinc-900 border border-zinc-800 text-zinc-500 text-[8px] font-bold rounded uppercase">{t('SimpleDashboardPage.runway.workspaceIgnoreTag')}</span>
              </div>
              <p className="text-[11px] text-[#71717a] leading-normal">
                {t('SimpleDashboardPage.runway.editIgnoreDesc')}
              </p>
              <textarea
                value={ignoreEditorContent}
                onChange={e => setIgnoreEditorContent(e.target.value)}
                className="bg-[#08080a] border border-[rgba(255,255,255,0.06)] rounded p-3.5 text-[11px] text-[#e4e4e7] font-mono outline-none focus:border-[var(--accent-color)] w-full h-48 resize-none"
                style={{ scrollbarWidth: 'thin', scrollbarColor: 'rgba(255,255,255,0.06) transparent' }}
              />
              <div className="flex justify-end gap-2 pt-2 border-t border-[rgba(255,255,255,0.06)]">
                <button
                  onClick={() => setIgnoreEditorOpen(false)}
                  className="px-4 py-1.5 bg-[rgba(255,255,255,0.02)] border border-[rgba(255,255,255,0.06)] hover:bg-[rgba(255,255,255,0.05)] text-[#a1a1aa] hover:text-white rounded-lg text-[10px] font-bold uppercase tracking-wider transition-colors cursor-pointer"
                >
                  {t('SimpleDashboardPage.runway.cancel')}
                </button>
                <button
                  onClick={async () => {
                    await handleSaveIgnoreFile(ignoreEditorContent);
                    setIgnoreEditorOpen(false);
                  }}
                  disabled={ignoreEditorSaving}
                  className="px-4 py-1.5 bg-[var(--accent-color)] hover:bg-[var(--accent-color-hover)] text-[var(--accent-color-on-text)] rounded-lg text-[10px] font-bold uppercase tracking-wider transition-colors disabled:opacity-50 cursor-pointer"
                >
                  {ignoreEditorSaving ? t('SimpleDashboardPage.runway.saving') : t('SimpleDashboardPage.runway.saveIgnoreFile')}
                </button>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>
    </div>
  );
};


const itemVariants = {
  hidden: { opacity: 0, y: 15 },
  visible: {
    opacity: 1,
    y: 0,
    transition: {
      type: "spring" as const,
      stiffness: 260,
      damping: 25
    }
  }
};

const sevDot = (sev: string) => {
  switch (sev?.toLowerCase()) {
    case 'critical': return '#d96873';
    case 'high': return '#d88a5b';
    case 'medium': return '#c7a84f';
    case 'low': return '#777c85';
    default: return '#777c85';
  }
};

const FindingRow: React.FC<{
  f: Finding;
  isExpanded: boolean;
  onToggle: () => void;
  productMap: Map<number, Product>;
  setProductFilter: (id: number) => void;
  handleTriage: (f: Finding, action: string) => void;
  onNavigateToChat?: (f: Finding) => void;
  onRefresh?: (options?: { silent?: boolean }) => void;
  isSelected?: boolean;
  onToggleSelect?: (e: React.MouseEvent | React.ChangeEvent) => void;
  isTriaging?: boolean;
  aiAvailable?: boolean;
}> = ({ f, isExpanded, onToggle, productMap, setProductFilter, handleTriage, onNavigateToChat, onRefresh, isSelected, onToggleSelect, isTriaging, aiAvailable }) => {
  const { t, i18n } = useTranslation('pages');
  const reduceMotion = useReducedMotion();
  const [agentPrompt, setAgentPrompt] = useState(f.agent_prompt ?? '');
  const [verificationSummary, setVerificationSummary] = useState(f.verification_summary ?? '');
  const [agentPromptLoading, setAgentPromptLoading] = useState(false);
  const [verificationLoading, setVerificationLoading] = useState(false);
  const [copiedContext, setCopiedContext] = useState(false);
  const [actionError, setActionError] = useState('');

  useEffect(() => {
    setAgentPrompt(f.agent_prompt ?? '');
    setVerificationSummary(f.verification_summary ?? '');
  }, [f.id, f.agent_prompt, f.verification_summary]);

  const currentStatus = f.status || 'open';
  const lifecycleStatus =
    currentStatus !== 'open'
      ? currentStatus
      : f.verification_status === 'fixed'
        ? 'resolved'
        : f.verification_status === 'not_fixed'
          ? 'verification_failed'
          : currentStatus;
  const shouldShowVerificationSummary =
    Boolean(verificationSummary) &&
    (verificationLoading || f.verification_status === 'error' || ['verification_failed', 'resolved', 'fixed'].includes(lifecycleStatus.toLowerCase()));

  const statusLabel = (status: string) => {
    const s = status.toLowerCase();
    if (s === 'sent_to_agent') return t('status_sent_to_agent');
    if (s === 'pending_verification') return t('status_pending_verification');
    if (s === 'verification_failed') return t('status_verification_failed');
    if (['resolved', 'fixed', 'closed', 'mitigated'].includes(s)) return t('status_fixed');
    if (['verified', 'confirmed', 'true_positive'].includes(s)) return t('review.confirmed');
    if (s === 'in_progress') return t('review.inProgress');
    if (s === 'triage') return t('statusTriage');
    if (s === 'false_positive') return t('statusFalsePositive');
    if (s === 'risk_accepted' || s === 'accepted_risk') return t('statusAccepted');
    return t('statusOpen');
  };

  const statusClass = (status: string) => {
    const s = status.toLowerCase();
    if (['resolved', 'fixed', 'closed', 'mitigated'].includes(s)) return 'text-[#22c55e] bg-[rgba(34,197,94,0.08)] border-[rgba(34,197,94,0.18)]';
    if (s === 'verification_failed') return 'text-[#ef4444] bg-[rgba(239,68,68,0.08)] border-[rgba(239,68,68,0.18)]';
    if (s === 'pending_verification') return 'text-[#eab308] bg-[rgba(234,179,8,0.08)] border-[rgba(234,179,8,0.18)]';
    if (s === 'sent_to_agent' || s === 'triage') return 'text-[#38bdf8] bg-[rgba(56,189,248,0.08)] border-[rgba(56,189,248,0.18)]';
    if (s === 'false_positive') return 'text-[#71717a] bg-[rgba(255,255,255,0.02)] border-[rgba(255,255,255,0.04)]';
    return 'text-[#f59e0b] bg-[rgba(245,158,11,0.06)] border-[rgba(245,158,11,0.12)]';
  };

  const normalizedSeverity = (f.severity || 'low').toLowerCase();
  const severityLabel = normalizedSeverity === 'critical'
    ? t('severityCritical')
    : normalizedSeverity === 'high'
      ? t('severityHigh')
      : normalizedSeverity === 'medium'
        ? t('severityMedium')
        : normalizedSeverity === 'low'
          ? t('severityLow')
          : f.severity;
  const project = f.product_id ? productMap.get(f.product_id) : undefined;
  const findingPath = f.file_path || f.file;

  const generateAgentPrompt = async (event: React.MouseEvent) => {
    event.stopPropagation();
    if (agentPromptLoading) return;
    setActionError('');
    setAgentPromptLoading(true);
    try {
      const res = await fetch(`/api/findings/${f.id}/agent-prompt`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      });
      const data = await res.json();
      if (!res.ok || !data.ok) throw new Error(data.error || 'Failed to generate agent prompt');
      const prompt = data.prompt || '';
      setAgentPrompt(prompt);
      setVerificationSummary('');
      try {
        await navigator.clipboard.writeText(prompt);
      } catch {
        // Prompt remains visible for manual copy when clipboard is unavailable.
      }
      onRefresh?.({ silent: true });
    } catch (err) {
      console.error(err);
      setActionError(err instanceof Error ? err.message : t('review.actionFailed'));
    } finally {
      setAgentPromptLoading(false);
    }
  };

  const verifyFinding = async (event: React.MouseEvent) => {
    event.stopPropagation();
    if (verificationLoading) return;
    setActionError('');
    setVerificationLoading(true);
    setVerificationSummary(t('verification_running'));
    try {
      const res = await fetch(`/api/findings/${f.id}/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      });
      const data = await res.json();
      if (!res.ok || !data.ok) throw new Error(data.error || 'Failed to verify finding');
      setVerificationSummary(data.summary || '');
      onRefresh?.({ silent: true });
    } catch (err) {
      console.error(err);
      setActionError(err instanceof Error ? err.message : t('review.actionFailed'));
      setVerificationSummary('');
    } finally {
      setVerificationLoading(false);
    }
  };
  
  return (
    <article className={`simple-finding ${isExpanded ? 'simple-finding--expanded' : ''}`}>
      <div
        className="simple-finding-row"
        onClick={onToggle}
      >
        {onToggleSelect && (
          <input
            type="checkbox"
            checked={isSelected || false}
            onChange={onToggleSelect}
            onClick={e => e.stopPropagation()}
            aria-label={i18n.language?.startsWith('ru') ? `Выбрать ${f.title}` : `Select ${f.title}`}
            className="simple-finding-row__checkbox accent-[var(--accent-color)] cursor-pointer select-checkbox file-checkbox"
          />
        )}
        <div className={`simple-finding-row__severity simple-finding-row__severity--${normalizedSeverity}`}>
          <span style={{ backgroundColor: sevDot(normalizedSeverity) }} aria-hidden="true" />
          <strong>{severityLabel}</strong>
        </div>

        <button onClick={(event) => { event.stopPropagation(); onToggle(); }} className="simple-finding-row__title" aria-expanded={isExpanded}>
          <strong>{f.title}</strong>
          {f.ai_triage_status && <small>AI: {f.ai_triage_status.replace('_', ' ')}</small>}
        </button>

        <div className="simple-finding-row__product">
          {project ? (
            <button onClick={(event) => { event.stopPropagation(); setProductFilter(project.id); }} title={`${t('groupProject')}: ${project.name}`}>{project.name}</button>
          ) : (
            <span>{t('allProjects')}</span>
          )}
          {f.stack && <small>{f.stack}</small>}
        </div>

        <button onClick={(event) => { event.stopPropagation(); onToggle(); }} className="simple-finding-row__path" aria-expanded={isExpanded}>
          <span>{findingPath || (i18n.language?.startsWith('ru') ? 'Путь не указан' : 'No file path')}</span>
          {f.line_number && <small>{i18n.language?.startsWith('ru') ? 'строка' : 'line'} {f.line_number}</small>}
        </button>

        <div className="simple-finding-row__status">
          <span className={`border ${statusClass(lifecycleStatus)}`}>{statusLabel(lifecycleStatus)}</span>
        </div>

        <button
          onClick={(event) => { event.stopPropagation(); onToggle(); }}
          className="simple-finding-row__disclosure"
          aria-label={isExpanded
            ? (i18n.language?.startsWith('ru') ? 'Свернуть находку' : 'Collapse finding')
            : (i18n.language?.startsWith('ru') ? 'Развернуть находку' : 'Expand finding')}
          aria-expanded={isExpanded}
        >
          <span className="material-symbols-outlined" aria-hidden="true">expand_more</span>
        </button>
      </div>
      
      <AnimatePresence initial={false}>
        {isExpanded && (
          <motion.div
            key="details"
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={reduceMotion ? { duration: 0 } : { duration: 0.18, ease: [0.23, 1, 0.32, 1] }}
            className="simple-finding-details overflow-hidden"
          >
            <div className="simple-finding-details__body px-4 pb-4 pt-1.5 space-y-3">
              <div className="simple-finding-details__meta flex items-center gap-2 flex-wrap">
                <span className="text-[9px] px-2 py-0.5 rounded font-mono font-bold uppercase border" 
                  style={{ 
                    color: sevDot(f.severity), 
                    backgroundColor: `${sevDot(f.severity)}08`,
                    borderColor: `${sevDot(f.severity)}1a`
                  }}
                >
                  {f.severity}
                </span>
                {f.file_path && <span className="text-[10px] font-mono truncate">{f.file_path}{f.line_number ? `:${f.line_number}` : ''}</span>}
              </div>
              
              <div className="finding-rule-meta"><span>{t('review.rule')}: <code>{f.rule_id || '—'}</code></span><span>{t('review.scanner')}: {f.stack || 'core'}</span>{f.cwe_id && <span>{f.cwe_id}</span>}{f.cve_id && <span>{f.cve_id}</span>}</div>
              {f.description && (
                <div><h4 className="review-heading">{t('review.why')}</h4><p className="simple-finding-details__description text-[12px] leading-relaxed select-text">
                  {f.description}
                </p></div>
              )}
              
              {f.impact && <div><h4 className="review-heading">{t('review.impact')}</h4><p className="review-help">{f.impact}</p></div>}
              {f.verification_last_run_at && <p className="finding-verification-time">
                {t('review.verificationAttempt')}: <time dateTime={f.verification_last_run_at}>{formatResultTime(f.verification_last_run_at, i18n.language) || t('review.noTimestamp')}</time>
                {f.verification_status && <span>{t(({ fixed: 'review.verificationFixed', not_fixed: 'review.verificationPresent', error: 'review.verificationError', running: 'review.verificationRunning' } as Record<string, string>)[f.verification_status] || 'review.verificationAttempt')}</span>}
              </p>}
              <FindingEvidence finding={f} />
              {(f.fix_suggestion || f.suggestion) && (
                <div className="simple-finding-details__guidance text-[12px] leading-relaxed pl-3 my-2 select-text font-mono p-3 rounded-r-md">
                  <span className="text-[9px] text-[#52525b] uppercase tracking-wider block mb-1 font-bold">{t('review.remediation')}</span>
                  {f.fix_suggestion || f.suggestion}
                </div>
              )}

              <div className="review-actions">
                <button type="button" className="review-primary" onClick={verifyFinding} disabled={verificationLoading || isTriaging}>
                  <span className="material-symbols-outlined" aria-hidden="true">fact_check</span>
                  {verificationLoading ? t('verification_running_short') : t('review.rescan')}
                </button>
                {isActive(f) ? <>
                  <button type="button" disabled={isTriaging || verificationLoading || ['confirmed', 'verified', 'true_positive'].includes(f.status)} onClick={() => handleTriage(f, 'confirmed')}>{t('review.confirm')}</button>
                  <button type="button" disabled={isTriaging || verificationLoading} onClick={() => handleTriage(f, 'false_positive')}>{t('review.falsePositive')}</button>
                  <button type="button" disabled={isTriaging || verificationLoading} onClick={() => handleTriage(f, 'risk_accepted')}>{t('review.acceptRisk')}</button>
                </> : <button type="button" disabled={isTriaging || verificationLoading} onClick={() => handleTriage(f, 'open')}>{t('review.reopen')}</button>}
                <button type="button" onClick={async () => {
                  try {
                    await navigator.clipboard.writeText([f.title, f.rule_id, f.severity, `${findingPath || ''}:${f.line_number || ''}`, f.description, f.impact, f.fix_suggestion || f.suggestion, f.code_snippet].filter(Boolean).join('\n'));
                    setCopiedContext(true);
                    setTimeout(() => setCopiedContext(false), 1500);
                  } catch { setActionError(t('review.copyFailed')); }
                }}>{copiedContext ? t('review.copied') : t('review.copy')}</button>
              </div>
              <p className="review-help">{t('verification_rescan_hint')}</p>
              {actionError && <p role="alert" className="review-error">{actionError}</p>}
              {shouldShowVerificationSummary && <p role="status" className="review-result">{verificationSummary}</p>}
              <details className="finding-ai-tools">
                <summary>{t('review.aiTools')}</summary>
                {f.ai_triage_summary && <div><h4 className="review-heading">{t('review.aiConclusion')}</h4><p className="review-help">{f.ai_triage_summary}</p></div>}
                <div className="review-actions">
                  <button type="button" onClick={generateAgentPrompt} disabled={agentPromptLoading}>{agentPromptLoading ? t('review.preparing') : t('agent_prompt')}</button>
                  <button type="button" disabled={!aiAvailable || isTriaging} onClick={() => handleTriage(f, 'triage')}>{isTriaging ? t('review.analyzing') : t('review.aiTriage')}</button>
                  {onNavigateToChat && <button type="button" disabled={!aiAvailable} onClick={() => onNavigateToChat(f)}>{t('review.askAi')}</button>}
                </div>
                {!aiAvailable && <p className="review-help">{t('review.aiUnavailable')}</p>}
                {agentPrompt && <textarea aria-label={t('agent_prompt')} className="review-prompt" value={agentPrompt} readOnly />}
              </details>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </article>
  );
};

export const SimpleDashboardPage: React.FC<SimpleDashboardPageProps> = ({ onNavigateToChat, onNavigateToReports }) => {
  const dashboardQuery = useDashboardQuery();
  const { productFilter, setProductFilter, expandedIds, setExpandedIds, activeFilter, statusFilter, searchQuery, groupBy, sortBy, requestedPage, setPage, scopeType, activeFilePath, clearFilters, showHistory } = dashboardQuery;
  const { t, i18n } = useTranslation('pages');
  const reduceMotion = useReducedMotion();
  const { findings, loading: findingsLoading, error: findingsError, refresh: refreshFindings } = useFindings();
  const { metrics, loading: metricsLoading, error: metricsError, refresh: refreshMetrics } = useMetrics(productFilter ?? undefined);
  const { products, loading: productsLoading, error: productsError, refresh: refreshProducts } = useProducts();

  const [collapsedGroups, setCollapsedGroups] = useState<Set<string>>(new Set());
  const [aiSummary, setAiSummary] = useState<string>('');
  const [aiSummaryLoading, setAiSummaryLoading] = useState(false);
  const [aiSummaryProjectId, setAiSummaryProjectId] = useState<number | null>(null);
  const [aiSummaryLang, setAiSummaryLang] = useState<'en' | 'ru'>(i18n.language.startsWith('ru') ? 'ru' : 'en');
  const [aiSummaryLocale, setAiSummaryLocale] = useState<'en' | 'ru'>(aiSummaryLang);
  const [isAiSummaryExpanded, setIsAiSummaryExpanded] = useState(false);
  const [, setToolStatus] = useState<Record<string, boolean>>({});
  // Scanning, scoring, the gate and every report format work without a provider.
  // Only triage and the written narrative need one, so the UI says which half is
  // available instead of letting the user find out by pressing a button.
  const [aiAvailable, setAiAvailable] = useState<boolean | null>(null);

  useEffect(() => {
    fetch('/api/health').then(r => r.json()).then(d => {
      if (d.ok && d.tools) setToolStatus(d.tools);
      if (d.ok && typeof d.ai_available === 'boolean') setAiAvailable(d.ai_available);
    }).catch(() => {});
  }, []);

  // SecureCoder Bulk Selection & Active File Scope State
  const [selectedFindings, setSelectedFindings] = useState<Set<number>>(new Set());
  const [bulkIgnoreModalOpen, setBulkIgnoreModalOpen] = useState(false);
  const [bulkIgnoreReason, setBulkIgnoreReason] = useState('False Positive');
  const [bulkIgnoring, setBulkIgnoring] = useState(false);
  const [bulkFixCopied, setBulkFixCopied] = useState(false);
  const [bulkVerifying, setBulkVerifying] = useState(false);
  const [bulkVerificationResult, setBulkVerificationResult] = useState('');
  const handleBulkVerify = async () => {
    if (bulkVerifying || bulkIgnoring) return;
    const selected = findings.filter(finding => selectedFindings.has(finding.id));
    setBulkVerifying(true); setBulkVerificationResult('');
    const processed = new Set<number>();
    const failedIds = new Set<number>();
    let fixed = 0, present = 0;
    try {
      for (let offset = 0; offset < selected.length; offset += 100) {
        const batch = selected.slice(offset, offset + 100);
        const response = await fetch('/api/findings/verify-bulk', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ids: batch.map(finding => finding.id) }) });
        const data = await response.json();
        if (!response.ok || !data.ok || !Array.isArray(data.results)) throw new Error(data.error || t('review.actionFailed'));
        const results = new Map<number, { id: number; error?: string; fixed: boolean }>(data.results.map((result: { id: number; error?: string; fixed: boolean }) => [result.id, result]));
        for (const finding of batch) {
          const result = results.get(finding.id);
          processed.add(finding.id);
          if (!result || result.error) failedIds.add(finding.id);
          else if (result.fixed) fixed++;
          else present++;
        }
        setBulkVerificationResult(`${processed.size}/${selected.length}`);
      }
    } catch {
      for (const finding of selected) if (!processed.has(finding.id)) failedIds.add(finding.id);
    }
    setBulkVerificationResult(i18n.language?.startsWith('ru')
      ? `Исправлено: ${fixed}; осталось: ${present}; ошибок: ${failedIds.size}`
      : `Fixed: ${fixed}; still present: ${present}; errors: ${failedIds.size}`);
    await Promise.all([refreshFindings({ silent: true }), refreshMetrics({ silent: true })]);
    setBulkVerifying(false);
    setSelectedFindings(previous => { const next = new Set(previous); for (const finding of selected) if (!failedIds.has(finding.id)) next.delete(finding.id); return next; });
  };

  const handleBulkIgnore = async () => {
    setBulkIgnoring(true);
    setStatusActionError('');
    const failed = new Set<number>();
    for (const finding of findings.filter(finding => selectedFindings.has(finding.id))) {
      try {
        const response = await fetch(`/api/findings/${finding.id}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ action: 'status', status: bulkIgnoreReason === 'False Positive' ? 'false_positive' : 'risk_accepted' }) });
        const data = await response.json();
        if (!response.ok || !data.ok) failed.add(finding.id);
      } catch { failed.add(finding.id); }
    }
    setSelectedFindings(failed);
    setBulkIgnoreModalOpen(false);
    if (failed.size) setStatusActionError(t('review.bulkFailed', { count: failed.size }));
    refreshFindings({ silent: true }); refreshMetrics({ silent: true });
    setBulkIgnoring(false);
  };

  const handleBulkFix = async () => {
    const selectedObjects = findings.filter(f => selectedFindings.has(f.id));
    if (selectedObjects.length === 0) return;

    let prompt = `Fix these security vulnerabilities in my code:\n\n`;
    selectedObjects.forEach((f, idx) => {
      prompt += `### Finding #${idx + 1}: ${f.title}\n`;
      prompt += `- **Severity:** ${f.severity?.toUpperCase()}\n`;
      prompt += `- **File:** ${f.file_path || 'unknown'}${f.line_number ? `:${f.line_number}` : ''}\n`;
      prompt += `- **Scanner:** ${f.stack || 'core'}\n`;
      prompt += `- **Description:** ${f.description || 'No description'}\n`;
      if (f.code_snippet) {
        prompt += `- **Code Snippet:**\n\`\`\`\n${f.code_snippet}\n\`\`\`\n`;
      }
      if (f.fix_suggestion || f.suggestion) {
        prompt += `- **Recommendation:** ${f.fix_suggestion || f.suggestion}\n`;
      }
      prompt += `\n`;
    });

    prompt += `Please perform a root-cause analysis for each finding and generate targeted before/after code patches and PoC verification guides according to the SecureCoder guidelines.`;

    try {
      await navigator.clipboard.writeText(prompt);
      setBulkFixCopied(true);
      setTimeout(() => setBulkFixCopied(false), 2000);
    } catch { setStatusActionError(t('review.copyFailed')); }
  };

  const [isProjectsPanelOpen, setIsProjectsPanelOpen] = useState(() => {
    try {
      return localStorage.getItem('projects_panel_open') === 'true';
    } catch {
      return false;
    }
  });
  const projectsTriggerRef = useRef<HTMLButtonElement>(null);
  const projectsDrawerRef = useRef<HTMLElement>(null);
  const [isSecureCoderOpen, setIsSecureCoderOpen] = useState(false);
  const secureCoderTriggerRef = useRef<HTMLButtonElement>(null);
  const secureCoderDrawerRef = useRef<HTMLElement>(null);

  const closeProjectsPanel = useCallback(() => {
    setIsProjectsPanelOpen(false);
    try {
      localStorage.setItem('projects_panel_open', 'false');
    } catch {
      // The drawer remains functional when storage is unavailable.
    }
    window.requestAnimationFrame(() => projectsTriggerRef.current?.focus());
  }, []);

  const handleToggleProjectsPanel = useCallback(() => {
    setIsProjectsPanelOpen((prev) => {
      const next = !prev;
      try {
        localStorage.setItem('projects_panel_open', String(next));
      } catch {
        // The drawer remains functional when storage is unavailable.
      }
      return next;
    });
  }, []);

  const closeSecureCoder = useCallback(() => {
    setIsSecureCoderOpen(false);
    window.requestAnimationFrame(() => secureCoderTriggerRef.current?.focus());
  }, []);

  useEffect(() => {
    if (!isProjectsPanelOpen && !isSecureCoderOpen) return;
    const activeDrawer = isSecureCoderOpen ? secureCoderDrawerRef.current : projectsDrawerRef.current;
    const closeActiveDrawer = isSecureCoderOpen ? closeSecureCoder : closeProjectsPanel;
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        closeActiveDrawer();
        return;
      }
      if (event.key !== 'Tab' || !activeDrawer) return;
      const focusable = Array.from(activeDrawer.querySelectorAll<HTMLElement>(
        'button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [href], [tabindex]:not([tabindex="-1"])'
      ));
      if (focusable.length === 0) return;
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };
    window.requestAnimationFrame(() => activeDrawer?.focus());
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [closeProjectsPanel, closeSecureCoder, isProjectsPanelOpen, isSecureCoderOpen]);

  // Build product map for quick lookup
  const productMap = useMemo(() => {
    const m = new Map<number, Product>();
    products?.forEach(p => m.set(p.id, p));
    return m;
  }, [products]);

  // Include scanned projects even when they have no findings.
  const activeProducts = useMemo(() => {
    return products || [];
  }, [products]);

  // Load the latest persisted AI summary so it survives page refreshes.
  useEffect(() => {
    const targetId = productFilter;
    if (!targetId) return;
    let cancelled = false;
    securityService.getAISummary(targetId, aiSummaryLang, false)
      .then(stored => {
        if (cancelled || !stored) return;
        setAiSummaryLocale(aiSummaryLang);
        setAiSummary(stored);
        setAiSummaryProjectId(targetId);
      })
      .catch(() => { /* No persisted summary yet. */ });
    return () => { cancelled = true; };
  }, [productFilter, aiSummaryLang]);

  const loading = findingsLoading || productsLoading;
  const pageError = findingsError || metricsError || productsError;

  const closedStatuses = terminalStatuses;

  const sevCounts = useMemo(() => {
    const c = { critical: 0, high: 0, medium: 0, low: 0 };
    findings?.forEach((f: Finding) => {
      if (productFilter !== null && f.product_id !== productFilter) return;
      // Exclude resolved/closed findings — match backend metrics query
      const st = (f.status || 'open').toLowerCase();
      if (closedStatuses.includes(st)) return;
      const s = f.severity?.toLowerCase();
      if (s === 'critical') c.critical++;
      else if (s === 'high') c.high++;
      else if (s === 'medium') c.medium++;
      else c.low++;
    });
    return c;
  }, [findings, productFilter]);

  const score = useMemo(() => {
    return metrics?.security_score ?? 0;
  }, [metrics]);


  // A scanner finding is a hypothesis until someone confirms it. Showing the two
  // apart is what makes a failing gate legible: "0 confirmed, 25 unreviewed"
  // explains itself, where "25 active findings" next to "0 true positives" reads
  // as a contradiction.
  const triageCounts = useMemo(() => {
    const counts = { confirmed: 0, needsReview: 0, suppressed: 0, resolved: 0 };
    findings?.forEach((f: Finding) => {
      if (productFilter !== null && f.product_id !== productFilter) return;
      const status = (f.status || 'open').toLowerCase();
      if (isResolved(f)) {
        counts.resolved++;
      } else if (isSuppressed(f)) {
        counts.suppressed++;
      } else if (f.ai_triage_status === 'true_positive' || f.is_verified || ['verified', 'confirmed', 'true_positive'].includes(status)) {
        counts.confirmed++;
      } else {
        counts.needsReview++;
      }
    });
    return counts;
  }, [findings, productFilter]);

  const projectStats = useMemo(() => {
    let total = 0;
    let resolved = 0;
    findings?.forEach((f: Finding) => {
      if (productFilter !== null && f.product_id !== productFilter) return;
      total++;
      // Count findings that are in terminal/resolved states
      if (isResolved(f)) {
        resolved++;
      }
    });
    return { total, resolved };
  }, [findings, productFilter]);

  const uniqueFilePaths = useMemo(() => {
    if (!findings) return [];
    const paths = new Set<string>();
    findings.forEach((f: Finding) => {
      if (productFilter !== null && f.product_id !== productFilter) return;
      if (f.file_path) paths.add(f.file_path);
    });
    return Array.from(paths).sort();
  }, [findings, productFilter]);

  const sevOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };

  const filteredFindings = useMemo(() => {
    if (!findings) return [];
    let filtered = [...findings];
    if (productFilter !== null) {
      filtered = filtered.filter((f: Finding) => f.product_id === productFilter);
    }
    if (activeFilter) {
      filtered = filtered.filter((f: Finding) => f.severity?.toLowerCase() === activeFilter);
    }
    if (statusFilter === 'active') {
      filtered = filtered.filter(isActive);
    } else if (statusFilter === 'resolved') {
      filtered = filtered.filter(isResolved);
    } else if (statusFilter !== 'all') {
      filtered = filtered.filter((f: Finding) => (f.status || 'open') === statusFilter);
    }
    if (scopeType === 'activeFile' && activeFilePath) {
      filtered = filtered.filter((f: Finding) => f.file_path === activeFilePath);
    }
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      filtered = filtered.filter((f: Finding) =>
        f.title?.toLowerCase().includes(q) ||
        f.description?.toLowerCase().includes(q) ||
        f.file_path?.toLowerCase().includes(q)
      );
    }
    filtered.sort((a: Finding, b: Finding) => {
      if (sortBy === 'severity') return (sevOrder[a.severity?.toLowerCase()] ?? 4) - (sevOrder[b.severity?.toLowerCase()] ?? 4);
      if (sortBy === 'title') return (a.title || '').localeCompare(b.title || '');
      if (sortBy === 'file') return (a.file_path || '').localeCompare(b.file_path || '');
      return 0;
    });
    return filtered;
  }, [findings, productFilter, activeFilter, statusFilter, scopeType, activeFilePath, searchQuery, sortBy]);

  const groups = useMemo(() => {
    if (groupBy === 'none') return null;
    const map = new Map<string, Finding[]>();
    filteredFindings.forEach((f: Finding) => {
      let key: string;
      switch (groupBy) {
        case 'severity': key = (f.severity || 'unknown').toUpperCase(); break;
        case 'title': key = f.title || 'Untitled'; break;
        case 'file': key = f.file_path || 'No file'; break;
        case 'scanner': key = f.stack || 'core'; break;
        case 'product': key = f.product_id ? (productMap.get(f.product_id)?.name || `Project #${f.product_id}`) : 'Unassigned'; break;
        default: key = 'Other';
      }
      if (!map.has(key)) map.set(key, []);
      map.get(key)!.push(f);
    });
    const entries = Array.from(map.entries());
    if (groupBy === 'severity') entries.sort((a, b) => (sevOrder[a[0].toLowerCase()] ?? 4) - (sevOrder[b[0].toLowerCase()] ?? 4));
    else entries.sort((a, b) => b[1].length - a[1].length);
    return entries;
  }, [filteredFindings, groupBy]);

  const filterCounts = useMemo(() => {
    const counts: Record<string, number> = { all: 0, critical: 0, high: 0, medium: 0, low: 0 };
    for (const finding of findings) {
      if (productFilter !== null && finding.product_id !== productFilter) continue;
      if (statusFilter === 'active' ? !isActive(finding) : statusFilter === 'resolved' ? !isResolved(finding) : statusFilter !== 'all' && finding.status !== statusFilter) continue;
      if (scopeType === 'activeFile' && activeFilePath && finding.file_path !== activeFilePath) continue;
      const query = searchQuery.trim().toLowerCase();
      if (query && ![finding.title, finding.description, finding.file_path].some(value => value?.toLowerCase().includes(query))) continue;
      counts.all++;
      const severity = finding.severity.toLowerCase();
      counts[severity] = (counts[severity] || 0) + 1;
    }
    return counts;
  }, [findings, productFilter, statusFilter, scopeType, activeFilePath, searchQuery]);

  const totalPages = Math.ceil(filteredFindings.length / PAGE_SIZE);
  const page = Math.min(requestedPage, Math.max(0, totalPages - 1));
  const pagedFindings = groupBy === 'none' ? filteredFindings.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE) : [];

  const toggleGroup = (key: string) => {
    setCollapsedGroups(prev => { const n = new Set(prev); n.has(key) ? n.delete(key) : n.add(key); return n; });
  };

  const [triagingIds, setTriagingIds] = useState<Set<number>>(new Set());
  const [statusActionError, setStatusActionError] = useState('');

  const handleTriage = async (f: Finding, action: string) => {
    setStatusActionError('');
    if (action === 'triage') {
      setTriagingIds(prev => {
        const next = new Set(prev);
        next.add(f.id);
        return next;
      });
      try {
        const res = await fetch(`/api/findings/${f.id}/ai-triage`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' }
        });
        const data = await res.json();
        if (!data.ok) {
          setStatusActionError(data.error || t('review.actionFailed'));
        }
      } catch (e) {
        console.error(e);
        setStatusActionError(t('review.actionFailed'));
      } finally {
        setTriagingIds(prev => {
          const next = new Set(prev);
          next.delete(f.id);
          return next;
        });
        refreshFindings?.();
        refreshMetrics?.();
      }
      return;
    }

    setTriagingIds(previous => new Set(previous).add(f.id));
    try {
      const response = await fetch(`/api/findings/${f.id}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ action: 'status', status: action }) });
      const data = await response.json();
      if (!response.ok || !data.ok) throw new Error(data.error || t('review.actionFailed'));
      refreshFindings({ silent: true });
      refreshMetrics({ silent: true });
    } catch (error) {
      setStatusActionError(error instanceof Error ? error.message : t('review.actionFailed'));
    } finally {
      setTriagingIds(previous => { const next = new Set(previous); next.delete(f.id); return next; });
    }
  };

  const sevDot = (sev: string) => {
    switch (sev?.toLowerCase()) {
      case 'critical': return '#d96873'; case 'high': return '#d88a5b'; case 'medium': return '#c7a84f'; case 'low': return '#777c85'; default: return '#777c85';
    }
  };

  if (loading) {
    return (
      <div className="simple-dashboard simple-dashboard--loading" aria-busy="true" aria-label="Loading security overview">
        <div className="simple-loading-shell">
          <div className="simple-skeleton simple-skeleton--overview" />
          <div className="simple-skeleton simple-skeleton--toolbar" />
          <div className="simple-skeleton simple-skeleton--list" />
        </div>
      </div>
    );
  }

  const revealTransition = reduceMotion
    ? { duration: 0 }
    : { duration: 0.18, ease: [0.23, 1, 0.32, 1] as [number, number, number, number] };
  const summaryProjectId = productFilter;
  const remediationPercent = projectStats.total > 0
    ? Math.round((projectStats.resolved / projectStats.total) * 100)
    : 0;
  const hasCurrentSummary = Boolean(aiSummary && aiSummaryProjectId === summaryProjectId && aiSummaryLocale === aiSummaryLang && !aiSummaryLoading);

  const generateAiSummary = async () => {
    if (!summaryProjectId || aiSummaryLoading) return;
    setAiSummary('');
    setAiSummaryLoading(true);
    setAiSummaryLocale(aiSummaryLang);
    setAiSummaryProjectId(summaryProjectId);
    setIsAiSummaryExpanded(true);
    try {
      const summary = await securityService.getAISummary(summaryProjectId, aiSummaryLang, true);
      setAiSummary(summary || (i18n.language?.startsWith('ru') ? 'Сводка не содержит данных.' : 'The summary returned no data.'));
    } catch {
      setAiSummary(i18n.language?.startsWith('ru')
        ? 'Не удалось сгенерировать сводку. Проверьте конфигурацию API.'
        : 'Failed to generate the summary. Check the API configuration.');
    } finally {
      setAiSummaryLoading(false);
    }
  };

  return (
    <div className="simple-dashboard flex h-full overflow-hidden">
      <div className="simple-dashboard__scroll flex-1 overflow-y-auto" style={{ scrollbarWidth: 'thin', scrollbarColor: 'rgba(255,255,255,0.06) transparent' }}>
        <div className="simple-dashboard__content px-4 py-4 md:px-6 md:py-5 xl:px-8">
          <div className="simple-dashboard__grid flex flex-col gap-4">
            {pageError && (
              <div className="simple-inline-error" role="alert">
                <span className="material-symbols-outlined" aria-hidden="true">cloud_off</span>
                <div className="min-w-0 flex-1">
                  <strong>{i18n.language?.startsWith('ru') ? 'Не удалось обновить данные' : 'Data could not be refreshed'}</strong>
                  <span>{pageError}</span>
                </div>
                <button onClick={() => { refreshFindings?.(); refreshMetrics?.(); refreshProducts(); }}>
                  {i18n.language?.startsWith('ru') ? 'Повторить' : 'Retry'}
                </button>
              </div>
            )}

            <motion.section variants={itemVariants} className="simple-posture-strip" aria-label={t('securityScore')}>
              <div className="simple-posture-strip__repository">
                <span className="material-symbols-outlined" aria-hidden="true">shield_lock</span>
                <div>
                  <span>{i18n.language?.startsWith('ru') ? 'Репозиторий' : 'Repository'}</span>
                  <strong title={productFilter === null ? t('allProjects') : productMap.get(productFilter)?.name}>{productFilter === null ? t('allProjects') : productMap.get(productFilter)?.name || `Project #${productFilter}`}</strong>
                </div>
              </div>
              <div className="simple-posture-strip__score" aria-busy={metricsLoading}>
                <span>{t('securityScore')}</span>
                <strong>{metricsLoading || metricsError || !metrics ? '—' : score}{!metricsLoading && !metricsError && metrics && <small>/100</small>}</strong>
                <em className={`simple-risk-label simple-risk-label--${score < 30 ? 'critical' : score < 60 ? 'high' : score < 80 ? 'medium' : 'secure'}`}>
                  {metricsLoading ? t('review.loadingScore') : metricsError || !metrics ? t('review.scoreUnavailable') : score < 30 ? t('criticalRisk') : score < 60 ? t('highRisk') : score < 80 ? t('mediumRisk') : t('review.noActiveRisk')}
                </em>
              </div>
              <div className="simple-posture-strip__triage" title={i18n.language?.startsWith('ru')
                ? 'Находка от сканера — это гипотеза, пока её не подтвердили. Непроверенные считаются открытыми, потому что они не разобраны, а не потому что доказаны.'
                : 'A scanner finding is a hypothesis until someone confirms it. Unreviewed findings count as open because they are unresolved, not because they are proven.'}>
                <span>{i18n.language?.startsWith('ru') ? 'Подтверждено' : 'Confirmed'}: <strong>{triageCounts.confirmed}</strong></span>
                <span>{i18n.language?.startsWith('ru') ? 'Требуют проверки' : 'Needs review'}: <strong>{triageCounts.needsReview}</strong></span>
                <span>{i18n.language?.startsWith('ru') ? 'Исправлено' : 'Resolved'}: <strong>{triageCounts.resolved}</strong></span>
                <span>{i18n.language?.startsWith('ru') ? 'Подавлено' : 'Suppressed'}: <strong>{triageCounts.suppressed}</strong></span>
              </div>
              <div className="simple-posture-strip__severities" aria-label={i18n.language?.startsWith('ru') ? 'Распределение по критичности' : 'Severity distribution'}>
                {([
                  { key: 'critical', label: i18n.language?.startsWith('ru') ? 'Критические' : 'Critical', count: sevCounts.critical },
                  { key: 'high', label: i18n.language?.startsWith('ru') ? 'Высокие' : 'High', count: sevCounts.high },
                  { key: 'medium', label: i18n.language?.startsWith('ru') ? 'Средние' : 'Medium', count: sevCounts.medium },
                  { key: 'low', label: i18n.language?.startsWith('ru') ? 'Низкие' : 'Low', count: sevCounts.low },
                ] as const).map(item => (
                  <div
                    key={item.key}
                    className={`simple-posture-severity simple-posture-severity--${item.key}`}
                    title={item.label}
                    aria-label={`${item.label}: ${item.count}`}
                  >
                    <span>{item.label}</span>
                    <strong>{item.count}</strong>
                  </div>
                ))}
              </div>
              <div className="simple-posture-strip__remediation">
                <div>
                  <span>{t('remediationProgress')}</span>
                  <strong>{remediationPercent}%</strong>
                </div>
                <div className="simple-remediation-track" aria-hidden="true">
                  <span style={{ width: `${remediationPercent}%` }} />
                </div>
                <small>{projectStats.resolved} / {projectStats.total} {i18n.language?.startsWith('ru') ? 'исправлено' : 'resolved'}</small>
              </div>
              <div className="simple-posture-strip__total">
                <span>{i18n.language?.startsWith('ru') ? 'Всего находок' : 'Total findings'}</span>
                <strong>{projectStats.total}</strong>
                <small>{sevCounts.critical + sevCounts.high} {i18n.language?.startsWith('ru') ? 'требуют внимания' : 'need attention'}</small>
              </div>
            </motion.section>

            <div className="simple-data-freshness" aria-label={t('review.lastScan')}>
              <span>{t('review.lastScan')}: <strong>{metricsLoading ? t('review.refreshingMetrics') : metricsError ? t('review.dataUnavailable') : formatResultTime(metrics?.last_successful_scan_at, i18n.language) || t('review.noTimestamp')}</strong></span>
              <span>{t('review.lastVerification')}: <strong>{metricsLoading ? t('review.refreshingMetrics') : metricsError ? t('review.dataUnavailable') : formatResultTime(metrics?.last_successful_verification_at, i18n.language) || t('review.noTimestamp')}</strong></span>
            </div>

            <details className="simple-ai-tools">
              <summary>{t('review.aiTools')}</summary>
              {aiAvailable !== true && <p className="review-help">{t('review.aiUnavailable')}</p>}
            <section className={`simple-ai-command ${isAiSummaryExpanded ? 'simple-ai-command--expanded' : ''}`} aria-label={t('aiSecuritySummary')}>
              <div className="simple-ai-command__heading"><strong>{t('aiSecuritySummary')}</strong></div>
              <p className="simple-ai-command__copy">
                {!summaryProjectId ? t('review.selectProject') : aiSummary && aiSummaryProjectId === summaryProjectId && aiSummaryLocale === aiSummaryLang
                  ? (i18n.language?.startsWith('ru') ? 'Сводка сохранена и готова к просмотру.' : 'The saved summary is ready to review.')
                  : (i18n.language?.startsWith('ru')
                    ? 'Получите краткий разбор риска и порядок исправления с помощью SecureCoder.'
                    : 'Generate a concise risk review and remediation order with SecureCoder.')}
              </p>
              <div className="simple-ai-command__actions">
                <select disabled={aiSummaryLoading} value={aiSummaryLang} onChange={event => setAiSummaryLang(event.target.value as 'en' | 'ru')} aria-label={i18n.language?.startsWith('ru') ? 'Язык сводки' : 'Summary language'}>
                  <option value="ru">RU</option>
                  <option value="en">EN</option>
                </select>
                {hasCurrentSummary && (
                  <button type="button" className="simple-ai-command__primary" onClick={() => setIsAiSummaryExpanded(value => !value)} aria-expanded={isAiSummaryExpanded}>
                    <span className="material-symbols-outlined" aria-hidden="true">{isAiSummaryExpanded ? 'expand_less' : 'description'}</span>
                    {isAiSummaryExpanded ? (i18n.language?.startsWith('ru') ? 'Свернуть' : 'Collapse') : (i18n.language?.startsWith('ru') ? 'Открыть сводку' : 'Open summary')}
                  </button>
                )}
                <button
                  type="button"
                  className={hasCurrentSummary ? 'simple-ai-command__secondary simple-ai-command__regenerate' : 'simple-ai-command__primary'}
                  onClick={generateAiSummary}
                  disabled={!summaryProjectId || aiSummaryLoading || aiAvailable !== true}
                >
                  <span className="material-symbols-outlined" aria-hidden="true">{hasCurrentSummary ? 'refresh' : 'auto_awesome'}</span>
                  {aiSummaryLoading
                    ? (i18n.language?.startsWith('ru') ? 'Анализируем' : 'Analyzing')
                    : (hasCurrentSummary ? (i18n.language?.startsWith('ru') ? 'Обновить' : 'Regenerate') : (i18n.language?.startsWith('ru') ? 'Сгенерировать сводку' : 'Generate summary'))}
                </button>
              </div>
              <AnimatePresence initial={false}>
                {isAiSummaryExpanded && aiSummaryProjectId === summaryProjectId && aiSummaryLocale === aiSummaryLang && (aiSummaryLoading || aiSummary) && (
                  <motion.div className="simple-ai-command__content" initial={reduceMotion ? false : { opacity: 0, transform: 'translateY(-6px)' }} animate={{ opacity: 1, transform: 'translateY(0)' }} exit={reduceMotion ? { opacity: 0 } : { opacity: 0, transform: 'translateY(-6px)' }} transition={revealTransition}>
                    {aiSummaryLoading ? (
                      <div className="simple-ai-command__loading" aria-live="polite"><span /><span /><span />{i18n.language?.startsWith('ru') ? 'Анализируем репозиторий' : 'Analyzing repository'}</div>
                    ) : (
                      <div className="simple-ai-command__markdown"><Markdown>{aiSummary}</Markdown></div>
                    )}
                  </motion.div>
                )}
              </AnimatePresence>
            </section>
            </details>

            {/* ── MAIN CONTENT SPLIT ── */}
            <div className="simple-workspace-grid grid grid-cols-1 gap-4 items-start">
              
              {/* LEFT: Findings & Toolbar */}
              <div className="simple-findings-column space-y-3 min-w-0">
                {statusActionError && <p role="alert" className="review-error">{statusActionError}</p>}
                {bulkVerificationResult && <p role="status">{bulkVerificationResult}</p>}
                {/* ── Floating Bulk Action Bar ── */}
                {selectedFindings.size > 0 && (
                  <motion.div
                    initial={reduceMotion ? false : { opacity: 0, y: -4 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: -4 }}
                    transition={reduceMotion ? { duration: 0 } : { duration: 0.18, ease: [0.23, 1, 0.32, 1] }}
                    className="simple-bulk-bar flex items-center justify-between gap-4 px-5 py-3 rounded-xl relative overflow-hidden"
                  >

                    {/* Left: selection info */}
                    <div className="flex items-center gap-4 shrink-0 relative z-10">
                      <div
                        className="flex items-center gap-2 px-3 py-1 rounded-full font-mono font-black text-[10px] uppercase tracking-widest shadow-[0_0_15px_var(--accent-color-soft)]"
                        style={{
                          background: 'var(--accent-color-soft)',
                          border: '1px solid var(--accent-color-line)',
                          color: 'var(--accent-color)'
                        }}
                      >
                        <span
                          className="inline-flex items-center justify-center w-4 h-4 rounded-full text-[9px] font-black"
                          style={{ background: 'var(--accent-color)', color: 'var(--accent-color-on-text)' }}
                        >
                          {selectedFindings.size}
                        </span>
                        {t('review.selected')}
                      </div>
                      <button
                        onClick={() => setSelectedFindings(new Set())}
                        className="flex items-center gap-1.5 text-[10px] font-mono font-bold uppercase tracking-wider transition-colors duration-200 cursor-pointer text-[#52525b] hover:text-[var(--accent-color)]"
                      >
                        <span aria-hidden="true" className="material-symbols-outlined text-[13px]">close</span>
                        {t('review.clearSelection')}
                      </button>
                    </div>

                    {/* Divider */}
                    <div className="w-px self-stretch" style={{ background: 'rgba(255,255,255,0.06)' }} />

                    {/* Right: actions */}
                    <div className="flex items-center gap-2.5 relative z-10">
                      <button type="button" disabled={bulkVerifying || bulkIgnoring} onClick={handleBulkVerify} className="btn-secondary px-3 py-2 text-xs disabled:opacity-50">
                        {bulkVerifying ? t('verification_running_short') : (i18n.language?.startsWith('ru') ? 'Перепроверить выбранные' : 'Verify selected')}
                      </button>
                      {/* Fix Selected – primary accent filled with translate hover */}
                      <button
                        onClick={handleBulkFix}
                        className="flex items-center gap-1.5 pl-3.5 pr-4 py-1.5 rounded-lg text-[11px] font-bold uppercase tracking-widest transition-[background-color,transform] duration-150 cursor-pointer bg-[var(--simple-accent)] hover:bg-[var(--simple-accent-hover)] text-[var(--accent-color-on-text)] active:scale-[0.97]"
                      >
                        <span aria-hidden="true" className="material-symbols-outlined text-[14px]">{bulkFixCopied ? 'check' : 'auto_fix_high'}</span>
                        {bulkFixCopied ? t('review.copied') : t('review.copyPrompt')}
                      </button>

                      {/* Ignore Selected – secondary ghost outline with translate hover */}
                      <button
                        disabled={bulkVerifying || bulkIgnoring} onClick={() => setBulkIgnoreModalOpen(true)}
                        className="flex items-center gap-1.5 pl-3.5 pr-4 py-1.5 rounded-lg text-[11px] font-bold uppercase tracking-widest transition-[color,background-color,border-color,transform] duration-150 cursor-pointer bg-[var(--simple-surface-2)] border border-[var(--simple-line)] text-[var(--simple-fg-soft)] hover:text-[var(--simple-fg)] hover:bg-[var(--simple-surface-3)] active:scale-[0.97]"
                      >
                        <span aria-hidden="true" className="material-symbols-outlined text-[14px]">do_not_disturb_on</span>
                        {t('review.bulkDecision')}
                      </button>
                    </div>
                  </motion.div>
                )}

                {/* ── Toolbar ── */}
                <motion.div variants={itemVariants} className="simple-command-surface space-y-2 p-3 rounded-xl">
                  <div className="simple-command-header">
                    <div>
                      <h2>{i18n.language?.startsWith('ru') ? 'Разбор находок' : 'Finding review'}</h2>
                      <span>{t('review.findingsInView', { count: filteredFindings.length })}</span>
                    </div>
                    <div className="simple-command-header__actions">
                      <button ref={projectsTriggerRef} type="button" onClick={() => { setIsSecureCoderOpen(false); handleToggleProjectsPanel(); }} aria-haspopup="dialog" aria-expanded={isProjectsPanelOpen} className="simple-command-header__primary">
                        <span className="material-symbols-outlined" aria-hidden="true">folder_open</span>
                        {i18n.language?.startsWith('ru') ? 'Сканирование проектов' : 'Project scanning'}
                      </button>
                      <button ref={secureCoderTriggerRef} type="button" onClick={() => { setIsProjectsPanelOpen(false); setIsSecureCoderOpen(true); }} aria-haspopup="dialog" aria-expanded={isSecureCoderOpen} className="simple-command-header__secondary" aria-label="SecureCoder" title="SecureCoder">
                        <span className="material-symbols-outlined" aria-hidden="true">smart_toy</span>
                        <span><strong>SecureCoder</strong><small>{i18n.language?.startsWith('ru') ? 'Дополнительный AI-инструмент' : 'Optional AI assistant'}</small></span>
                      </button>
                    </div>
                  </div>
                  <DashboardFilters {...dashboardQuery}
                    products={activeProducts} filePaths={uniqueFilePaths} counts={filterCounts} count={filteredFindings.length}
                    allSelected={filteredFindings.length > 0 && filteredFindings.every(f => selectedFindings.has(f.id))}
                    someSelected={filteredFindings.some(f => selectedFindings.has(f.id))}
                    onSelectAll={checked => setSelectedFindings(previous => { const next = new Set(previous); for (const finding of filteredFindings) { if (checked) next.add(finding.id); else next.delete(finding.id); } return next; })}
                    onProject={id => { setProductFilter(id); setSelectedFindings(new Set()); }}
                    onSeverity={dashboardQuery.setActiveFilter} onStatus={dashboardQuery.setStatusFilter}
                    onSearch={dashboardQuery.setSearchQuery} onGroup={dashboardQuery.setGroupBy}
                    onSort={dashboardQuery.setSortBy} onFile={dashboardQuery.setActiveFilePath}
                    onCollapse={() => setExpandedIds(new Set())}
                    onClear={() => { clearFilters(); setSelectedFindings(new Set()); }}
                  />
                </motion.div>

                {/* ── Findings ── */}
                {groupBy === 'none' && filteredFindings.length > 0 && (
                  <div className="simple-findings-table-header" aria-hidden="true">
                    <span />
                    <span>{i18n.language?.startsWith('ru') ? 'Критичность' : 'Severity'}</span>
                    <span>{i18n.language?.startsWith('ru') ? 'Название находки' : 'Finding'}</span>
                    <span>{i18n.language?.startsWith('ru') ? 'Репозиторий / технология' : 'Repository / stack'}</span>
                    <span>{i18n.language?.startsWith('ru') ? 'Файл / путь' : 'File / path'}</span>
                    <span>{i18n.language?.startsWith('ru') ? 'Статус' : 'Status'}</span>
                    <span />
                  </div>
                )}
                {filteredFindings.length === 0 ? (
                  <motion.div variants={itemVariants} className="simple-empty-state py-12 text-center text-[12px] text-[#71717a] font-mono uppercase tracking-wider">
                    <span className="material-symbols-outlined text-[36px] text-[#3f3f46] mb-2 block">search_off</span>
                    <h3>{pageError ? t('review.loadFailed') : findings.length === 0 ? t('review.noScans') : t('review.noMatches')}</h3><p className="review-help">{pageError ? t('review.retryHelp') : findings.length === 0 ? t('review.startHelp') : t('review.filterHelp')}</p>
                    {!pageError && findings.length === 0 && <button type="button" className="review-primary" onClick={handleToggleProjectsPanel}>{t('review.startScan')}</button>}
                    {!pageError && findings.length > 0 && <button type="button" onClick={showHistory}>{t('review.showHistory')}</button>}
                  </motion.div>
                ) : groupBy !== 'none' && groups ? (
                  <motion.div variants={itemVariants} className="simple-findings-groups space-y-3">
                    {groups.map(([key, items]) => {
                      const isCollapsed = collapsedGroups.has(key);
                      return (
                        <div key={key} className="simple-findings-group overflow-hidden">
                          <div className="flex items-center gap-3 px-4 py-2.5 hover:bg-[rgba(255,255,255,0.02)] border-b border-[rgba(255,255,255,0.02)]">
                            <input
                              type="checkbox"
                              checked={items.every(item => selectedFindings.has(item.id))}
                              ref={el => {
                                if (el) {
                                  const isAllSel = items.every(item => selectedFindings.has(item.id));
                                  el.indeterminate = items.some(item => selectedFindings.has(item.id)) && !isAllSel;
                                }
                              }}
                              onChange={(e) => {
                                const checked = e.target.checked;
                                setSelectedFindings(prev => {
                                  const next = new Set(prev);
                                  items.forEach(item => {
                                    if (checked) {
                                      next.add(item.id);
                                    } else {
                                      next.delete(item.id);
                                    }
                                  });
                                  return next;
                                });
                              }}
                              onClick={e => e.stopPropagation()}
                              className="accent-[var(--accent-color)] cursor-pointer select-checkbox w-3.5 h-3.5 rounded bg-[rgba(255,255,255,0.02)] border border-[rgba(255,255,255,0.08)]"
                            />
                            <button onClick={() => toggleGroup(key)} className="flex-1 text-left flex items-center gap-3">
                              <span className={`material-symbols-outlined text-[14px] text-[#71717a] transition-transform ${isCollapsed ? '' : 'rotate-90'}`}>chevron_right</span>
                              {groupBy === 'severity' && <span className="w-2 h-2 rounded-full shadow-sm" style={{ backgroundColor: sevDot(key) }} />}
                              <span className="text-[12px] text-[#f4f4f5] font-semibold truncate flex-1 tracking-wide">{key}</span>
                              <span className="text-[10px] text-[#a1a1aa] bg-[rgba(255,255,255,0.06)] px-2 py-0.5 rounded-md font-mono">{items.length}</span>
                            </button>
                          </div>
                          {!isCollapsed && (
                            <div className="divide-y divide-[rgba(255,255,255,0.03)]">
                              {items.map(f => (
                                <FindingRow
                                  key={f.id}
                                  f={f}
                                  isExpanded={expandedIds.has(f.id)}
                                  onToggle={() => {
                                    setExpandedIds(prev => {
                                      const next = new Set(prev);
                                      if (next.has(f.id)) next.delete(f.id);
                                      else next.add(f.id);
                                      return next;
                                    });
                                  }}
                                  productMap={productMap}
                                  setProductFilter={id => { setProductFilter(id); setSelectedFindings(new Set()); }}
                                  handleTriage={handleTriage}
                                  onNavigateToChat={onNavigateToChat}
                                  onRefresh={(options) => {
                                    refreshFindings?.(options);
                                    refreshMetrics?.(options);
                                  }}
                                  isSelected={selectedFindings.has(f.id)}
                                  isTriaging={triagingIds.has(f.id)}
                                  aiAvailable={aiAvailable === true}
                                  onToggleSelect={() => {
                                    setSelectedFindings(prev => {
                                      const next = new Set(prev);
                                      if (next.has(f.id)) {
                                        next.delete(f.id);
                                      } else {
                                        next.add(f.id);
                                      }
                                      return next;
                                    });
                                  }}
                                />
                              ))}
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </motion.div>
                ) : (
                  <motion.div variants={itemVariants} className="simple-findings-list space-y-3">
                    <div className="simple-findings-list__rows">
                      {pagedFindings.map(f => (
                        <FindingRow
                          key={f.id}
                          f={f}
                          isExpanded={expandedIds.has(f.id)}
                          onToggle={() => {
                            setExpandedIds(prev => {
                              const next = new Set(prev);
                              if (next.has(f.id)) next.delete(f.id);
                              else next.add(f.id);
                              return next;
                            });
                          }}
                          productMap={productMap}
                          setProductFilter={id => { setProductFilter(id); setSelectedFindings(new Set()); }}
                          handleTriage={handleTriage}
                          onNavigateToChat={onNavigateToChat}
                          onRefresh={(options) => {
                            refreshFindings?.(options);
                            refreshMetrics?.(options);
                          }}
                          isSelected={selectedFindings.has(f.id)}
                          isTriaging={triagingIds.has(f.id)}
                                  aiAvailable={aiAvailable === true}
                          onToggleSelect={() => {
                            setSelectedFindings(prev => {
                              const next = new Set(prev);
                              if (next.has(f.id)) {
                                next.delete(f.id);
                              } else {
                                next.add(f.id);
                              }
                              return next;
                            });
                          }}
                        />
                      ))}
                    </div>
                    {totalPages > 1 && (
                      <div className="flex items-center justify-between pt-1 px-1">
                        <button onClick={() => setPage(Math.max(0, page - 1))} disabled={page === 0} className="text-[11px] text-[#a1a1aa] hover:text-[#f4f4f5] disabled:opacity-30 flex items-center gap-1 transition-colors font-bold uppercase tracking-wider font-mono bg-[rgba(255,255,255,0.02)] border border-[rgba(255,255,255,0.04)] px-2.5 py-1 rounded-md hover:bg-[rgba(255,255,255,0.04)]">
                          <span className="material-symbols-outlined text-[14px]">chevron_left</span>{t('SimpleDashboardPage.previous')}</button>
                        <div className="flex items-center gap-1">
                          {Array.from({ length: Math.min(totalPages, 7) }, (_, i) => {
                            const p = totalPages <= 7 ? i : page <= 3 ? i : page >= totalPages - 4 ? totalPages - 7 + i : page - 3 + i;
                            return (
                              <button key={p} onClick={() => setPage(p)}
                                className={`w-6 h-6 rounded-md text-[10px] font-bold font-mono transition-all ${p === page ? 'bg-[rgba(255,255,255,0.08)] text-white border border-[rgba(255,255,255,0.12)]' : 'text-[#71717a] hover:text-[#e4e4e7] hover:bg-[rgba(255,255,255,0.02)]'}`}>
                                {p + 1}
                              </button>
                            );
                          })}
                        </div>
                        <button onClick={() => setPage(Math.min(totalPages - 1, page + 1))} disabled={page >= totalPages - 1} className="text-[11px] text-[#a1a1aa] hover:text-[#f4f4f5] disabled:opacity-30 flex items-center gap-1 transition-colors font-bold uppercase tracking-wider font-mono bg-[rgba(255,255,255,0.02)] border border-[rgba(255,255,255,0.04)] px-2.5 py-1 rounded-md hover:bg-[rgba(255,255,255,0.04)]">
                          Next<span className="material-symbols-outlined text-[14px]">chevron_right</span></button>
                      </div>
                    )}
                  </motion.div>
                )}
              </div>

            </div>
          </div>
        </div>
      </div>
      <AnimatePresence initial={false}>
        {isSecureCoderOpen && (
          <div className="simple-drawer-shell simple-securecoder-shell">
            <button
              type="button"
              aria-label={i18n.language?.startsWith('ru') ? 'Закрыть SecureCoder' : 'Close SecureCoder'}
              className="simple-drawer-backdrop"
              onClick={closeSecureCoder}
            />
            <aside
              ref={secureCoderDrawerRef}
              role="dialog"
              aria-modal="true"
              aria-label="SecureCoder"
              tabIndex={-1}
              className="simple-drawer simple-securecoder-drawer bg-v2-bg"
            >
              <div className="simple-drawer__content">
                <SecureCoderPanel
                  activeProducts={activeProducts}
                  onClose={closeSecureCoder}
                  onNavigateToReports={onNavigateToReports}
                />
              </div>
            </aside>
          </div>
        )}
      </AnimatePresence>

      <AnimatePresence initial={false}>
        {isProjectsPanelOpen && (
          <div className="simple-drawer-shell simple-projects-shell">
            <button
              type="button"
              aria-label={i18n.language?.startsWith('ru') ? 'Закрыть сканирование проектов' : 'Close project scanning'}
              className="simple-drawer-backdrop"
              onClick={closeProjectsPanel}
            />
            <aside
              ref={projectsDrawerRef}
              role="dialog"
              aria-modal="true"
              aria-label={i18n.language?.startsWith('ru') ? 'Сканирование проектов' : 'Project scanning'}
              tabIndex={-1}
              className="simple-drawer simple-projects-drawer bg-surface"
            >
              <div className="simple-drawer__bar">
                <div><span className="material-symbols-outlined" aria-hidden="true">folder_open</span><strong>{i18n.language?.startsWith('ru') ? 'Сканирование проектов' : 'Project scanning'}</strong></div>
                <button type="button" onClick={closeProjectsPanel} aria-label={i18n.language?.startsWith('ru') ? 'Закрыть сканирование проектов' : 'Close project scanning'}>
                  <span className="material-symbols-outlined" aria-hidden="true">close</span>
                </button>
              </div>
              <div className="simple-drawer__content"><ScanPanel onScanComplete={() => runScanCompletionRefreshers({
                findings: refreshFindings,
                metrics: refreshMetrics,
                products: refreshProducts,
              })} /></div>
            </aside>
          </div>
        )}
      </AnimatePresence>

      {/* Bulk Ignore Triage Justification Modal */}
      <AnimatePresence>
        {bulkIgnoreModalOpen && (
          <ModalDialog label={t('review.bulkDecision')} onClose={() => { if (!bulkIgnoring) setBulkIgnoreModalOpen(false); }} className="bulk-review-dialog">
            <div className="p-6 space-y-4">
              <div>
                <h3 className="text-[12px] font-bold text-white uppercase tracking-wider">{t('review.bulkDecision')} ({selectedFindings.size})</h3>
                <p className="text-[11px] text-[#71717a] mt-1 leading-normal">
                  {t('review.bulkHint')}
                </p>
              </div>

              <div className="space-y-1">
                <label className="text-[10px] text-[#71717a] font-bold uppercase tracking-wider">{t('review.decision')}</label>
                <select
                  aria-label={t('review.decision')} value={bulkIgnoreReason}
                  onChange={e => setBulkIgnoreReason(e.target.value)}
                  className="w-full bg-[rgba(255,255,255,0.02)] border border-[rgba(255,255,255,0.06)] rounded-md px-3 py-1.5 text-[11px] text-white outline-none focus:border-[var(--accent-color)] cursor-pointer"
                >
                  <option value="False Positive">{t('statusFalsePositive')}</option>
                  <option value="Accepted Risk">{t('review.acceptRisk')}</option>
                </select>
              </div>

              <div className="flex justify-end gap-2 pt-2 border-t border-[rgba(255,255,255,0.06)]">
                <button
                  onClick={() => setBulkIgnoreModalOpen(false)}
                  className="px-3.5 py-1.5 bg-[rgba(255,255,255,0.02)] border border-[rgba(255,255,255,0.06)] hover:bg-[rgba(255,255,255,0.05)] text-[#a1a1aa] hover:text-white rounded-lg text-[10px] font-bold uppercase tracking-wider transition-colors cursor-pointer"
                >
                  {t('SimpleDashboardPage.cancel')}
                </button>
                <button
                  onClick={handleBulkIgnore}
                  disabled={bulkIgnoring}
                  className="px-4 py-1.5 bg-red-600 hover:bg-red-500 text-white rounded-lg text-[10px] font-bold uppercase tracking-wider transition-colors cursor-pointer disabled:opacity-50"
                >
                  {bulkIgnoring ? t('review.preparing') : t('review.applyDecision')}
                </button>
              </div>
            </div>
          </ModalDialog>
        )}
      </AnimatePresence>


    </div>
  );
};
