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
            placeholder="/host/Desktop/my-project"
            className="w-full bg-surface-bright border border-[rgba(255,255,255,0.06)] rounded-lg pl-8 pr-3 py-2 text-[12px] text-[#f4f4f5] font-mono placeholder:text-[#3f3f46] outline-none focus:border-[rgba(255,255,255,0.12)] transition-colors"
          />
        </div>
        <button
          onClick={openBrowser}
          className="shrink-0 w-8 h-8 flex items-center justify-center rounded-lg border border-[rgba(255,255,255,0.06)] text-[#52525b] hover:text-[#a1a1aa] hover:bg-[rgba(255,255,255,0.03)] transition-colors"
          title="Browse folders"
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
              Select
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
  const [external,  ] = useState(true);
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
  const [tools, setTools] = useState({ semgrep: true, gitleaks: true, trivy: true, bandit: true });
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

  // Scan phase simulation
  const [scanPhase, setScanPhase] = useState(0);
  const [scanLogs, setScanLogs] = useState<string[]>([]);
  const phases = [
    { name: 'Core', desc: 'AST parsing & pattern matching', icon: 'memory' },
    { name: 'Semgrep', desc: 'SAST rules & taint analysis', icon: 'shield' },
    { name: 'Gitleaks', desc: 'Secrets & credential detection', icon: 'key' },
    { name: 'Trivy', desc: 'CVE & dependency vulnerabilities', icon: 'inventory_2' },
    { name: 'Bandit', desc: 'Python-specific security checks', icon: 'bug_report' },
  ];
  const logMessages = [
    'Indexing source files...', 'Building AST...', 'Running pattern rules...',
    'Checking injection patterns...', 'Scanning for SQL injection...', 'Analyzing auth flows...',
    'Detecting hardcoded secrets...', 'Checking API keys...', 'Scanning .env files...',
    'Resolving dependencies...', 'Checking CVE database...', 'Analyzing lock files...',
    'Scanning Python imports...', 'Checking subprocess calls...', 'Detecting unsafe deserialization...',
    'Analyzing template injection...', 'Checking XSS vectors...', 'Scanning CSRF protections...',
  ];

  // Elapsed timer + phase cycling during scan
  useEffect(() => {
    if (!scanningProject) { setElapsed(0); setScanPhase(0); setScanLogs([]); return; }
    const t = setInterval(() => setElapsed(e => e + 1), 1000);
    const p = setInterval(() => setScanPhase(ph => (ph + 1) % phases.length), 4000);
    const l = setInterval(() => {
      const msg = logMessages[Math.floor(Math.random() * logMessages.length)];
      setScanLogs(prev => [...prev.slice(-4), msg]);
    }, 1200);
    return () => { clearInterval(t); clearInterval(p); clearInterval(l); };
  }, [scanningProject]);

  const runScan = async (path: string): Promise<boolean> => {
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
    setTimeout(() => onScanComplete?.(), 2000);
  };

  const scanOne = async (path: string) => {
    setTotalScans(1);
    setActiveScans(1);
    await runScan(path);
    setTimeout(() => onScanComplete?.(), 1500);
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
            title="Go back"
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
            {/* Phase indicator */}
            <div className="flex items-center gap-1.5 mt-1.5">
              <span className="material-symbols-outlined text-[12px] text-[#22c55e]">{phases[scanPhase].icon}</span>
              <span className="text-[10px] text-[#a1a1aa] font-medium">{phases[scanPhase].name}</span>
              <span className="text-[10px] text-[#3f3f46]">— {t(`SimpleDashboardPage.phases.${scanPhase}.desc`, { defaultValue: phases[scanPhase].desc })}</span>
            </div>
            {/* Phase progress dots */}
            <div className="flex gap-1 mt-2">
              {phases.map((ph, i) => (
                <div key={ph.name} className={`flex-1 h-1 rounded-full transition-all duration-500 ${
                  i < scanPhase ? 'bg-[#22c55e]' : i === scanPhase ? 'bg-[#22c55e] animate-pulse' : 'bg-surface-bright'
                }`} />
              ))}
            </div>
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
          {/* Mini log */}
          <div className="px-4 py-1.5 border-t border-[rgba(255,255,255,0.04)] bg-background/40 font-mono">
            {scanLogs.slice(-3).map((log, i) => (
              <div key={i} className={`text-[9px] leading-relaxed transition-opacity duration-300 ${i === scanLogs.slice(-3).length - 1 ? 'text-[#52525b]' : 'text-[#27272a]'}`}>
                <span className="text-[#3f3f46] mr-1">$</span>{log}
              </div>
            ))}
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
              Scanners
            </span>
            <span>{Object.values(tools).filter(Boolean).length}/{Object.keys(tools).length} {t('SimpleDashboardPage.active')}</span>
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
                  {toolList.map(t => {
                    const installed = toolStatus[t.key];
                    const enabled = (tools as any)[t.key];
                    return (
                      <div key={t.key} className="flex items-center gap-2 px-2 py-1.5 rounded hover:bg-surface-bright/40">
                        <button onClick={() => setTools(prev => ({ ...prev, [t.key]: !enabled }))}
                          className={`w-3.5 h-3.5 rounded border flex items-center justify-center transition-colors ${enabled ? 'bg-[#f4f4f5] border-[#f4f4f5]' : 'border-[#3f3f46]'}`}>
                          {enabled && <span className="material-symbols-outlined text-[10px] text-[var(--bg-color)]">check</span>}
                        </button>
                        <span className="text-[11px] text-[#a1a1aa] flex-1">{t.label}</span>
                        {installed !== undefined && <span className={`w-1.5 h-1.5 rounded-full ${installed ? 'bg-[#22c55e]' : 'bg-[#ef4444]'}`} />}
                      </div>
                    );
                  })}
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
          disabled={isAnyScanRunning}
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
type GroupBy = 'none' | 'severity' | 'title' | 'file' | 'scanner' | 'product';
type SortBy = 'severity' | 'title' | 'file';
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
  setPage: (p: number) => void;
  handleTriage: (f: Finding, action: string) => void;
  onNavigateToChat?: (f: Finding) => void;
  onRefresh?: (options?: { silent?: boolean }) => void;
  isSelected?: boolean;
  onToggleSelect?: (e: React.MouseEvent | React.ChangeEvent) => void;
  isTriaging?: boolean;
}> = ({ f, isExpanded, onToggle, productMap, setProductFilter, setPage, handleTriage, onNavigateToChat, onRefresh, isSelected, onToggleSelect, isTriaging }) => {
  const { t, i18n } = useTranslation('pages');
  const reduceMotion = useReducedMotion();
  const [agentPrompt, setAgentPrompt] = useState(f.agent_prompt ?? '');
  const [verificationSummary, setVerificationSummary] = useState(f.verification_summary ?? '');
  const [agentPromptLoading, setAgentPromptLoading] = useState(false);
  const [verificationLoading, setVerificationLoading] = useState(false);
  const [copiedContext, setCopiedContext] = useState(false);

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
    (verificationLoading || ['verification_failed', 'resolved', 'fixed'].includes(lifecycleStatus.toLowerCase()));
  const handoffStatus = verificationLoading ? 'pending_verification' : lifecycleStatus;

  const statusLabel = (status: string) => {
    const s = status.toLowerCase();
    if (s === 'sent_to_agent') return t('status_sent_to_agent');
    if (s === 'pending_verification') return t('status_pending_verification');
    if (s === 'verification_failed') return t('status_verification_failed');
    if (s === 'resolved' || s === 'fixed') return t('status_fixed');
    if (s === 'triage') return t('statusTriage');
    if (s === 'false_positive') return t('statusFalsePositive');
    if (s === 'risk_accepted' || s === 'accepted_risk') return t('statusAccepted');
    return t('statusOpen');
  };

  const statusClass = (status: string) => {
    const s = status.toLowerCase();
    if (s === 'resolved' || s === 'fixed') return 'text-[#22c55e] bg-[rgba(34,197,94,0.08)] border-[rgba(34,197,94,0.18)]';
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
      alert(err instanceof Error ? err.message : 'Failed to generate agent prompt');
    } finally {
      setAgentPromptLoading(false);
    }
  };

  const verifyFinding = async (event: React.MouseEvent) => {
    event.stopPropagation();
    if (verificationLoading) return;
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
      alert(err instanceof Error ? err.message : 'Failed to verify finding');
    } finally {
      setVerificationLoading(false);
    }
  };
  
  return (
    <article className={`simple-finding ${isExpanded ? 'simple-finding--expanded' : ''}`}>
      <div
        className="simple-finding-row"
        role="button"
        tabIndex={0}
        aria-expanded={isExpanded}
        onClick={onToggle}
        onKeyDown={(event) => {
          if (event.target !== event.currentTarget) return;
          if (event.key === 'Enter' || event.key === ' ') {
            event.preventDefault();
            onToggle();
          }
        }}
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
            <button onClick={(event) => { event.stopPropagation(); setProductFilter(project.id); setPage(0); }} title={`${t('groupProject')}: ${project.name}`}>{project.name}</button>
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
              
              {f.description && (
                <p className="simple-finding-details__description text-[12px] leading-relaxed select-text">
                  {f.description}
                </p>
              )}
              
              {(f.fix_suggestion || f.suggestion) && (
                <div className="simple-finding-details__guidance text-[12px] leading-relaxed pl-3 my-2 select-text font-mono p-3 rounded-r-md">
                  <span className="text-[9px] text-[#52525b] uppercase tracking-wider block mb-1 font-bold">Remediation Guidance</span>
                  {f.fix_suggestion || f.suggestion}
                </div>
              )}

              {f.ai_triage_summary && (
                <div className="text-[12px] text-[#a1a1aa] leading-relaxed border-l-2 pl-3 my-2.5 select-text p-2.5 rounded-r-md"
                  style={{
                    borderColor: f.ai_triage_status === 'true_positive' ? '#ef4444' : f.ai_triage_status === 'false_positive' ? '#22c55e' : '#eab308',
                    backgroundColor: f.ai_triage_status === 'true_positive' ? 'rgba(239,68,68,0.02)' : f.ai_triage_status === 'false_positive' ? 'rgba(34,197,94,0.02)' : 'rgba(234,179,8,0.02)'
                  }}
                >
                  <div className="flex items-center gap-1.5 mb-1.5">
                    <span className="material-symbols-outlined text-[14px]" style={{ color: f.ai_triage_status === 'true_positive' ? '#ef4444' : f.ai_triage_status === 'false_positive' ? '#22c55e' : '#eab308' }}>psychology</span>
                    <span className="text-[9px] uppercase tracking-wider font-bold" style={{ color: f.ai_triage_status === 'true_positive' ? '#ef4444' : f.ai_triage_status === 'false_positive' ? '#22c55e' : '#eab308' }}>
                      AI Triage Conclusion: {f.ai_triage_status?.replace('_', ' ').toUpperCase()}
                    </span>
                  </div>
                  <p className="text-[#e4e4e7] text-[14px] font-sans leading-relaxed">
                    {f.ai_triage_summary}
                  </p>
                </div>
              )}

              <div className="simple-finding-handoff rounded-lg p-3 space-y-2.5">
                <div className="flex items-center justify-between gap-2">
                  <div className="flex items-center gap-1.5 min-w-0">
                    <span className="material-symbols-outlined text-[13px] text-[var(--accent-color)]">smart_toy</span>
                    <span className="text-[9px] text-[#a1a1aa] uppercase tracking-wider font-bold font-mono truncate">
                      {t('agent_handoff')}
                    </span>
                  </div>
                  <span className={`shrink-0 whitespace-nowrap text-[9px] px-1.5 py-0.5 rounded font-mono uppercase tracking-wider border ${statusClass(handoffStatus)}`}>
                    {statusLabel(handoffStatus)}
                  </span>
                </div>
                <div className="flex items-center gap-1.5 flex-wrap">
                  <button
                    onClick={generateAgentPrompt}
                    disabled={agentPromptLoading}
                    className="text-[10px] text-[var(--accent-color)] border border-[rgba(139,92,246,0.15)] hover:bg-[rgba(139,92,246,0.06)] px-2.5 py-1 rounded-md flex items-center gap-1 transition-colors font-medium disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    {agentPromptLoading ? (
                      <div className="w-3 h-3 border-2 border-t-[var(--accent-color)] border-[rgba(255,255,255,0.1)] rounded-full animate-spin shrink-0" />
                    ) : (
                      <span className="material-symbols-outlined text-[12px]">content_paste</span>
                    )}
                    {t('agent_prompt')}
                  </button>
                  <button
                    onClick={verifyFinding}
                    disabled={verificationLoading}
                    className="text-[10px] text-[#22c55e] border border-[rgba(34,197,94,0.15)] hover:bg-[rgba(34,197,94,0.06)] px-2.5 py-1 rounded-md flex items-center gap-1 transition-colors font-medium disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    {verificationLoading ? (
                      <div className="w-3 h-3 border-2 border-t-[#22c55e] border-[rgba(255,255,255,0.1)] rounded-full animate-spin shrink-0" />
                    ) : (
                      <span className="material-symbols-outlined text-[12px]">fact_check</span>
                    )}
                    {verificationLoading ? t('verification_running_short') : t('verify_fix')}
                  </button>
                </div>
                <div className="text-[10px] text-[#71717a] leading-relaxed border-l border-[rgba(34,197,94,0.16)] pl-2">
                  {t('verification_rescan_hint')}
                </div>
                {agentPrompt && (
                  <textarea
                    value={agentPrompt}
                    readOnly
                    className="w-full min-h-[140px] resize-y rounded-md border border-[rgba(255,255,255,0.06)] bg-[rgba(0,0,0,0.25)] p-2 text-[10px] leading-relaxed text-[#d4d4d8] font-mono outline-none"
                  />
                )}
                {shouldShowVerificationSummary && (
                  <div className="text-[11px] text-[#d4d4d8] leading-relaxed border-l border-[rgba(255,255,255,0.08)] pl-2 py-1 bg-[rgba(255,255,255,0.01)] rounded-r-md">
                    {verificationSummary}
                  </div>
                )}
              </div>
              
              <div className="simple-finding-actions flex items-center gap-1.5 pt-1.5 flex-wrap">
                <button 
                  onClick={e => { 
                    e.stopPropagation(); 
                    if (isTriaging) return;
                    handleTriage(f, 'triage'); 
                  }} 
                  disabled={isTriaging || f.status === 'false_positive'}
                  className="text-[10px] text-[#38bdf8] border border-[rgba(56,189,248,0.15)] hover:bg-[rgba(56,189,248,0.06)] px-2.5 py-1 rounded-md flex items-center gap-1 transition-colors font-medium disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {isTriaging ? (
                    <>
                      <div className="w-3 h-3 border-2 border-t-[#38bdf8] border-[rgba(255,255,255,0.1)] rounded-full animate-spin shrink-0" />
                      <span>Analyzing...</span>
                    </>
                  ) : (
                    <>
                      <span className="material-symbols-outlined text-[12px]">psychology</span>Triage
                    </>
                  )}
                </button>
                <button 
                  onClick={e => { e.stopPropagation(); handleTriage(f, 'false_positive'); }} 
                  className="text-[10px] text-[#71717a] border border-[rgba(255,255,255,0.06)] hover:bg-[rgba(255,255,255,0.03)] px-2.5 py-1 rounded-md flex items-center gap-1 transition-colors font-medium"
                >
                  <span className="material-symbols-outlined text-[12px]">block</span>False Positive
                </button>
                <button 
                  onClick={e => { e.stopPropagation(); handleTriage(f, 'risk_accepted'); }} 
                  className="text-[10px] text-[#f59e0b] border border-[rgba(245,158,11,0.15)] hover:bg-[rgba(245,158,11,0.06)] px-2.5 py-1 rounded-md flex items-center gap-1 transition-colors font-medium"
                >
                  <span className="material-symbols-outlined text-[12px]">verified_user</span>Accept Risk
                </button>
                
                <div className="w-px h-3.5 bg-[rgba(255,255,255,0.06)] mx-1" />
                
                {onNavigateToChat && (
                  <button
                    type="button"
                    onClick={e => { e.stopPropagation(); onNavigateToChat(f); }} 
                    title="Ask AI about this finding"
                    aria-label={`Ask AI about ${f.title}`}
                    className="group/ask h-8 text-[10px] text-[#d9f99d] border border-transparent ring-1 ring-[rgba(132,204,22,0.26)] bg-[linear-gradient(135deg,rgba(132,204,22,0.14),rgba(6,182,212,0.07))] hover:ring-[rgba(132,204,22,0.55)] hover:bg-[linear-gradient(135deg,rgba(132,204,22,0.2),rgba(6,182,212,0.1))] hover:shadow-[0_0_18px_rgba(132,204,22,0.14)] px-3 rounded-md flex items-center gap-1.5 transition-all duration-200 font-semibold focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-[#84cc16]/60"
                  >
                    <span className="material-symbols-outlined text-[15px] text-[#84cc16] group-hover/ask:scale-110 transition-transform duration-200">smart_toy</span>
                    <span>Ask AI</span>
                  </button>
                )}
                
                <button
                  type="button"
                  title="Copy finding context"
                  aria-label={`Copy context for ${f.title}`}
                  onClick={async e => {
                    e.stopPropagation();
                    try {
                      await navigator.clipboard.writeText(`${f.title}\n${f.severity}\n${f.description || ''}\n${f.fix_suggestion || ''}`);
                      setCopiedContext(true);
                      setTimeout(() => setCopiedContext(false), 1500);
                    } catch (err) {
                      console.error('Failed to copy finding context', err);
                    }
                  }} 
                  className={`h-8 w-8 rounded-md border flex items-center justify-center transition-all duration-200 shrink-0 focus-visible:outline-none focus-visible:ring-1 ${
                    copiedContext
                      ? 'text-[#22c55e] border-[rgba(34,197,94,0.35)] bg-[rgba(34,197,94,0.08)] focus-visible:ring-[#22c55e]/60'
                      : 'text-[#71717a] border-[rgba(255,255,255,0.06)] bg-[rgba(255,255,255,0.015)] hover:text-[#d4d4d8] hover:border-[rgba(255,255,255,0.14)] hover:bg-[rgba(255,255,255,0.04)] focus-visible:ring-[#a1a1aa]/50'
                  }`}
                >
                  <span className="material-symbols-outlined text-[14px]">{copiedContext ? 'check' : 'content_copy'}</span>
                </button>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </article>
  );
};

export const SimpleDashboardPage: React.FC<SimpleDashboardPageProps> = ({ onNavigateToChat, onNavigateToReports }) => {
  const { t, i18n } = useTranslation('pages');
  const reduceMotion = useReducedMotion();
  const { findings, loading: findingsLoading, error: findingsError, refresh: refreshFindings } = useFindings() as any;
  const { metrics, loading: metricsLoading, error: metricsError, refresh: refreshMetrics } = useMetrics();
  const { products, loading: productsLoading, error: productsError, refresh: refreshProducts } = useProducts();

  const [globalScanning, setGlobalScanning] = useState(false);
  const [globalScanPath, setGlobalScanPath] = useState('/host');
  void setGlobalScanPath;
  const [globalScanLogs, setGlobalScanLogs] = useState<string[]>([]);
  const [globalScanPhase, setGlobalScanPhase] = useState(0);
  const [globalScanElapsed, setGlobalScanElapsed] = useState(0);
  
  // AI query state

  const scanPhases = [
    { name: 'Core', desc: 'AST parsing & pattern matching', icon: 'memory' },
    { name: 'Semgrep', desc: 'SAST rules & taint analysis', icon: 'shield' },
    { name: 'Gitleaks', desc: 'Secrets & credential detection', icon: 'key' },
    { name: 'Trivy', desc: 'CVE & dependency vulnerabilities', icon: 'inventory_2' },
    { name: 'Bandit', desc: 'Python-specific security checks', icon: 'bug_report' },
  ];
  
  const scanLogMessages = [
    'Indexing source files...', 'Building AST...', 'Running pattern rules...',
    'Checking injection patterns...', 'Scanning for SQL injection...', 'Analyzing auth flows...',
    'Detecting hardcoded secrets...', 'Checking API keys...', 'Scanning .env files...',
    'Resolving dependencies...', 'Checking CVE database...', 'Analyzing lock files...',
    'Scanning Python imports...', 'Checking subprocess calls...', 'Detecting unsafe deserialization...',
    'Analyzing template injection...', 'Checking XSS vectors...', 'Scanning CSRF protections...',
  ];

  const handleGlobalScan = async (path: string) => {
    setGlobalScanning(true);
    setGlobalScanLogs(['Initializing in-place scan...']);
    setGlobalScanPhase(0);
    setGlobalScanElapsed(0);

    const tTimer = setInterval(() => setGlobalScanElapsed(e => e + 1), 1000);
    const pTimer = setInterval(() => setGlobalScanPhase(ph => (ph + 1) % scanPhases.length), 3000);
    const lTimer = setInterval(() => {
      const msg = scanLogMessages[Math.floor(Math.random() * scanLogMessages.length)];
      setGlobalScanLogs(prev => [...prev.slice(-10), msg]);
    }, 700);

    try {
      const res = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ path, external: true }),
      });
      const data = await res.json();
      if (data.ok) {
        runScanCompletionRefreshers({
          findings: refreshFindings,
          metrics: refreshMetrics,
          products: refreshProducts,
        });
      } else {
        alert(data.error || 'Scan failed');
      }
    } catch (err: any) {
      alert(err.message || 'Connection error during scan');
    } finally {
      clearInterval(tTimer);
      clearInterval(pTimer);
      clearInterval(lTimer);
      setGlobalScanning(false);
    }
  };
  void handleGlobalScan;

  const [expandedIds, setExpandedIds] = useState<Set<number>>(new Set());
  const [activeFilter, setActiveFilter] = useState<string | null>(null);
  const [productFilter, setProductFilter] = useState<number | null>(null);
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [groupBy, setGroupBy] = useState<GroupBy>('none');
  const [sortBy, setSortBy] = useState<SortBy>('severity');
  const [page, setPage] = useState(0);
  const [collapsedGroups, setCollapsedGroups] = useState<Set<string>>(new Set());
  const [aiSummary, setAiSummary] = useState<string>('');
  const [aiSummaryLoading, setAiSummaryLoading] = useState(false);
  const [aiSummaryProjectId, setAiSummaryProjectId] = useState<number | null>(null);
  const [aiSummaryLang, setAiSummaryLang] = useState<'en' | 'ru'>('ru');
  const [isAiSummaryExpanded, setIsAiSummaryExpanded] = useState(false);
  const [toolStatus, setToolStatus] = useState<Record<string, boolean>>({});
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
  const [configAutostartFixes, setConfigAutostartFixes] = useState(true);
  const [bulkIgnoreModalOpen, setBulkIgnoreModalOpen] = useState(false);
  const [bulkIgnoreReason, setBulkIgnoreReason] = useState('False Positive');
  const [bulkIgnoring, setBulkIgnoring] = useState(false);
  const [bulkFixCopied, setBulkFixCopied] = useState(false);
  const [scopeType, setScopeType] = useState<'all' | 'activeFile'>('all');
  const [activeFilePath, setActiveFilePath] = useState<string>('');

  useEffect(() => {
    fetch('/api/securecoder/config')
      .then(r => r.json())
      .then(data => {
        if (data.autostartFixes !== undefined) setConfigAutostartFixes(data.autostartFixes);
      })
      .catch(() => {});
  }, []);

  const handleSaveConfig = async (overrideSettings?: any) => {
    try {
      await fetch('/api/securecoder/config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          autostartFixes: overrideSettings?.autostartFixes ?? configAutostartFixes
        })
      });
    } catch (e) {
      console.error(e);
    }
  };

  const handleBulkIgnore = async () => {
    setBulkIgnoring(true);
    try {
      const selectedObjects = findings.filter((f: any) => selectedFindings.has(f.id));
      for (const f of selectedObjects) {
        await fetch(`/api/findings/${f.id}`, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ action: 'status', status: bulkIgnoreReason === 'False Positive' ? 'false_positive' : 'risk_accepted' })
        });
        
        await fetch('/api/securecoder/ignore', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            filePath: f.file_path || '',
            ruleId: f.rule_id || '',
            codeSnippet: f.code_snippet || '',
            lineNumber: f.line_number || 0,
            vulnerabilityClass: f.title || '',
            reason: bulkIgnoreReason
          })
        });
      }
      setSelectedFindings(new Set());
      setBulkIgnoreModalOpen(false);
      refreshFindings?.();
      refreshMetrics?.();
    } catch (e) {
      console.error(e);
    } finally {
      setBulkIgnoring(false);
    }
  };

  const handleBulkFix = () => {
    const selectedObjects = findings.filter((f: any) => selectedFindings.has(f.id));
    if (selectedObjects.length === 0) return;

    let prompt = `Fix these security vulnerabilities in my code:\n\n`;
    selectedObjects.forEach((f: any, idx: number) => {
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

    navigator.clipboard.writeText(prompt);
    setBulkFixCopied(true);
    setTimeout(() => setBulkFixCopied(false), 2000);
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

  // Get products that have findings
  const activeProducts = useMemo(() => {
    if (!findings || !products) return [];
    const ids = new Set<number>();
    findings.forEach((f: Finding) => { if (f.product_id) ids.add(f.product_id); });
    return products.filter(p => ids.has(p.id));
  }, [findings, products]);

  // Load the latest persisted AI summary so it survives page refreshes.
  useEffect(() => {
    const targetId = productFilter ?? [...activeProducts].sort((a, b) => {
      const aCount = findings?.filter((f: Finding) => f.product_id === a.id).length || 0;
      const bCount = findings?.filter((f: Finding) => f.product_id === b.id).length || 0;
      return bCount - aCount;
    })[0]?.id ?? null;
    if (!targetId) return;
    let cancelled = false;
    securityService.getAISummary(targetId, aiSummaryLang, false)
      .then(stored => {
        if (cancelled || !stored) return;
        setAiSummary(stored);
        setAiSummaryProjectId(targetId);
      })
      .catch(() => { /* No persisted summary yet. */ });
    return () => { cancelled = true; };
  }, [productFilter, activeProducts, findings, aiSummaryLang]);

  const loading = findingsLoading || metricsLoading || productsLoading;
  const pageError = findingsError || metricsError || productsError;

  const closedStatuses = ['resolved', 'closed', 'false_positive', 'risk_accepted'];

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
    const penalty = sevCounts.critical * 10 + sevCounts.high * 4 + sevCounts.medium * 1;
    const s = 100 - penalty;
    return s < 0 ? 0 : s;
  }, [sevCounts]);


  // A scanner finding is a hypothesis until someone confirms it. Showing the two
  // apart is what makes a failing gate legible: "0 confirmed, 25 unreviewed"
  // explains itself, where "25 active findings" next to "0 true positives" reads
  // as a contradiction.
  const triageCounts = useMemo(() => {
    const counts = { confirmed: 0, needsReview: 0, suppressed: 0 };
    findings?.forEach((f: Finding) => {
      if (productFilter !== null && f.product_id !== productFilter) return;
      const status = (f.status || 'open').toLowerCase();
      if (['false_positive', 'risk_accepted', 'resolved', 'closed', 'mitigated'].includes(status)) {
        counts.suppressed++;
      } else if (['verified', 'confirmed', 'true_positive'].includes(status)) {
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
      const st = (f.status || 'open').toLowerCase();
      if (closedStatuses.includes(st)) {
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
    if (statusFilter !== 'all') {
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

  const totalPages = Math.ceil(filteredFindings.length / PAGE_SIZE);
  const pagedFindings = groupBy === 'none' ? filteredFindings.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE) : [];

  const toggleGroup = (key: string) => {
    setCollapsedGroups(prev => { const n = new Set(prev); n.has(key) ? n.delete(key) : n.add(key); return n; });
  };

  const [triagingIds, setTriagingIds] = useState<Set<number>>(new Set());

  const handleTriage = async (f: Finding, action: string) => {
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
          alert(data.error || 'AI Triage failed');
        }
      } catch (e) {
        console.error(e);
        alert('Failed to connect to AI Triage service');
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

    try {
      await fetch(`/api/findings/${f.id}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ action: 'status', status: action }) });
      
      if (action === 'false_positive' || action === 'risk_accepted') {
        const reason = action === 'false_positive' ? 'False Positive' : 'Accepted Risk';
        await fetch('/api/securecoder/ignore', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            filePath: f.file_path || '',
            ruleId: f.rule_id || '',
            codeSnippet: f.code_snippet || '',
            lineNumber: f.line_number || 0,
            vulnerabilityClass: f.title || '',
            reason: reason
          })
        });
      }
      refreshFindings?.();
      refreshMetrics?.();
    } catch (e) {
      console.error(e);
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

  const showProjectScore = productFilter !== null;
  const revealTransition = reduceMotion
    ? { duration: 0 }
    : { duration: 0.18, ease: [0.23, 1, 0.32, 1] as [number, number, number, number] };
  const summaryProjectId = productFilter ?? [...activeProducts].sort((a, b) => {
    const aCount = findings?.filter((f: Finding) => f.product_id === a.id).length || 0;
    const bCount = findings?.filter((f: Finding) => f.product_id === b.id).length || 0;
    return bCount - aCount;
  })[0]?.id ?? null;
  const summaryProject = summaryProjectId ? productMap.get(summaryProjectId) : undefined;
  const remediationPercent = projectStats.total > 0
    ? Math.round((projectStats.resolved / projectStats.total) * 100)
    : 0;
  const scannerCount = Object.values(toolStatus).filter(Boolean).length;
  const scannerTotal = Math.max(Object.keys(toolStatus).length, 4);
  const hasCurrentSummary = Boolean(aiSummary && aiSummaryProjectId === summaryProjectId && !aiSummaryLoading);

  const generateAiSummary = async () => {
    if (!summaryProjectId || aiSummaryLoading) return;
    setAiSummary('');
    setAiSummaryLoading(true);
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
                <button onClick={() => { refreshFindings?.(); refreshMetrics?.(); }}>
                  {i18n.language?.startsWith('ru') ? 'Повторить' : 'Retry'}
                </button>
              </div>
            )}

            {aiAvailable === false && (
              <motion.section variants={itemVariants} className="simple-ai-offline" role="status">
                <span className="material-symbols-outlined" aria-hidden="true">info</span>
                <div>
                  <strong>
                    {i18n.language?.startsWith('ru')
                      ? 'Базовый аудит активен. ИИ-триаж выключен — провайдер не настроен.'
                      : 'Basic audit active. AI triage is off — no provider configured.'}
                  </strong>
                  <span>
                    {i18n.language?.startsWith('ru')
                      ? 'Работает без ключа: сканирование, рейтинг безопасности, вердикт политики, отчёты SARIF / CSV / SBOM / для руководства. Требует ключа: автоматический разбор находок на подтверждённые и ложные, PoC и текстовые выводы.'
                      : 'Works without a key: scanning, security score, policy verdict, and SARIF / CSV / SBOM / executive reports. Needs a key: automatic triage into confirmed and false positives, PoC reasoning, and written conclusions.'}
                  </span>
                </div>
              </motion.section>
            )}
            <motion.section variants={itemVariants} className="simple-posture-strip" aria-label={t('securityScore')}>
              <div className="simple-posture-strip__repository">
                <span className="material-symbols-outlined" aria-hidden="true">shield_lock</span>
                <div>
                  <span>{i18n.language?.startsWith('ru') ? 'Репозиторий' : 'Repository'}</span>
                  <strong>{summaryProject?.name || t('allProjects')}</strong>
                </div>
              </div>
              <div className="simple-posture-strip__score">
                <span>{t('securityScore')}</span>
                <strong>{score}<small>/100</small></strong>
                <em className={`simple-risk-label simple-risk-label--${score < 30 ? 'critical' : score < 60 ? 'high' : score < 80 ? 'medium' : 'secure'}`}>
                  {score < 30 ? t('criticalRisk') : score < 60 ? t('highRisk') : score < 80 ? t('mediumRisk') : t('secureStatus')}
                </em>
              </div>
              <div className="simple-posture-strip__triage" title={i18n.language?.startsWith('ru')
                ? 'Находка от сканера — это гипотеза, пока её не подтвердили. Непроверенные считаются открытыми, потому что они не разобраны, а не потому что доказаны.'
                : 'A scanner finding is a hypothesis until someone confirms it. Unreviewed findings count as open because they are unresolved, not because they are proven.'}>
                <span>{i18n.language?.startsWith('ru') ? 'Подтверждено' : 'Confirmed'}: <strong>{triageCounts.confirmed}</strong></span>
                <span>{i18n.language?.startsWith('ru') ? 'Требуют проверки' : 'Needs review'}: <strong>{triageCounts.needsReview}</strong></span>
                <span>{i18n.language?.startsWith('ru') ? 'Подавлено' : 'Suppressed'}: <strong>{triageCounts.suppressed}</strong></span>
              </div>
              <div className="simple-posture-strip__severities" aria-label={i18n.language?.startsWith('ru') ? 'Распределение по критичности' : 'Severity distribution'}>
                {([
                  { key: 'critical', label: i18n.language?.startsWith('ru') ? 'Критические' : 'Critical', count: sevCounts.critical },
                  { key: 'high', label: i18n.language?.startsWith('ru') ? 'Высокие' : 'High', count: sevCounts.high },
                  { key: 'medium', label: i18n.language?.startsWith('ru') ? 'Средние' : 'Medium', count: sevCounts.medium },
                  { key: 'low', label: i18n.language?.startsWith('ru') ? 'Низкие' : 'Low', count: sevCounts.low },
                ] as const).map(item => (
                  <button
                    key={item.key}
                    type="button"
                    onClick={() => { setActiveFilter(item.key); setPage(0); }}
                    className={`simple-posture-severity simple-posture-severity--${item.key}`}
                  >
                    <span>{item.label}</span>
                    <strong>{item.count}</strong>
                  </button>
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

            <motion.section
              variants={itemVariants}
              className={`simple-ai-command ${isAiSummaryExpanded ? 'simple-ai-command--expanded' : ''}`}
              aria-label={t('aiSecuritySummary')}
            >
              <div className="simple-ai-command__heading">
                <span className="material-symbols-outlined" aria-hidden="true">psychology</span>
                <strong>{t('aiSecuritySummary')}</strong>
              </div>
              <div className="simple-ai-command__status" aria-label={i18n.language?.startsWith('ru') ? 'Готовность данных' : 'Data readiness'}>
                <span><i />{i18n.language?.startsWith('ru') ? 'Репозиторий готов' : 'Repository ready'}</span>
                <span><i />{i18n.language?.startsWith('ru') ? `Сканеры ${scannerCount}/${scannerTotal}` : `Scanners ${scannerCount}/${scannerTotal}`}</span>
                <span><i />{i18n.language?.startsWith('ru') ? 'Данные актуальны' : 'Data current'}</span>
              </div>
              <p className="simple-ai-command__copy">
                {aiSummary && aiSummaryProjectId === summaryProjectId
                  ? (i18n.language?.startsWith('ru') ? 'Сводка сохранена и готова к просмотру.' : 'The saved summary is ready to review.')
                  : (i18n.language?.startsWith('ru')
                    ? 'Получите краткий разбор риска и порядок исправления с помощью SecureCoder.'
                    : 'Generate a concise risk review and remediation order with SecureCoder.')}
              </p>
              <div className="simple-ai-command__actions">
                <select value={aiSummaryLang} onChange={event => setAiSummaryLang(event.target.value as 'en' | 'ru')} aria-label={i18n.language?.startsWith('ru') ? 'Язык сводки' : 'Summary language'}>
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
                  disabled={!summaryProjectId || aiSummaryLoading}
                >
                  <span className="material-symbols-outlined" aria-hidden="true">{hasCurrentSummary ? 'refresh' : 'auto_awesome'}</span>
                  {aiSummaryLoading
                    ? (i18n.language?.startsWith('ru') ? 'Анализируем' : 'Analyzing')
                    : (hasCurrentSummary ? (i18n.language?.startsWith('ru') ? 'Обновить' : 'Regenerate') : (i18n.language?.startsWith('ru') ? 'Сгенерировать сводку' : 'Generate summary'))}
                </button>
              </div>
              <AnimatePresence initial={false}>
                {isAiSummaryExpanded && aiSummaryProjectId === summaryProjectId && (aiSummaryLoading || aiSummary) && (
                  <motion.div className="simple-ai-command__content" initial={reduceMotion ? false : { opacity: 0, transform: 'translateY(-6px)' }} animate={{ opacity: 1, transform: 'translateY(0)' }} exit={reduceMotion ? { opacity: 0 } : { opacity: 0, transform: 'translateY(-6px)' }} transition={revealTransition}>
                    {aiSummaryLoading ? (
                      <div className="simple-ai-command__loading" aria-live="polite"><span /><span /><span />{i18n.language?.startsWith('ru') ? 'Анализируем репозиторий' : 'Analyzing repository'}</div>
                    ) : (
                      <div className="simple-ai-command__markdown"><Markdown>{aiSummary}</Markdown></div>
                    )}
                  </motion.div>
                )}
              </AnimatePresence>
            </motion.section>

            {/* ── TOP BENTO ROW ── */}
            <div className="hidden grid grid-cols-1 lg:grid-cols-3 gap-6 items-stretch">
              
              {/* Score Card */}
              {showProjectScore && (
              <motion.div
                variants={itemVariants}
                className="lg:col-span-1 border border-[rgba(255,255,255,0.06)] rounded-2xl p-6 bg-background/80 backdrop-blur-xl flex flex-col justify-between shadow-2xl relative overflow-hidden min-h-[260px] h-full group"
              >
                {/* Advanced Animated Background Glow */}
                <div className="absolute inset-0 overflow-hidden pointer-events-none rounded-2xl">
                  <div 
                    className="absolute -top-[100px] -right-[50px] w-[300px] h-[300px] rounded-full mix-blend-screen opacity-20 filter blur-[90px] group-hover:opacity-30 transition-all duration-700 ease-in-out group-hover:scale-110"
                    style={{
                      background: 'radial-gradient(circle, var(--accent-color) 0%, transparent 70%)'
                    }}
                  />
                  <div 
                    className="absolute -bottom-[100px] -left-[50px] w-[200px] h-[200px] rounded-full mix-blend-screen opacity-10 filter blur-[70px] group-hover:opacity-20 transition-all duration-1000 ease-in-out group-hover:scale-125 delay-150"
                    style={{
                      background: 'radial-gradient(circle, var(--accent-color-hover) 0%, transparent 70%)'
                    }}
                  />
                </div>

                {/* Optional glassmorphism overlay */}
                <div className="absolute inset-0 bg-gradient-to-br from-[rgba(255,255,255,0.03)] to-[rgba(255,255,255,0.005)] rounded-2xl pointer-events-none" />

                {/* Header Section */}
                <div className="flex items-start justify-between z-10">
                  <div>
                    <div className="flex items-center gap-2 mb-1">
                      <div className="w-6 h-6 rounded-md bg-[rgba(255,255,255,0.06)] border border-[rgba(255,255,255,0.05)] flex items-center justify-center shadow-inner">
                        <span className="material-symbols-outlined text-[14px] text-[#e4e4e7]">security</span>
                      </div>
                      <h3 className="text-sm font-semibold text-[#f4f4f5] tracking-wide font-sans uppercase">
                        {t('securityScore')}
                      </h3>
                    </div>
                    <div className="text-[11px] text-[#71717a] font-mono tracking-wider ml-8 uppercase">
                      {productFilter !== null && productMap.has(productFilter) 
                        ? `${productMap.get(productFilter)!.name}` 
                        : t('allProjects')}
                    </div>
                  </div>
                  
                  {/* Premium Status Badge */}
                  <div 
                    className="relative flex items-center gap-1.5 px-2.5 py-1 rounded-full border shadow-sm backdrop-blur-md"
                    style={{
                      color: 'var(--accent-color)',
                      backgroundColor: 'var(--accent-color-soft)',
                      borderColor: 'var(--accent-color-line)'
                    }}
                  >
                    <span className="relative flex h-2 w-2">
                      <span className="animate-ping absolute inline-flex h-full w-full rounded-full opacity-75" style={{ backgroundColor: 'var(--accent-color)' }}></span>
                      <span className="relative inline-flex rounded-full h-2 w-2" style={{ backgroundColor: 'var(--accent-color)' }}></span>
                    </span>
                    <span className="text-[10px] font-bold tracking-widest uppercase">
                      {score < 30 ? t('criticalRisk') : score < 60 ? t('highRisk') : score < 80 ? t('mediumRisk') : t('secureStatus')}
                    </span>
                  </div>
                </div>

                {/* Middle: Gauge (Left) and Severity bars (Right) side-by-side */}
                <div className="flex gap-6 items-center my-5 relative z-10 flex-1">
                  {/* Left Column: Radial Progress Gauge (Redesigned) */}
                  <div className="relative shrink-0 group-hover:scale-105 transition-transform duration-500 ease-out">
                    <svg className="w-[110px] h-[110px] transform -rotate-90 filter drop-shadow-xl overflow-visible" viewBox="0 0 100 100" style={{ overflow: 'visible' }}>
                      <circle
                        cx="50"
                        cy="50"
                        r="42"
                        className="stroke-[rgba(255,255,255,0.04)] fill-none"
                        strokeWidth="8"
                      />
                      <circle
                        cx="50"
                        cy="50"
                        r="42"
                        className="fill-none stroke-current transition-all duration-1500 ease-out"
                        strokeWidth="8"
                        strokeDasharray={2 * Math.PI * 42}
                        strokeDashoffset={2 * Math.PI * 42 * (1 - score / 100)}
                        strokeLinecap="round"
                        style={{
                          color: 'var(--accent-color)',
                          filter: 'drop-shadow(0 0 8px var(--accent-color-line))'
                        }}
                      />
                    </svg>
                    <div className="absolute inset-0 flex flex-col items-center justify-center">
                      <span 
                        className="text-[34px] font-black tracking-tighter leading-none"
                        style={{
                          background: 'linear-gradient(135deg, #ffffff 0%, var(--accent-color) 100%)',
                          WebkitBackgroundClip: 'text',
                          WebkitTextFillColor: 'transparent',
                          filter: 'drop-shadow(0px 2px 4px rgba(0,0,0,0.4))'
                        }}
                      >
                        {score}
                      </span>
                      <span className="text-[9px] text-[#71717a] font-bold tracking-[0.2em] mt-0.5 uppercase">
                        {i18n.language?.startsWith('ru') ? 'ИЗ 100' : 'SCORE'}
                      </span>
                    </div>
                  </div>

                  {/* Right Column: High-density Severity list */}
                  <div className="flex-1 flex flex-col justify-center space-y-2.5">
                    {(['critical', 'high', 'medium', 'low'] as const).map(s => {
                      const count = sevCounts[s];
                      const color = sevDot(s);
                      const totalCount = sevCounts.critical + sevCounts.high + sevCounts.medium + sevCounts.low;
                      const pct = totalCount > 0 ? (count / totalCount) * 100 : 0;
                      return (
                        <div key={s} className="flex flex-col gap-1.5 group/bar cursor-default">
                          <div className="flex items-center justify-between text-xs font-mono leading-none">
                            <span className="flex items-center gap-1.5 text-[#a1a1aa] uppercase text-[10px] tracking-wider font-semibold transition-colors group-hover/bar:text-[#e4e4e7]">
                              <span className="w-1.5 h-1.5 rounded-full shrink-0 shadow-[0_0_4px_currentColor]" style={{ backgroundColor: color, color: color }} />
                              {s === 'critical' ? (i18n.language?.startsWith('ru') ? 'Крит' : 'Crit') : s === 'high' ? (i18n.language?.startsWith('ru') ? 'Высок' : 'High') : s === 'medium' ? (i18n.language?.startsWith('ru') ? 'Сред' : 'Med') : (i18n.language?.startsWith('ru') ? 'Низк' : 'Low')}
                            </span>
                            <span className="font-bold text-[11px] transition-colors" style={{ color: count > 0 ? color : '#52525b' }}>{count}</span>
                          </div>
                          <div className="w-full h-1.5 bg-[rgba(255,255,255,0.03)] rounded-full overflow-hidden shadow-inner border border-[rgba(255,255,255,0.02)]">
                            <div 
                              className="h-full rounded-full transition-all duration-1000 ease-out relative" 
                              style={{ 
                                width: `${pct}%`, 
                                backgroundColor: color,
                                opacity: count > 0 ? 1 : 0.1,
                                boxShadow: count > 0 ? `0 0 8px ${color}80` : 'none'
                              }} 
                            />
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>

                {/* Remediation/Resolution progress bar */}
                {metrics && (
                  <div className="border-t border-[rgba(255,255,255,0.04)] pt-4 mt-1 z-10 font-mono">
                    <div className="flex justify-between items-center text-[10px] text-[#a1a1aa] font-bold uppercase tracking-widest mb-2">
                      <span className="flex items-center gap-1.5">
                        <span className="material-symbols-outlined text-[13px]" style={{ color: 'var(--accent-color)' }}>fact_check</span>
                        {t('remediationProgress')}
                      </span>
                      <span className="text-[#f4f4f5] tabular-nums">
                        {projectStats.total > 0 
                          ? `${Math.round((projectStats.resolved / projectStats.total) * 100)}%` 
                          : '0%'}
                      </span>
                    </div>
                    <div className="w-full h-2 bg-[rgba(255,255,255,0.03)] rounded-full overflow-hidden shadow-inner border border-[rgba(255,255,255,0.02)] relative p-[1px]">
                      <div 
                        className="h-full rounded-full transition-all duration-1000 ease-out relative overflow-hidden"
                        style={{
                          width: `${projectStats.total > 0 ? (projectStats.resolved / projectStats.total) * 100 : 0}%`,
                          background: 'linear-gradient(90deg, var(--accent-color-hover) 0%, var(--accent-color) 100%)',
                          boxShadow: '0 0 10px var(--accent-color-line)'
                        }}
                      />
                    </div>
                    <div className="flex justify-between text-[10px] text-[#52525b] mt-2 font-medium tracking-wide">
                      <span>{t('resolvedCount', { count: projectStats.resolved })}</span>
                      <span>{t('totalFindingsCount', { count: projectStats.total })}</span>
                    </div>
                  </div>
                )}
              </motion.div>
              )}

              {/* ── AI Security Summary Section ── */}
              <div className={showProjectScore ? 'lg:col-span-2' : 'lg:col-span-3'}>
                {(() => {
                  const summaryProjectId = productFilter ?? activeProducts.sort((a, b) => {
                    const aCount = findings?.filter((f: Finding) => f.product_id === a.id).length || 0;
                    const bCount = findings?.filter((f: Finding) => f.product_id === b.id).length || 0;
                    return bCount - aCount;
                  })[0]?.id ?? null;

                  if (!summaryProjectId || !productMap.has(summaryProjectId)) {
                    return (
                      <motion.div variants={itemVariants} className="h-full border border-dashed border-[rgba(139,92,246,0.2)] rounded-xl p-6 bg-[rgba(139,92,246,0.02)] flex flex-col justify-center items-center gap-3 text-center min-h-[250px]">
                        <span className="material-symbols-outlined text-[32px] text-[#3f3f46]">analytics</span>
                        <div>
                          <div className="text-[14px] font-medium text-[#71717a] mb-1">No projects scanned yet</div>
                          <div className="text-[12px] text-[#52525b]">Scan a repository from the sidebar to generate an AI security summary</div>
                        </div>
                      </motion.div>
                    );
                  }

                  const proj = productMap.get(summaryProjectId)!;

                  return (
                    <motion.div variants={itemVariants} className="h-full rounded-xl overflow-hidden border border-[rgba(255,255,255,0.08)] bg-gradient-to-br from-[rgba(255,255,255,0.02)] to-[rgba(255,255,255,0.005)] shadow-lg p-5 relative flex flex-col min-h-[250px]">
                      {/* Header */}
                      <div className="flex items-center justify-between mb-4 border-b border-[rgba(255,255,255,0.06)] pb-3 shrink-0">
                        <div className="flex items-center gap-2">
                          <span className="material-symbols-outlined text-lg text-[#71717a]">psychology</span>
                          <span className="text-xs text-[#e4e4e7] uppercase tracking-[0.15em] font-bold">{t('aiSecuritySummary')}</span>
                        </div>
                        <div className="flex items-center gap-2.5">
                          <select value={aiSummaryLang} onChange={e => setAiSummaryLang(e.target.value as 'en' | 'ru')}
                            className="text-xs text-[#a1a1aa] bg-[rgba(255,255,255,0.04)] border border-[rgba(255,255,255,0.08)] rounded px-2.5 py-1 outline-none hover:border-[rgba(255,255,255,0.12)] transition-colors font-bold tracking-wider uppercase font-sans cursor-pointer">
                            <option value="ru">RU</option>
                            <option value="en">EN</option>
                          </select>
                          {activeProducts.length > 1 && (
                            <select value={summaryProjectId} onChange={e => setProductFilter(Number(e.target.value))}
                              className="text-xs text-[#a1a1aa] bg-[rgba(255,255,255,0.04)] border border-[rgba(255,255,255,0.08)] rounded px-2.5 py-1 outline-none hover:border-[rgba(255,255,255,0.12)] transition-colors font-bold tracking-wider uppercase font-sans max-w-[150px] cursor-pointer">
                              {activeProducts.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}
                            </select>
                          )}
                          {aiSummaryProjectId === summaryProjectId && aiSummary && !aiSummaryLoading && (
                            <button onClick={() => { setAiSummary(''); setAiSummaryProjectId(null); }}
                              className="text-xs text-[#71717a] hover:text-[#e4e4e7] transition-colors flex items-center gap-1.5 font-bold uppercase tracking-wider font-mono">
                              <span className="material-symbols-outlined text-[13px]">refresh</span>Regenerate
                            </button>
                          )}
                        </div>
                      </div>

                      {/* AI Summary Content */}
                      <div className="flex-1 overflow-y-auto pr-2" style={{ scrollbarWidth: 'thin', scrollbarColor: 'rgba(255,255,255,0.06) transparent' }}>
                        {aiSummaryLoading && aiSummaryProjectId === summaryProjectId ? (
                          <div className="flex flex-col items-center justify-center h-full gap-3 text-[#71717a] min-h-[140px]">
                            <div className="flex gap-1.5">
                              {[0, 1, 2].map(i => (
                                <div key={i} className="w-2 h-2 rounded-full bg-[#52525b] animate-bounce" style={{ animationDelay: `${i * 150}ms` }} />
                              ))}
                            </div>
                            <span className="text-xs font-mono tracking-widest uppercase">Analyzing repository security...</span>
                          </div>
                        ) : aiSummaryProjectId === summaryProjectId && aiSummary ? (
                          <div className="text-[13px] text-[#a1a1aa] leading-relaxed prose prose-invert max-w-none [&_strong]:text-[#e4e4e7] [&_strong]:font-semibold [&_code]:text-[#e4e4e7] [&_code]:bg-[#27272a] [&_code]:border [&_code]:border-[#3f3f46] [&_code]:px-1.5 [&_code]:py-0.5 [&_code]:rounded-md [&_code]:text-[12px] [&_p]:mb-2.5 last:[&_p]:mb-0 select-text">
                            <Markdown>{aiSummary}</Markdown>
                          </div>
                        ) : (
                          <div className="grid grid-cols-1 md:grid-cols-12 gap-6 h-full items-center min-h-[140px]">
                            {/* Left: System Specifications */}
                            <div className="md:col-span-7 md:border-r border-[rgba(255,255,255,0.06)] pr-5 space-y-3 flex flex-col justify-center h-full">
                              <div className="flex items-center gap-1.5">
                                <span className="material-symbols-outlined text-sm text-[var(--accent-color)]">folder_open</span>
                                <span className="text-xs text-[#71717a] font-mono tracking-widest uppercase font-bold">ACTIVE REPOSITORY</span>
                              </div>
                              <div className="text-base font-extrabold text-white tracking-tight">{proj.name}</div>
                              <div className="grid grid-cols-2 gap-2.5 pt-1">
                                {[
                                  { name: 'Trivy', key: 'trivy', label: 'Deps & Vulns' },
                                  { name: 'Semgrep', key: 'semgrep', label: 'SAST Engine' },
                                  { name: 'Gitleaks', key: 'gitleaks', label: 'Secrets Scan' },
                                  { name: 'Bandit', key: 'bandit', label: 'Python SAST' }
                                ].map(tool => {
                                  const installed = toolStatus[tool.key];
                                  return (
                                    <div key={tool.key} className="flex items-center gap-2.5 p-2 rounded-lg bg-[rgba(255,255,255,0.015)] border border-[rgba(255,255,255,0.04)]">
                                      <div className={`w-2 h-2 rounded-full shrink-0 ${installed ? 'bg-[#22c55e]' : 'bg-[#ef4444]'}`} />
                                      <div className="flex-1 min-w-0 font-mono">
                                        <div className="text-xs text-[#e4e4e7] font-bold leading-none">{tool.name}</div>
                                        <div className="text-[10px] text-[#71717a] mt-1 leading-none">{tool.label}</div>
                                      </div>
                                    </div>
                                  );
                                })}
                              </div>
                            </div>

                            {/* Right: Neural Prompt activation */}
                            <div className="md:col-span-5 flex flex-col items-center justify-center text-center p-4 rounded-xl bg-[rgba(255,255,255,0.015)] border border-[rgba(255,255,255,0.05)] relative overflow-hidden group h-full">
                              <div className="absolute inset-0 bg-radial-gradient from-[rgba(139,92,246,0.02)] to-transparent pointer-events-none group-hover:opacity-100 transition-opacity" />
                              <span className="material-symbols-outlined text-[30px] text-[var(--accent-color)] animate-pulse mb-2">psychology</span>
                              <p className="text-xs text-[#a1a1aa] leading-normal max-w-[220px] mb-4">
                                Generate summary utilizing SecureCoder LLM agent pipeline
                              </p>
                              <button
                                onClick={async () => {
                                  setAiSummary('');
                                  setAiSummaryLoading(true);
                                  setAiSummaryProjectId(summaryProjectId);
                                  try {
                                    const summary = await securityService.getAISummary(summaryProjectId, aiSummaryLang, true);
                                    setAiSummary(summary || 'No response');
                                  } catch (err) {
                                    setAiSummary('Failed to generate summary. Check API key configuration.');
                                  } finally {
                                    setAiSummaryLoading(false);
                                  }
                                }}
                                className="btn-ai-generate w-full py-2.5 rounded-lg text-xs font-bold tracking-widest uppercase transition-all shadow-md flex items-center justify-center gap-1.5 cursor-pointer"
                              >
                                <span className="material-symbols-outlined text-sm">bolt</span>
                                {t('generate')}
                              </button>
                            </div>
                          </div>
                        )}
                      </div>
                    </motion.div>
                  );
                })()}
              </div>
            </div>

            {/* Urgency Banner */}
            {sevCounts.critical > 0 && (
              <motion.div variants={itemVariants} className="hidden flex items-center gap-4 px-5 py-3 rounded-xl border border-[rgba(239,68,68,0.15)] bg-gradient-to-r from-[rgba(239,68,68,0.06)] to-[rgba(239,68,68,0.01)] shadow-sm">
                <span className="material-symbols-outlined text-[#ef4444] text-[20px] animate-pulse">warning</span>
                <div className="flex-1">
                  <span className="text-[13px] text-[#f4f4f5] font-semibold tracking-wide">{sevCounts.critical} {sevCounts.critical === 1 ? t('criticalIssueRequires') : t('criticalIssuesRequire')} {t('immediateAttention')}</span>
                  <span className="text-[12px] text-[#a1a1aa] ml-2 font-mono">— {sevCounts.high} {t('highSeverityAlsoPending')}</span>
                </div>
                <button onClick={() => { setActiveFilter('critical'); setPage(0); }}
                  className="text-[11px] text-[#ef4444] border border-[rgba(239,68,68,0.25)] hover:bg-[rgba(239,68,68,0.1)] font-bold px-3.5 py-1.2 rounded-lg transition-colors shrink-0 uppercase tracking-wider font-mono">
                  {t('showCritical')}
                </button>
              </motion.div>
            )}

            {/* ── MAIN CONTENT SPLIT ── */}
            <div className="simple-workspace-grid grid grid-cols-1 gap-4 items-start">
              
              {/* LEFT: Findings & Toolbar */}
              <div className="simple-findings-column space-y-3 min-w-0">
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
                        SELECTED
                      </div>
                      <button
                        onClick={() => setSelectedFindings(new Set())}
                        className="flex items-center gap-1.5 text-[10px] font-mono font-bold uppercase tracking-wider transition-colors duration-200 cursor-pointer text-[#52525b] hover:text-[var(--accent-color)]"
                      >
                        <span className="material-symbols-outlined text-[13px]">close</span>
                        CLEAR SELECTION
                      </button>
                    </div>

                    {/* Divider */}
                    <div className="w-px self-stretch" style={{ background: 'rgba(255,255,255,0.06)' }} />

                    {/* Right: actions */}
                    <div className="flex items-center gap-2.5 relative z-10">
                      {/* Fix Mode select */}
                      <div className="relative">
                        <select
                          value={configAutostartFixes ? 'auto' : 'review'}
                          onChange={async (e) => {
                            const auto = e.target.value === 'auto';
                            setConfigAutostartFixes(auto);
                            await handleSaveConfig({ autostartFixes: auto });
                          }}
                          className="appearance-none pl-3.5 pr-8 py-1.5 rounded-lg text-[11px] font-mono font-semibold uppercase tracking-wider outline-none cursor-pointer transition-[color,background-color,border-color] duration-150 bg-[var(--simple-surface-2)] border border-[var(--simple-line)] text-[var(--simple-fg-soft)] hover:text-[var(--simple-fg)] hover:border-[var(--simple-surface-3)] focus:border-[var(--simple-accent-line)]"
                          style={{
                            backgroundImage: `url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='10' height='10' viewBox='0 0 24 24' fill='none' stroke='%2371717a' stroke-width='2'%3E%3Cpath d='m6 9 6 6 6-6'/%3E%3C/svg%3E")`,
                            backgroundRepeat: 'no-repeat',
                            backgroundPosition: 'right 8px center',
                            backgroundSize: '8px'
                          }}
                        >
                          <option value="auto" className="bg-[#111113] text-[#f4f4f5]">Fix Mode: Auto</option>
                          <option value="review" className="bg-[#111113] text-[#f4f4f5]">Fix Mode: Review First</option>
                        </select>
                      </div>

                      {/* Fix Selected – primary accent filled with translate hover */}
                      <button
                        onClick={handleBulkFix}
                        className="flex items-center gap-1.5 pl-3.5 pr-4 py-1.5 rounded-lg text-[11px] font-bold uppercase tracking-widest transition-[background-color,transform] duration-150 cursor-pointer bg-[var(--simple-accent)] hover:bg-[var(--simple-accent-hover)] text-[var(--accent-color-on-text)] active:scale-[0.97]"
                      >
                        <span className="material-symbols-outlined text-[14px]">{bulkFixCopied ? 'check' : 'auto_fix_high'}</span>
                        {bulkFixCopied ? 'Copied!' : 'Fix Selected'}
                      </button>

                      {/* Ignore Selected – secondary ghost outline with translate hover */}
                      <button
                        onClick={() => setBulkIgnoreModalOpen(true)}
                        className="flex items-center gap-1.5 pl-3.5 pr-4 py-1.5 rounded-lg text-[11px] font-bold uppercase tracking-widest transition-[color,background-color,border-color,transform] duration-150 cursor-pointer bg-[var(--simple-surface-2)] border border-[var(--simple-line)] text-[var(--simple-fg-soft)] hover:text-[var(--simple-fg)] hover:bg-[var(--simple-surface-3)] active:scale-[0.97]"
                      >
                        <span className="material-symbols-outlined text-[14px]">do_not_disturb_on</span>
                        Ignore Selected
                      </button>
                    </div>
                  </motion.div>
                )}

                {/* ── Toolbar ── */}
                <motion.div variants={itemVariants} className="simple-command-surface space-y-2 p-3 rounded-xl">
                  <div className="simple-command-header">
                    <div>
                      <h2>{i18n.language?.startsWith('ru') ? 'Очередь уязвимостей' : 'Vulnerability queue'}</h2>
                      <span>{filteredFindings.length} {i18n.language?.startsWith('ru') ? 'находок в текущем представлении' : 'findings in the current view'}</span>
                    </div>
                    <div className="simple-command-header__actions">
                      <button ref={secureCoderTriggerRef} type="button" onClick={() => { setIsProjectsPanelOpen(false); setIsSecureCoderOpen(true); }} aria-haspopup="dialog" aria-expanded={isSecureCoderOpen} className="simple-command-header__primary">
                        <span className="material-symbols-outlined" aria-hidden="true">security</span>
                        <span><strong>SecureCoder</strong><small>{i18n.language?.startsWith('ru') ? 'Основной ИИ-инструмент исправления' : 'Primary AI remediation tool'}</small></span>
                      </button>
                      <button ref={projectsTriggerRef} type="button" onClick={() => { setIsSecureCoderOpen(false); handleToggleProjectsPanel(); }} aria-haspopup="dialog" aria-expanded={isProjectsPanelOpen}>
                        <span className="material-symbols-outlined" aria-hidden="true">folder_scan</span>
                        {i18n.language?.startsWith('ru') ? 'Сканирование проектов' : 'Project scanning'}
                      </button>
                    </div>
                  </div>
                  {/* Row 1: Filters & Search */}
                  <div className="flex items-center justify-between gap-4 flex-wrap">
                    <div className="flex items-center gap-3 flex-wrap">
                      {/* Select All Checkbox */}
                      <div className="flex items-center justify-center border-r border-[rgba(255,255,255,0.06)] pr-3">
                        <input
                          type="checkbox"
                          checked={filteredFindings.length > 0 && filteredFindings.every(f => selectedFindings.has(f.id))}
                          ref={el => {
                            if (el) {
                              const selCount = filteredFindings.filter(f => selectedFindings.has(f.id)).length;
                              el.indeterminate = selCount > 0 && selCount < filteredFindings.length;
                            }
                          }}
                          onChange={(e) => {
                            const checked = e.target.checked;
                            setSelectedFindings(prev => {
                              const next = new Set(prev);
                              filteredFindings.forEach(f => {
                                if (checked) {
                                  next.add(f.id);
                                } else {
                                  next.delete(f.id);
                                }
                              });
                              return next;
                            });
                          }}
                          className="accent-[var(--accent-color)] cursor-pointer select-checkbox w-3.5 h-3.5 rounded bg-[rgba(255,255,255,0.02)] border border-[rgba(255,255,255,0.08)]"
                          title="Select All"
                        />
                      </div>

                      {/* Scope Toggles */}
                      <div className="flex items-center gap-1.5 border-r border-[rgba(255,255,255,0.06)] pr-3">
                        <button
                          onClick={() => setScopeType(scopeType === 'all' ? 'activeFile' : 'all')}
                          className={`flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider transition-all border ${
                            scopeType === 'activeFile'
                              ? 'border-[var(--accent-color-line)] bg-[var(--accent-color-soft)] text-[var(--accent-color)] font-semibold'
                              : 'border-[rgba(255,255,255,0.03)] bg-[rgba(255,255,255,0.015)] text-[#a1a1aa] hover:text-white'
                          }`}
                          title="Toggle Active File scope"
                        >
                          <span className="material-symbols-outlined text-[12px]">{scopeType === 'activeFile' ? 'description' : 'folder_copy'}</span>
                          {scopeType === 'activeFile' ? 'Active' : 'All'}
                        </button>

                        {scopeType === 'activeFile' && (
                          <select
                            value={activeFilePath}
                            onChange={e => { setActiveFilePath(e.target.value); setPage(0); }}
                            className="bg-[rgba(255,255,255,0.015)] border border-[rgba(255,255,255,0.04)] rounded px-1.5 py-0.5 text-[10px] text-white outline-none hover:border-[rgba(255,255,255,0.08)] transition-all cursor-pointer font-mono max-w-[120px]"
                          >
                            <option value="">-- Active File --</option>
                            {uniqueFilePaths.map(path => (
                              <option key={path} value={path}>{path.split('/').pop()}</option>
                            ))}
                          </select>
                        )}
                      </div>

                      {/* Severity pills */}
                      <div className="flex items-center gap-1.5 flex-wrap">
                        {[
                          { key: null, label: t('filterAll'), count: findings?.length ?? 0 },
                          { key: 'critical', label: t('severityCritical'), count: sevCounts.critical, color: '#ef4444' },
                          { key: 'high', label: t('severityHigh'), count: sevCounts.high, color: '#f97316' },
                          { key: 'medium', label: t('severityMedium'), count: sevCounts.medium, color: '#eab308' },
                          { key: 'low', label: t('severityLow'), count: sevCounts.low, color: '#3f3f46' },
                        ].map(f => (
                          <button key={f.key ?? 'all'} onClick={() => { setActiveFilter(f.key); setPage(0); }}
                            className={`flex items-center gap-1.5 px-2.5 py-1 rounded-md text-[11px] font-medium transition-all border ${activeFilter === f.key ? 'border-[rgba(255,255,255,0.12)] bg-[rgba(255,255,255,0.06)] text-white shadow-sm font-semibold' : 'border-[rgba(255,255,255,0.03)] bg-[rgba(255,255,255,0.015)] text-[#a1a1aa] hover:text-white hover:bg-[rgba(255,255,255,0.03)]'}`}>
                            {f.color && <span className="w-1.5 h-1.5 rounded-full shrink-0" style={{ backgroundColor: f.color }} />}{f.label} 
                            <span className="text-[10px] opacity-50 font-mono ml-0.5">({f.count})</span>
                          </button>
                        ))}
                      </div>
                    </div>

                    {/* Search */}
                    <div className="flex items-center gap-2 flex-1 md:flex-none justify-end min-w-[240px]">
                      <div className="relative w-full">
                        <span className="material-symbols-outlined text-[14px] text-[#52525b] absolute left-2.5 top-1/2 -translate-y-1/2">search</span>
                        <input 
                          value={searchQuery} 
                          onChange={e => { setSearchQuery(e.target.value); setPage(0); }} 
                          placeholder={t('searchPlaceholder')}
                          className="w-full bg-[rgba(0,0,0,0.15)] border border-[rgba(255,255,255,0.05)] rounded-md pl-8 pr-3 py-1 text-[12px] text-[#f4f4f5] placeholder:text-[#52525b] outline-none focus:border-[var(--accent-color)] focus:bg-[rgba(0,0,0,0.25)] transition-all shadow-inner font-sans" 
                        />
                      </div>
                      <div className="text-[12px] text-[#52525b] font-sans shrink-0 bg-[rgba(255,255,255,0.02)] px-2 py-1 rounded-md border border-[rgba(255,255,255,0.03)]">
                        {filteredFindings.length} ISSUES
                      </div>
                    </div>
                  </div>

                  <div className="h-px w-full bg-[rgba(255,255,255,0.04)]" />

                  {/* Row 2: Selects & Active Filters */}
                  <div className="flex items-center justify-between gap-4 flex-wrap">
                    <div className="flex items-center gap-2 flex-wrap">
                      {/* Product filter */}
                      {activeProducts.length > 0 && (
                        <select 
                          value={productFilter ?? ''} 
                          onChange={e => { setProductFilter(e.target.value ? Number(e.target.value) : null); setPage(0); }}
                          className="bg-[rgba(255,255,255,0.015)] border border-[rgba(255,255,255,0.04)] rounded-md px-2.5 py-1 text-[12px] uppercase font-sans tracking-wider text-[#a1a1aa] hover:text-white hover:border-[rgba(255,255,255,0.08)] transition-all cursor-pointer appearance-none pr-6 outline-none shadow-sm"
                          style={{ 
                            backgroundImage: `url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='10' height='10' viewBox='0 0 24 24' fill='none' stroke='%2371717a' stroke-width='2'%3E%3Cpath d='m6 9 6 6 6-6'/%3E%3C/svg%3E")`, 
                            backgroundRepeat: 'no-repeat', 
                            backgroundPosition: 'right 6px center',
                            backgroundSize: '8px'
                          }}
                        >
                          <option value="">{t('allProjects')}</option>
                          {activeProducts.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}
                        </select>
                      )}
                      
                      <select 
                        value={statusFilter} 
                        onChange={e => { setStatusFilter(e.target.value); setPage(0); }}
                        className="bg-[rgba(255,255,255,0.015)] border border-[rgba(255,255,255,0.04)] rounded-md px-2.5 py-1 text-[12px] uppercase font-sans tracking-wider text-[#a1a1aa] hover:text-white hover:border-[rgba(255,255,255,0.08)] transition-all cursor-pointer appearance-none pr-6 outline-none shadow-sm"
                        style={{ 
                          backgroundImage: `url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='10' height='10' viewBox='0 0 24 24' fill='none' stroke='%2371717a' stroke-width='2'%3E%3Cpath d='m6 9 6 6 6-6'/%3E%3C/svg%3E")`, 
                          backgroundRepeat: 'no-repeat', 
                          backgroundPosition: 'right 6px center',
                          backgroundSize: '8px'
                        }}
                      >
                        <option value="all">{t('statusAll')}</option>
                        <option value="open">{t('statusOpen')}</option>
                        <option value="triage">{t('statusTriage')}</option>
                        <option value="false_positive">{t('statusFalsePositive')}</option>
                        <option value="risk_accepted">{t('statusAccepted')}</option>
                      </select>
                      
                      <select 
                        value={groupBy} 
                        onChange={e => { setGroupBy(e.target.value as GroupBy); setPage(0); }}
                        className="bg-[rgba(255,255,255,0.015)] border border-[rgba(255,255,255,0.04)] rounded-md px-2.5 py-1 text-[12px] uppercase font-sans tracking-wider text-[#a1a1aa] hover:text-white hover:border-[rgba(255,255,255,0.08)] transition-all cursor-pointer appearance-none pr-6 outline-none shadow-sm"
                        style={{ 
                          backgroundImage: `url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='10' height='10' viewBox='0 0 24 24' fill='none' stroke='%2371717a' stroke-width='2'%3E%3Cpath d='m6 9 6 6 6-6'/%3E%3C/svg%3E")`, 
                          backgroundRepeat: 'no-repeat', 
                          backgroundPosition: 'right 6px center',
                          backgroundSize: '8px'
                        }}
                      >
                        <option value="none">{t('flatList')}</option>
                        <option value="severity">{t('groupSeverity')}</option>
                        <option value="title">{t('groupTitle')}</option>
                        <option value="file">{t('groupFile')}</option>
                        <option value="scanner">{t('groupScanner')}</option>
                        <option value="product">{t('groupProject')}</option>
                      </select>
                      
                      <select 
                        value={sortBy} 
                        onChange={e => setSortBy(e.target.value as SortBy)}
                        className="bg-[rgba(255,255,255,0.015)] border border-[rgba(255,255,255,0.04)] rounded-md px-2.5 py-1 text-[12px] uppercase font-sans tracking-wider text-[#a1a1aa] hover:text-white hover:border-[rgba(255,255,255,0.08)] transition-all cursor-pointer appearance-none pr-6 outline-none shadow-sm"
                        style={{ 
                          backgroundImage: `url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='10' height='10' viewBox='0 0 24 24' fill='none' stroke='%2371717a' stroke-width='2'%3E%3Cpath d='m6 9 6 6 6-6'/%3E%3C/svg%3E")`, 
                          backgroundRepeat: 'no-repeat', 
                          backgroundPosition: 'right 6px center',
                          backgroundSize: '8px'
                        }}
                      >
                        <option value="severity">{t('sortSeverity')}</option>
                        <option value="title">{t('sortTitle')}</option>
                        <option value="file">{t('sortFile')}</option>
                      </select>
                      {expandedIds.size > 0 && (
                        <button
                          onClick={() => setExpandedIds(new Set())}
                          className="flex items-center gap-1 px-2.5 py-1 rounded-md text-[11px] font-bold uppercase tracking-wider transition-all border border-[var(--accent-color-line)] bg-[var(--accent-color-soft)] text-[var(--accent-color)] hover:bg-[var(--accent-color-hover)] hover:text-[var(--accent-color-on-text)]"
                          title="Collapse all findings"
                        >
                          <span className="material-symbols-outlined text-[14px]">unfold_less</span>
                          {i18n.language?.startsWith('ru') ? 'Свернуть все' : 'Collapse All'}
                        </button>
                      )}
                    </div>

                    {/* Active filters summary */}
                    {(activeFilter || productFilter !== null || statusFilter !== 'all' || searchQuery) && (
                      <div className="flex items-center gap-1.5 flex-wrap">
                        {productFilter !== null && (
                          <span className="inline-flex items-center gap-1 text-[9px] text-[#e4e4e7] bg-[rgba(255,255,255,0.04)] px-2 py-0.5 rounded border border-[rgba(255,255,255,0.03)] font-mono uppercase">
                            <span className="material-symbols-outlined text-[10px] text-[#a1a1aa]">folder</span>{productMap.get(productFilter)?.name || `Project #${productFilter}`}
                            <button onClick={() => setProductFilter(null)} className="ml-1 text-[#a1a1aa] hover:text-white material-symbols-outlined text-[11px] leading-none">close</button>
                          </span>
                        )}
                        {activeFilter && (
                          <span className="inline-flex items-center gap-1 text-[9px] text-[#e4e4e7] bg-[rgba(255,255,255,0.04)] px-2 py-0.5 rounded border border-[rgba(255,255,255,0.03)] font-mono uppercase">
                            <span className="w-1 h-1 rounded-full" style={{ backgroundColor: sevDot(activeFilter) }} />{activeFilter}
                            <button onClick={() => setActiveFilter(null)} className="ml-1 text-[#a1a1aa] hover:text-white material-symbols-outlined text-[11px] leading-none">close</button>
                          </span>
                        )}
                        {statusFilter !== 'all' && (
                          <span className="inline-flex items-center gap-1 text-[9px] text-[#e4e4e7] bg-[rgba(255,255,255,0.04)] px-2 py-0.5 rounded border border-[rgba(255,255,255,0.03)] font-mono uppercase">
                            {statusFilter.replace('_', ' ')}
                            <button onClick={() => setStatusFilter('all')} className="ml-1 text-[#a1a1aa] hover:text-white material-symbols-outlined text-[11px] leading-none">close</button>
                          </span>
                        )}
                        {searchQuery && (
                          <span className="inline-flex items-center gap-1 text-[9px] text-[#e4e4e7] bg-[rgba(255,255,255,0.04)] px-2 py-0.5 rounded border border-[rgba(255,255,255,0.03)] font-mono uppercase">
                            "{searchQuery}"
                            <button onClick={() => setSearchQuery('')} className="ml-1 text-[#a1a1aa] hover:text-white material-symbols-outlined text-[11px] leading-none">close</button>
                          </span>
                        )}
                        <button onClick={() => { setActiveFilter(null); setProductFilter(null); setStatusFilter('all'); setSearchQuery(''); setPage(0); }}
                          className="text-[9px] transition-colors ml-1 font-bold bg-[rgba(239,68,68,0.08)] hover:bg-[rgba(239,68,68,0.15)] text-[#ef4444] px-2 py-0.5 rounded font-mono uppercase tracking-wider">{t('SimpleDashboardPage.clearAll')}</button>
                      </div>
                    )}
                  </div>
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
                    {searchQuery ? t('SimpleDashboardPage.noIssuesForQuery', { query: searchQuery }) : t('SimpleDashboardPage.noIssues')}
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
                                  setProductFilter={setProductFilter}
                                  setPage={setPage}
                                  handleTriage={handleTriage}
                                  onNavigateToChat={onNavigateToChat}
                                  onRefresh={(options) => {
                                    refreshFindings?.(options);
                                    refreshMetrics?.(options);
                                  }}
                                  isSelected={selectedFindings.has(f.id)}
                                  isTriaging={triagingIds.has(f.id)}
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
                          setProductFilter={setProductFilter}
                          setPage={setPage}
                          handleTriage={handleTriage}
                          onNavigateToChat={onNavigateToChat}
                          onRefresh={(options) => {
                            refreshFindings?.(options);
                            refreshMetrics?.(options);
                          }}
                          isSelected={selectedFindings.has(f.id)}
                          isTriaging={triagingIds.has(f.id)}
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
                        <button onClick={() => setPage(p => Math.max(0, p - 1))} disabled={page === 0} className="text-[11px] text-[#a1a1aa] hover:text-[#f4f4f5] disabled:opacity-30 flex items-center gap-1 transition-colors font-bold uppercase tracking-wider font-mono bg-[rgba(255,255,255,0.02)] border border-[rgba(255,255,255,0.04)] px-2.5 py-1 rounded-md hover:bg-[rgba(255,255,255,0.04)]">
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
                        <button onClick={() => setPage(p => Math.min(totalPages - 1, p + 1))} disabled={page >= totalPages - 1} className="text-[11px] text-[#a1a1aa] hover:text-[#f4f4f5] disabled:opacity-30 flex items-center gap-1 transition-colors font-bold uppercase tracking-wider font-mono bg-[rgba(255,255,255,0.02)] border border-[rgba(255,255,255,0.04)] px-2.5 py-1 rounded-md hover:bg-[rgba(255,255,255,0.04)]">
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
                <div><span className="material-symbols-outlined" aria-hidden="true">folder_scan</span><strong>{i18n.language?.startsWith('ru') ? 'Сканирование проектов' : 'Project scanning'}</strong></div>
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
          <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-[100] flex items-center justify-center p-4">
            <motion.div
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              className="bg-[#0e0e11] border border-[rgba(255,255,255,0.08)] rounded-xl w-[400px] p-6 shadow-[0_24px_50px_rgba(0,0,0,0.85)] flex flex-col space-y-4 text-left relative overflow-hidden"
            >
              <div>
                <h3 className="text-[12px] font-bold text-white uppercase tracking-wider">Ignore {selectedFindings.size} Selected Findings</h3>
                <p className="text-[11px] text-[#71717a] mt-1 leading-normal">
                  Choose the triage status and justification reason to suppress these findings in bulk.
                </p>
              </div>

              <div className="space-y-1">
                <label className="text-[10px] text-[#71717a] font-bold uppercase tracking-wider">Triage Justification</label>
                <select
                  value={bulkIgnoreReason}
                  onChange={e => setBulkIgnoreReason(e.target.value)}
                  className="w-full bg-[rgba(255,255,255,0.02)] border border-[rgba(255,255,255,0.06)] rounded-md px-3 py-1.5 text-[11px] text-white outline-none focus:border-[var(--accent-color)] cursor-pointer"
                >
                  <option value="False Positive">False Positive (Inaccurate finding)</option>
                  <option value="Accepted Risk">Accepted Risk (Accept risk, do not fix)</option>
                  <option value="Won't Fix">Won't Fix (Acknowledge, but keep as is)</option>
                </select>
              </div>

              <div className="flex justify-end gap-2 pt-2 border-t border-[rgba(255,255,255,0.06)]">
                <button
                  onClick={() => setBulkIgnoreModalOpen(false)}
                  className="px-3.5 py-1.5 bg-[rgba(255,255,255,0.02)] border border-[rgba(255,255,255,0.06)] hover:bg-[rgba(255,255,255,0.05)] text-[#a1a1aa] hover:text-white rounded-lg text-[10px] font-bold uppercase tracking-wider transition-colors cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  onClick={handleBulkIgnore}
                  disabled={bulkIgnoring}
                  className="px-4 py-1.5 bg-red-600 hover:bg-red-500 text-white rounded-lg text-[10px] font-bold uppercase tracking-wider transition-colors cursor-pointer disabled:opacity-50"
                >
                  {bulkIgnoring ? 'Ignoring...' : 'Ignore Findings'}
                </button>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

      {/* ── PREMIUM SCANNING OVERLAY ── */}
      <AnimatePresence>
        {globalScanning && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 z-[200] flex items-center justify-center bg-background/90 backdrop-blur-md"
          >
            <div className="w-[500px] border border-[rgba(255,255,255,0.08)] bg-surface rounded-2xl shadow-2xl overflow-hidden flex flex-col p-6 font-sans">
              <div className="flex flex-col items-center gap-4 text-center pb-6 border-b border-[rgba(255,255,255,0.06)]">
                {/* pulsing visual radar/circle */}
                <div className="relative w-16 h-16 flex items-center justify-center">
                  <div className="absolute inset-0 border-2 border-[var(--accent-color-line)] rounded-full animate-ping opacity-25" />
                  <div className="w-12 h-12 border-2 border-dashed border-[var(--accent-color)] rounded-full animate-spin flex items-center justify-center">
                    <span className="material-symbols-outlined text-[20px] text-[var(--accent-color)]">
                      shield
                    </span>
                  </div>
                </div>
                <div>
                  <h3 className="text-sm font-bold text-white uppercase tracking-widest font-mono">
                    AI Security Triage Audit Active
                  </h3>
                  <p className="text-xs text-[#71717a] mt-1 font-mono truncate max-w-[400px]">
                    Directory: {globalScanPath}
                  </p>
                </div>
              </div>

              {/* Progress bar */}
              <div className="py-4 text-left">
                <div className="flex justify-between items-center text-[10px] text-[#71717a] font-mono mb-1.5 uppercase">
                  <span>Phase: {scanPhases[globalScanPhase].name}</span>
                  <span>{globalScanElapsed}s elapsed</span>
                </div>
                <div className="w-full h-1.5 bg-surface-bright rounded-full overflow-hidden">
                  <div 
                    className="h-full bg-[var(--accent-color)] rounded-full transition-all duration-500 shadow-[0_0_8px_var(--accent-color-line)]"
                    style={{ width: `${((globalScanPhase + 1) / scanPhases.length) * 100}%` }}
                  />
                </div>
                <p className="text-[10px] text-[#52525b] mt-2 font-mono italic">
                  — {scanPhases[globalScanPhase].desc}
                </p>
              </div>

              {/* Console log box */}
              <div className="bg-black/40 border border-[rgba(255,255,255,0.04)] rounded-lg p-4 font-mono text-[10px] text-[#52525b] h-32 overflow-y-auto flex flex-col justify-end gap-1.5 text-left">
                {globalScanLogs.map((log, i) => (
                  <div key={i} className={i === globalScanLogs.length - 1 ? 'text-[#a1a1aa]' : ''}>
                    <span className="text-[#3f3f46] mr-1.5">$</span>{log}
                  </div>
                ))}
              </div>

              <div className="pt-4 mt-2 text-center text-[9px] text-[#3f3f46] font-mono uppercase tracking-[0.2em]">
                Do not close or reload the browser window
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};
