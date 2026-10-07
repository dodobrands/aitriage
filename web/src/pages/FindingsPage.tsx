import { useSearchParams } from 'react-router-dom';
import { FindingEvidence } from '../components/findings/FindingEvidence';
import React, { useEffect, useRef, useState } from 'react';
import { PrismLight as SyntaxHighlighter } from 'react-syntax-highlighter';
import javascript from 'react-syntax-highlighter/dist/esm/languages/prism/javascript';
import typescript from 'react-syntax-highlighter/dist/esm/languages/prism/typescript';
import tsx from 'react-syntax-highlighter/dist/esm/languages/prism/tsx';
import json from 'react-syntax-highlighter/dist/esm/languages/prism/json';
import python from 'react-syntax-highlighter/dist/esm/languages/prism/python';
import go from 'react-syntax-highlighter/dist/esm/languages/prism/go';
import bash from 'react-syntax-highlighter/dist/esm/languages/prism/bash';
import yaml from 'react-syntax-highlighter/dist/esm/languages/prism/yaml';
import rust from 'react-syntax-highlighter/dist/esm/languages/prism/rust';
import csharp from 'react-syntax-highlighter/dist/esm/languages/prism/csharp';
import java from 'react-syntax-highlighter/dist/esm/languages/prism/java';
import php from 'react-syntax-highlighter/dist/esm/languages/prism/php';
import ruby from 'react-syntax-highlighter/dist/esm/languages/prism/ruby';
import docker from 'react-syntax-highlighter/dist/esm/languages/prism/docker';
import vscDarkPlus from 'react-syntax-highlighter/dist/esm/styles/prism/vsc-dark-plus';
import { isActive, isResolved } from '../lib/findingStatus';
import { useTranslation } from 'react-i18next';
import { useFindings } from '../hooks/useFindings';
import { useTitle } from '../hooks/useTitle';
import { useCopilotStore } from '../store/CopilotStore';

for (const [name, grammar] of Object.entries({ javascript, typescript, tsx, json, python, go, bash, yaml, rust, csharp, java, php, ruby, docker })) SyntaxHighlighter.registerLanguage(name, grammar);
const codeLanguage = (path = '', stack = '') => {
  const extension = path.split('.').pop()?.toLowerCase() || '';
  const languages: Record<string, string> = { js: 'javascript', jsx: 'javascript', ts: 'typescript', tsx: 'tsx', py: 'python', go: 'go', sh: 'bash', json: 'json', yml: 'yaml', yaml: 'yaml', rs: 'rust', cs: 'csharp', java: 'java', php: 'php', rb: 'ruby' };
  if (/dockerfile$/i.test(path)) return 'docker';
  return languages[extension] || (['javascript', 'typescript', 'tsx', 'python', 'go', 'bash', 'json', 'yaml', 'rust', 'csharp', 'java', 'php', 'ruby'].includes(stack.toLowerCase()) ? stack.toLowerCase() : 'text');
};

import type { Finding } from '../types';

const SEV_COLORS: Record<string, { dot: string; text: string; badge: string }> = {
  CRITICAL: { dot: 'bg-error', text: 'text-error', badge: 'border-error bg-error/10 text-error pulse-glow-critical' },
  HIGH: {
    dot: 'bg-severity-high',
    text: 'text-severity-high',
    badge: 'border-severity-high bg-severity-high/10 text-severity-high',
  },
  MEDIUM: {
    dot: 'bg-severity-medium',
    text: 'text-severity-medium',
    badge: 'border-severity-medium bg-severity-medium/10 text-severity-medium',
  },
  LOW: {
    dot: 'bg-on-surface-variant',
    text: 'text-on-surface-variant',
    badge: 'border-outline-variant text-on-surface-variant',
  },
};

const getSev = (sev: string) => SEV_COLORS[sev?.toUpperCase()] ?? SEV_COLORS.LOW;

export const FindingsPage: React.FC = () => {
  const { t } = useTranslation('pages');
  const { findings, loading, error, refresh } = useFindings();

  const getSeverityLabel = (severity: string) => {
    const s = severity?.toUpperCase();
    if (s === 'CRITICAL') return t('critical');
    if (s === 'HIGH') return t('high');
    if (s === 'MEDIUM') return t('medium');
    if (s === 'LOW') return t('low');
    return severity;
  };

  const getStatusLabel = (status: string | undefined) => {
    const s = status?.toLowerCase() || 'open';
    if (s === 'sent_to_agent') return t('status_sent_to_agent');
    if (s === 'pending_verification') return t('status_pending_verification');
    if (s === 'verification_failed') return t('status_verification_failed');
    if (s === 'resolved' || s === 'fixed') return t('status_fixed');
    if (s === 'triage') return t('status_triage');
    if (s === 'confirmed') return t('review.confirmed');
    if (s === 'false_positive') return t('status_false_positive');
    if (s === 'risk_accepted' || s === 'accepted_risk') return t('status_accepted_risk');
    return t('status_open');
  };

  const getStatusTone = (status: string | undefined) => {
    const s = status?.toLowerCase() || 'open';
    if (s === 'resolved' || s === 'fixed') return 'text-success';
    if (s === 'verification_failed') return 'text-error';
    if (s === 'pending_verification') return 'text-severity-medium';
    if (s === 'sent_to_agent' || s === 'triage') return 'text-[#38bdf8]';
    return 'text-primary';
  };

  useTitle(t('findings_title'));
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [searchParams, setSearchParams] = useSearchParams();
  const search = searchParams.get('q') || '';
  const setSearch = (value: string) => setSearchParams(previous => { const next = new URLSearchParams(previous); if (value) next.set('q', value); else next.delete('q'); return next; }, { replace: true });
  const [selectedSeverity, setSelectedSeverity] = useState('ALL_SEVERITIES');
  const [findingStateFilter, setFindingStateFilter] = useState('active');
  const [actionError, setActionError] = useState('');
  const [aiAvailable, setAiAvailable] = useState(false);
  useEffect(() => {
    const controller = new AbortController();
    fetch('/api/health', { signal: controller.signal }).then(response => response.json()).then(data => { if (!controller.signal.aborted) setAiAvailable(data.ai_available === true); }).catch(() => { /* Optional AI availability. */ });
    return () => controller.abort();
  }, []);
  const [triageStatus, setTriageStatus] = useState<Record<number, 'IDLE' | 'PROCESSING'>>({});
  const [agentPrompt, setAgentPrompt] = useState('');
  const [agentPromptStatus, setAgentPromptStatus] = useState<Record<number, 'IDLE' | 'PROCESSING'>>({});
  const [verificationStatus, setVerificationStatus] = useState<Record<number, 'IDLE' | 'PROCESSING'>>({});
  const [verificationResult, setVerificationResult] = useState<string | null>(null);

  const stacks = Array.from(new Set(findings.map((f: Finding) => f.stack)))
    .filter(Boolean)
    .sort() as string[];
  const [selectedStack, setSelectedStack] = useState('ALL_STACKS');

  const [sortField, setSortField] = useState<'id' | 'severity' | 'stack'>('severity');
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc');

  const filtered = findings
    .filter((f: Finding) => {
      if (findingStateFilter === 'active' && !isActive(f)) return false;
      if (findingStateFilter === 'resolved' && !isResolved(f)) return false;
      const matchesSearch =
        !search ||
        f.title?.toLowerCase().includes(search.toLowerCase()) ||
        String(f.id).includes(search);
      const matchesSeverity =
        selectedSeverity === 'ALL_SEVERITIES' || f.severity?.toUpperCase() === selectedSeverity;
      const matchesStack = selectedStack === 'ALL_STACKS' || f.stack === selectedStack;
      return matchesSearch && matchesSeverity && matchesStack;
    })
    .sort((a, b) => {
      const dir = sortDir === 'asc' ? 1 : -1;
      if (sortField === 'id') return (a.id - b.id) * dir;
      if (sortField === 'stack') return (a.stack || '').localeCompare(b.stack || '') * dir;
      if (sortField === 'severity') {
        const sevMap: Record<string, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
        const valA = sevMap[a.severity?.toUpperCase()] || 0;
        const valB = sevMap[b.severity?.toUpperCase()] || 0;
        return (valA - valB) * dir;
      }
      return 0;
    });

  const selectedFinding =
    filtered.find((f: Finding) => f.id === selectedId) ??
    (filtered.length > 0 ? filtered[0] : null);

  const selectedFindingId = useRef<number | undefined>(undefined);
  useEffect(() => {
    selectedFindingId.current = selectedFinding?.id;
    setAgentPrompt(selectedFinding?.agent_prompt ?? '');
    const status = selectedFinding?.status?.toLowerCase();
    const canShowVerificationResult = selectedFinding?.verification_status === 'error' || status === 'verification_failed' || status === 'resolved' || status === 'fixed';
    setVerificationResult(canShowVerificationResult ? selectedFinding?.verification_summary ?? null : null);
  }, [selectedFinding?.id, selectedFinding?.agent_prompt, selectedFinding?.verification_summary, selectedFinding?.verification_status, selectedFinding?.status]);

  const severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

  const triageFinding = async (id: number, action: 'IGNORE' | 'CONFIRM' | 'ACCEPT' | 'OPEN' | 'TRIAGE') => {
    setActionError('');
    setTriageStatus(previous => ({ ...previous, [id]: 'PROCESSING' }));
    try {
      const status = { IGNORE: 'false_positive', CONFIRM: 'confirmed', ACCEPT: 'risk_accepted', OPEN: 'open', TRIAGE: 'triage' }[action];
      const res = await fetch(`/api/findings/${id}${action === 'TRIAGE' ? '/ai-triage' : ''}`, {
        method: action === 'TRIAGE' ? 'POST' : 'PUT', headers: { 'Content-Type': 'application/json' },
        ...(action === 'TRIAGE' ? {} : { body: JSON.stringify({ action: 'status', status }) }),
      });
      const data = await res.json();
      if (!res.ok || !data.ok) throw new Error(data.error || t('review.actionFailed'));
      refresh({ silent: true });
    } catch (error) { setActionError(error instanceof Error ? error.message : t('review.actionFailed')); }
    finally { setTriageStatus(previous => ({ ...previous, [id]: 'IDLE' })); }
  };

  const generateAgentPrompt = async () => {
    if (!selectedFinding) return;
    const id = selectedFinding.id;
    setAgentPromptStatus((prev) => ({ ...prev, [id]: 'PROCESSING' }));
    try {
      const res = await fetch(`/api/findings/${id}/agent-prompt`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      });
      const data = await res.json();
      if (!res.ok || !data.ok) {
        throw new Error(data.error || 'Failed to generate prompt');
      }
      if (selectedFindingId.current !== id) return;
      setAgentPrompt(data.prompt || '');
      setVerificationResult(null);
      try {
        await navigator.clipboard.writeText(data.prompt || '');
      } catch { /* Prompt remains available for manual copy. */ }
      refresh({ silent: true });
    } catch (err) {
      console.error('Agent prompt generation failed', err);
      if (selectedFindingId.current === id) setActionError(err instanceof Error ? err.message : t('review.actionFailed'));
    } finally {
      setAgentPromptStatus((prev) => ({ ...prev, [id]: 'IDLE' }));
    }
  };

  const verifyFinding = async () => {
    if (!selectedFinding) return;
    const id = selectedFinding.id;
    setActionError('');
    setVerificationStatus((prev) => ({ ...prev, [id]: 'PROCESSING' }));
    setVerificationResult(t('verification_running'));
    try {
      const res = await fetch(`/api/findings/${id}/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      });
      const data = await res.json();
      if (!res.ok || !data.ok) {
        throw new Error(data.error || 'Verification failed');
      }
      if (selectedFindingId.current === id) setVerificationResult(data.summary || '');
      refresh({ silent: true });
    } catch (err) {
      console.error('Verification failed', err);
      if (selectedFindingId.current === id) {
        setActionError(err instanceof Error ? err.message : t('review.actionFailed'));
        setVerificationResult(null);
      }
    } finally {
      setVerificationStatus((prev) => ({ ...prev, [id]: 'IDLE' }));
    }
  };

  return (
    <div className="findings-page flex flex-col h-full overflow-hidden">
      {actionError && <p role="alert" className="review-error">{actionError}</p>}
      {/* Page Header */}
      <div className="findings-page__header px-4 py-2 flex flex-wrap gap-3 justify-between items-center flex-shrink-0 cyber-header-premium border-b border-outline-variant/30">
        <div>
          <p className="text-[9px] font-bold tracking-widest text-on-surface-variant mb-0.5">
            {t('sec_findings')}
          </p>
          <h1 className="text-title-lg font-bold tracking-tight text-primary uppercase">
            {t('review.title')}
          </h1>
        </div>
        <div className="flex items-center gap-3">
          {/* Stack Filter */}
          <select
            aria-label={t('all_stacks')} className="bg-surface-container-lowest border border-outline-variant rounded-lg text-label-xs text-on-surface-variant h-8 px-2 focus:border-primary focus:ring-1 focus:ring-primary/25 outline-none cursor-pointer uppercase tracking-widest transition-all duration-300"
            value={selectedStack}
            onChange={(e) => setSelectedStack(e.target.value)}
          >
            <option value="ALL_STACKS">{t('all_stacks')}</option>
            {stacks.map((s) => (
              <option key={s} value={s}>
                {s.toUpperCase()}
              </option>
            ))}
          </select>

          <select aria-label={t('review.statusFilter')} className="cyber-input p-2 text-xs" value={findingStateFilter} onChange={event => setFindingStateFilter(event.target.value)}>
            <option value="active">{t('review.active')}</option><option value="resolved">{t('status_fixed')}</option><option value="all">{t('statusAll')}</option>
          </select>
          {/* Severity Filter */}
          <select aria-label={t('all_severities')}
            className="bg-surface-container-lowest border border-outline-variant rounded-lg text-label-xs text-on-surface-variant h-8 px-2 focus:border-primary focus:ring-1 focus:ring-primary/25 outline-none cursor-pointer uppercase tracking-widest transition-all duration-300"
            value={selectedSeverity}
            onChange={(e) => setSelectedSeverity(e.target.value)}
          >
            <option value="ALL_SEVERITIES">{t('all_severities')}</option>
            {severities.map((s) => (
              <option key={s} value={s}>
                {getSeverityLabel(s).toUpperCase()}
              </option>
            ))}
          </select>

          <div className="flex items-center border border-outline-variant bg-surface-container-lowest h-8 px-3 gap-2 w-56 rounded-lg focus-within:border-primary focus-within:ring-1 focus-within:ring-primary/25 transition-all duration-300">
            <span
              className="material-symbols-outlined text-on-surface-variant"
              style={{ fontSize: '14px' }}
            >
              search
            </span>
            <input
              className="bg-transparent border-none focus:ring-0 focus:outline-none text-xs text-primary placeholder:text-on-surface-variant/50 w-full"
              placeholder={t('filter_findings')} aria-label={t('filter_findings')}
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </div>
        </div>
      </div>

      {/* Split Layout */}
      <div className="findings-page__split flex-1 flex min-h-0 overflow-hidden">
        {/* Master List */}
        <div className="findings-page__list w-1/2 min-w-0 flex flex-col border-r border-outline-variant overflow-hidden">
          {/* Table Header */}
          <div className="cyber-grid-header flex items-center text-label-xs text-on-surface-variant tracking-widest shrink-0">
            <div className="w-10 py-3 px-3 text-center shrink-0" aria-hidden="true">●</div>
            <button type="button" aria-label={t('review.sortId')}
              className="w-24 py-3 px-3 shrink-0 cursor-pointer hover:text-primary transition-none flex items-center gap-1"
              onClick={() => {
                setSortField('id');
                setSortDir(sortDir === 'asc' ? 'desc' : 'asc');
              }}
            >
              {t('id')} {sortField === 'id' && (sortDir === 'asc' ? '↑' : '↓')}
            </button>
            <div className="flex-1 py-3 px-3 min-w-0">{t('review.findingName')}</div>
            <button type="button" aria-label={t('review.sortStack')}
              className="w-24 py-3 px-3 shrink-0 text-center cursor-pointer hover:text-primary transition-none flex items-center justify-center gap-1"
              onClick={() => {
                setSortField('stack');
                setSortDir(sortDir === 'asc' ? 'desc' : 'asc');
              }}
            >
              {t('stack')} {sortField === 'stack' && (sortDir === 'asc' ? '↑' : '↓')}
            </button>
            <button type="button" aria-label={t('review.sortSeverity')}
              className="w-24 py-3 px-3 shrink-0 text-right cursor-pointer hover:text-primary transition-none flex items-center justify-end gap-1"
              onClick={() => {
                setSortField('severity');
                setSortDir(sortDir === 'asc' ? 'desc' : 'asc');
              }}
            >
              {t('severity')} {sortField === 'severity' && (sortDir === 'asc' ? '↑' : '↓')}
            </button>
          </div>

          {/* Rows */}
          <div className="flex-1 overflow-y-auto cyber-scrollbar">
            {loading && (
              <div className="flex flex-col items-center justify-center p-12 gap-4">
                <div className="flex gap-1.5">
                  {[0, 1, 2].map((i) => (
                    <div
                      key={i}
                      className="w-2 h-6 bg-primary animate-pulse"
                      style={{ animationDelay: `${i * 0.15}s` }}
                    />
                  ))}
                </div>
                <span className="text-label-caps text-on-surface-variant tracking-[0.2em] text-xs">
                  {t('loading_findings')}
                </span>
              </div>
            )}
            {error && (
              <div className="p-4 flex items-center gap-3 border border-error m-4 bg-error/5">
                <div className="w-2 h-2 bg-error shrink-0" />
                <span className="text-label-caps text-error">{error}</span>
              </div>
            )}
            {!loading &&
              !error &&
              filtered.map((f) => {
                const sev = getSev(f.severity);
                const isSelected = f.id === selectedId || (!selectedId && f.id === filtered[0]?.id);
                const isCrit = f.severity?.toUpperCase() === 'CRITICAL';
                return (
                  <div
                    key={f.id}
                    onClick={() => setSelectedId(f.id)} role="button" tabIndex={0} aria-pressed={isSelected}
                    onKeyDown={event => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); setSelectedId(f.id); } }}
                    className={`cyber-grid-row flex items-center cursor-pointer transition-all duration-250 ease-out ${
                      isSelected
                        ? 'bg-surface-bright text-primary border-l-2 border-l-primary shadow-[inset_4px_0_12px_rgba(139,92,246,0.1)]'
                        : 'border-l-2 border-l-transparent hover:bg-surface hover:border-l-primary'
                    }`}
                  >
                    <div className="w-10 py-3 px-3 flex justify-center shrink-0">
                      <div
                        className={`status-dot ${sev.dot} ${isCrit ? 'pulse-glow-critical' : ''}`}
                      />
                    </div>
                    <div className="w-24 py-3 px-3 text-mono-data text-on-surface-variant shrink-0">
                      #{f.id}
                    </div>
                    <div className="flex-1 py-3 px-3 text-mono-data text-on-surface truncate min-w-0">
                      {f.title}
                    </div>
                    <div className="w-24 py-3 px-3 shrink-0 text-center">
                      <span className="text-[9px] font-bold tracking-tighter px-1.5 py-0.5 border border-outline-variant text-on-surface-variant uppercase bg-surface-container-low/50">
                        {f.stack || t('default_core')}
                      </span>
                    </div>
                    <div
                      className={`w-24 py-3 px-3 text-label-xs tracking-widest shrink-0 text-right font-bold ${sev.text}`}
                    >
                      {getSeverityLabel(f.severity).toUpperCase()}
                    </div>
                  </div>
                );
              })}
            {!loading && filtered.length === 0 && (
              <div className="p-12 flex flex-col items-center justify-center text-center opacity-30">
                <span className="material-symbols-outlined text-4xl mb-4">search_off</span>
                <p className="text-label-caps">{t('no_findings')}</p>
              </div>
            )}
          </div>
        </div>

        {/* Detail Panel */}
        <div className="findings-page__detail w-1/2 min-w-0 flex flex-col overflow-y-auto cyber-scrollbar bg-surface-container-lowest">
          {selectedFinding ? (
            <div className="p-6 flex flex-col gap-6 animate-in fade-in slide-in-from-right-4 ">
              {/* Finding header */}
              <div className="flex justify-between items-start gap-4 border-b border-outline-variant pb-5">
                <div className="flex-1 min-w-0">
                  <div className="text-label-xs text-on-surface-variant tracking-widest mb-1">
                    {t('finding_uppercase')} #{selectedFinding.id}
                  </div>
                  <h2 className="text-headline-sm text-primary tracking-tight break-words">
                    {selectedFinding.title}
                  </h2>
                </div>
                <div className="flex flex-col items-end gap-2">
                  <span
                    className={`text-label-xs px-3 py-1 border tracking-widest shrink-0 font-bold ${getSev(selectedFinding.severity).badge}`}
                  >
                    {getSeverityLabel(selectedFinding.severity).toUpperCase()}
                  </span>

                </div>
              </div>

              {/* Metadata chips */}
              <div className="grid grid-cols-2 gap-3">
                <div className="cyber-widget p-3 border-l-2 border-l-primary/30">
                  <span className="text-label-xs text-on-surface-variant block mb-2 tracking-widest">
                    {t('review.statusFilter')}
                  </span>
                  <span
                    className={`text-mono-data font-bold ${getStatusTone(selectedFinding.status)}`}
                  >
                    {getStatusLabel(selectedFinding.status).toUpperCase()}
                  </span>
                </div>
                <div className="cyber-widget p-3 border-l-2 border-l-primary/30">
                  <span className="text-label-xs text-on-surface-variant block mb-2 tracking-widest">
                    {t('review.fileFilter')}
                  </span>
                  <span className="text-mono-data text-on-surface break-all block text-xs underline decoration-outline-variant">
                    {selectedFinding.file_path ?? selectedFinding.file ?? '—'}
                  </span>
                </div>
              </div>

              <div className="finding-rule-meta">
                {selectedFinding.rule_id && <span>{t('review.rule')}: {selectedFinding.rule_id}</span>}
                {selectedFinding.stack && <span>{t('review.scanner')}: {selectedFinding.stack}</span>}
                {selectedFinding.cwe_id && <span>{selectedFinding.cwe_id}</span>}
                {selectedFinding.cve_id && <span>{selectedFinding.cve_id}</span>}
              </div>
              {/* Description */}
              <div>
                <div className="text-label-xs text-on-surface-variant tracking-widest mb-3 flex items-center gap-2">
                  <span className="material-symbols-outlined text-[14px] text-primary">
                    description
                  </span>
                  {t('review.why')}
                </div>
                <div className="cyber-widget p-4 text-body-sm text-on-surface leading-relaxed border-outline-variant/30">
                  {selectedFinding.description ?? t('no_description')}
                </div>
              </div>

              {selectedFinding.impact && <section><h3 className="review-heading">{t('review.impact')}</h3><p className="review-help">{selectedFinding.impact}</p></section>}
              {!selectedFinding.code_snippet && <FindingEvidence finding={selectedFinding} />}
              {/* Code snippet with Syntax Highlighting */}
              {selectedFinding.code_snippet && (
                <div>
                  <div className="text-label-xs text-on-surface-variant tracking-widest mb-3 flex items-center gap-2">
                    <span className="material-symbols-outlined text-[14px] text-primary">code</span>
                    {t('technical_evidence')}
                  </div>
                  <div className="cyber-widget border-outline-variant/30 overflow-hidden">
                    <SyntaxHighlighter
                      language={codeLanguage(selectedFinding.file_path || selectedFinding.file, selectedFinding.stack)}
                      style={vscDarkPlus}
                      customStyle={{
                        margin: 0,
                        padding: '1rem',
                        fontSize: '12px',
                        background: 'transparent',
                      }}
                    >
                      {selectedFinding.code_snippet}
                    </SyntaxHighlighter>
                  </div>
                </div>
              )}

              {/* Remediation */}
              <div>
                <div className="text-label-xs text-on-surface-variant tracking-widest mb-3 flex items-center gap-2">
                  <span className="material-symbols-outlined text-[14px] text-primary">
                    auto_fix_high
                  </span>
                  {t('review.remediation')}
                </div>
                <div className="border-l-2 border-primary pl-4 py-1 text-body-sm text-on-surface leading-relaxed">
                  {selectedFinding.fix_suggestion ??
                    selectedFinding.suggestion ??
                    t('follow_standard')}
                </div>
              </div>

              <div className="review-actions">
                <button type="button" className="review-primary" onClick={verifyFinding} disabled={verificationStatus[selectedFinding.id] === 'PROCESSING'}>{verificationStatus[selectedFinding.id] === 'PROCESSING' ? t('verification_running_short') : t('review.rescan')}</button>
                {isActive(selectedFinding) ? <>
                  <button type="button" disabled={selectedFinding.status === 'confirmed' || triageStatus[selectedFinding.id] === 'PROCESSING'} onClick={() => triageFinding(selectedFinding.id, 'CONFIRM')}>{t('review.confirm')}</button>
                  <button type="button" disabled={triageStatus[selectedFinding.id] === 'PROCESSING'} onClick={() => triageFinding(selectedFinding.id, 'IGNORE')}>{t('review.falsePositive')}</button>
                  <button type="button" disabled={triageStatus[selectedFinding.id] === 'PROCESSING'} onClick={() => triageFinding(selectedFinding.id, 'ACCEPT')}>{t('review.acceptRisk')}</button>
                </> : <button type="button" disabled={triageStatus[selectedFinding.id] === 'PROCESSING'} onClick={() => triageFinding(selectedFinding.id, 'OPEN')}>{t('review.reopen')}</button>}
              </div>
              <p className="text-sm text-on-surface-variant leading-relaxed">{t('verification_rescan_hint')}</p>
              {verificationResult && <p role="status" className="review-result">{verificationResult}</p>}
              <details className="finding-ai-tools">
                <summary>{t('review.aiTools')}</summary>
                <div className="review-actions">
                  <button type="button" onClick={generateAgentPrompt} disabled={agentPromptStatus[selectedFinding.id] === 'PROCESSING'}>{t('agent_prompt')}</button>
                  <button type="button" disabled={!aiAvailable || triageStatus[selectedFinding.id] === 'PROCESSING'} onClick={() => triageFinding(selectedFinding.id, 'TRIAGE')}>{t('review.aiTriage')}</button>
                  <button type="button" disabled={!aiAvailable} onClick={() => { const { setContext, setIsOpen } = useCopilotStore.getState(); setContext(selectedFinding); setIsOpen(true); }}>{t('review.askAi')}</button>
                </div>
                {!aiAvailable && <p className="review-help">{t('review.aiUnavailable')}</p>}
                {agentPrompt && <textarea aria-label={t('agent_prompt')} className="review-prompt" readOnly value={agentPrompt} />}
              </details>
            </div>
          ) : (
            <div className="flex-1 flex items-center justify-center p-8">
              <div className="text-center text-on-surface-variant">
                <span className="material-symbols-outlined text-6xl mb-4">shield_with_heart</span>
                <p className="text-label-caps">{t('review.noMatches')}</p>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
