import { isActive } from '../lib/findingStatus';
import { FindingEvidence } from '../components/findings/FindingEvidence';
import React, { useState, useMemo, useCallback } from 'react';
import { useTranslation } from 'react-i18next';
import { useFindings } from '../hooks/useFindings';
import { useMetrics } from '../hooks/useMetrics';
import { usePrompts, interpolatePrompt } from '../hooks/usePrompts';
import type { PromptTemplate } from '../hooks/usePrompts';
import { useCopilotStore } from '../store/CopilotStore';
import type { Finding } from '../types';
import { PipelinePanel } from '../components/PipelinePanel';

/* ═══════════════════════════════════════════════════════════════════════
 * AI Triage Framework — SecureCoder-style prompt engineering
 * Pre-generated narratives + ready-made prompts for LLM remediation
 * ═══════════════════════════════════════════════════════════════════════ */

/* ── Helper ──────────────────────────────────────────────────────────── */
const sevColor = (sev: string) => {
  switch (sev?.toUpperCase()) {
    case 'CRITICAL':
      return 'text-severity-critical border-severity-critical';
    case 'HIGH':
      return 'text-severity-high border-severity-high';
    case 'MEDIUM':
      return 'text-severity-medium border-severity-medium';
    case 'LOW':
      return 'text-on-surface-variant border-outline-variant';
    default:
      return 'text-on-surface-variant border-outline-variant';
  }
};

const sevBg = (sev: string) => {
  switch (sev?.toUpperCase()) {
    case 'CRITICAL':
      return 'bg-severity-critical/10';
    case 'HIGH':
      return 'bg-severity-high/10';
    case 'MEDIUM':
      return 'bg-severity-medium/10';
    default:
      return 'bg-surface-container';
  }
};

/* ═══════════════════════════════════════════════════════════════════════ */
export const AITriageFramework: React.FC = () => {
  const { t } = useTranslation('pages');
  const { findings, loading: findingsLoading } = useFindings() as any;
  const { metrics } = useMetrics();
  const { templates: PROMPT_ACTIONS, loading: promptsLoading } = usePrompts();
  const { setIsOpen, setContext } = useCopilotStore();
  const [selectedFindingId, setSelectedFindingId] = useState<number | null>(null);
  const [activePrompt, setActivePrompt] = useState<string>('');
  const [activeAction, setActiveAction] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [filterSev, setFilterSev] = useState<string | null>(null);
  const [mode, setMode] = useState<'triage' | 'pipeline'>('triage');

  const loading = findingsLoading || promptsLoading;

  const selectedFinding: Finding | null =
    findings?.find((f: Finding) => f.id === selectedFindingId) || null;

  /* ── Repository Narrative ───────────────────────────────────────────── */
  const narrative = useMemo(() => {
    if (!findings || findings.length === 0) return null;

    const sevCounts: Record<string, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
    const stackCounts: Record<string, number> = {};
    const issueCounts: Record<string, number> = {};
    const fileCounts: Record<string, number> = {};

    findings.filter(isActive).forEach((f: Finding) => {
      sevCounts[f.severity?.toUpperCase()] = (sevCounts[f.severity?.toUpperCase()] || 0) + 1;
      const stack = f.stack || 'core';
      stackCounts[stack] = (stackCounts[stack] || 0) + 1;
      const title = f.title || 'Unknown';
      issueCounts[title] = (issueCounts[title] || 0) + 1;
      const file = f.file_path || f.file || '';
      if (file) fileCounts[file] = (fileCounts[file] || 0) + 1;
    });

    const topIssues = Object.entries(issueCounts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5);
    const topFiles = Object.entries(fileCounts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5);
    const stacks = Object.entries(stackCounts).sort((a, b) => b[1] - a[1]);

    return { sevCounts, topIssues, topFiles, stacks, total: findings.length };
  }, [findings]);

  /* ── Filtered findings ──────────────────────────────────────────────── */
  const filteredFindings = useMemo(() => {
    if (!findings) return [];
    return findings.filter((f: Finding) => isActive(f) && (!filterSev || f.severity?.toUpperCase() === filterSev));
  }, [findings, filterSev]);

  /* ── Select finding ─────────────────────────────────────────────────── */
  const handleSelectFinding = useCallback((id: number) => {
    setSelectedFindingId(id);
    setActivePrompt('');
    setActiveAction(null);
  }, []);

  /* ── Generate prompt ────────────────────────────────────────────────── */
  const handleAction = useCallback(
    (actionId: string) => {
      if (!selectedFinding) return;
      const action = PROMPT_ACTIONS.find((a: PromptTemplate) => a.id === actionId);
      if (!action) return;
      setActiveAction(actionId);
      setActivePrompt(interpolatePrompt(action.template, selectedFinding));
    },
    [selectedFinding, PROMPT_ACTIONS],
  );

  /* ── Copy ────────────────────────────────────────────────────────────── */
  const handleCopy = useCallback(() => {
    navigator.clipboard.writeText(activePrompt);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }, [activePrompt]);

  /* ── Send to Copilot ────────────────────────────────────────────────── */
  const handleSendToCopilot = useCallback(() => {
    setContext(selectedFinding);
    useCopilotStore.getState().setPromptToSubmit(activePrompt);
    setIsOpen(true);
  }, [activePrompt, selectedFinding, setContext, setIsOpen]);

  return (
    <div className="flex h-full overflow-hidden bg-transparent">
      {/* ═══ LEFT PANEL: Narrative + Finding List ═══════════════════════ */}
      <div className="w-[380px] shrink-0 border-r border-outline-variant/30 flex flex-col h-full bg-surface-container-lowest overflow-hidden">
        {/* ── Repository Narrative ─────────────────────────────────── */}
        {narrative && (
          <div className="shrink-0 border-b border-outline-variant/30">
            <div className="px-4 py-3 border-b border-outline-variant/20 bg-surface-container/50">
              <div className="flex items-center gap-2">
                <div className="w-1 h-3 bg-primary" />
                <span className="text-[10px] font-bold tracking-widest text-primary uppercase">
                  {t('framework.securityPosture')}
                </span>
              </div>
            </div>
            <div className="p-4 space-y-3">
              {/* Score */}
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div
                    className={`w-10 h-10 border-2 flex items-center justify-center ${
                      (metrics?.security_score ?? 0) < 50
                        ? 'border-severity-critical text-severity-critical'
                        : (metrics?.security_score ?? 0) < 70
                          ? 'border-severity-high text-severity-high'
                          : 'border-primary text-primary'
                    }`}
                  >
                    <span className="text-lg font-black">{metrics?.security_grade || '–'}</span>
                  </div>
                  <div>
                    <div className="text-[10px] text-on-surface-variant/40 tracking-widest">
                      {t('framework.score')}
                    </div>
                    <div className="text-mono-data text-primary font-bold">
                      {metrics?.security_score ?? '–'}/100
                    </div>
                  </div>
                </div>
                <div className="text-right">
                  <div className="text-[10px] text-on-surface-variant/40 tracking-widest">
                    {t('framework.findings')}
                  </div>
                  <div className="text-mono-data text-severity-high font-bold">
                    {narrative.total}
                  </div>
                </div>
              </div>

              {/* Severity chips */}
              <div className="flex gap-1.5">
                {(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const).map((sev) => {
                  const count = narrative.sevCounts[sev] || 0;
                  if (count === 0) return null;
                  const isActive = filterSev === sev;
                  return (
                    <button
                      key={sev}
                      onClick={() => setFilterSev(isActive ? null : sev)}
                      className={`flex items-center gap-1 px-2 py-1 border text-[10px] font-bold tracking-wider transition-none ${
                        isActive
                          ? `${sevColor(sev)} ${sevBg(sev)}`
                          : 'border-outline-variant/20 text-on-surface-variant/50 hover:border-outline-variant/50'
                      }`}
                    >
                      <span className={isActive ? '' : 'opacity-60'}>{sev.slice(0, 4)}</span>
                      <span>{count}</span>
                    </button>
                  );
                })}
              </div>

              {/* Top issues */}
              <div>
                <div className="text-[9px] text-on-surface-variant/30 tracking-widest mb-1.5 font-bold">
                  {t('framework.topPatterns')}
                </div>
                {narrative.topIssues.slice(0, 3).map(([name, count], i) => (
                  <div key={i} className="flex items-center justify-between py-0.5">
                    <span className="text-[11px] text-on-surface-variant/60 truncate mr-2">
                      {name}
                    </span>
                    <span className="text-[10px] text-primary font-bold tabular-nums shrink-0">
                      ×{count}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* ── Finding List ─────────────────────────────────────────── */}
        <div className="px-4 py-2.5 border-b border-outline-variant/20 flex items-center justify-between shrink-0">
          <span className="text-[10px] font-bold tracking-widest text-on-surface-variant/50 uppercase">
            {filterSev ? t('framework.findingsCountSev', { sev: filterSev }) : t('framework.findingsCountAll')} ({filteredFindings.length})
          </span>
          {filterSev && (
            <button
              onClick={() => setFilterSev(null)}
              className="text-[10px] text-primary hover:text-white transition-none"
            >
              {t('framework.clear')}
            </button>
          )}
        </div>
        <div className="flex-1 overflow-y-auto cyber-scrollbar">
          {loading ? (
            <div className="p-6 text-center">
              <span className="text-label-caps text-on-surface-variant animate-pulse tracking-widest">
                {t('framework.loading')}
              </span>
            </div>
          ) : (
            <div className="divide-y divide-outline-variant/10">
              {filteredFindings.map((f: Finding) => {
                const isSelected = selectedFindingId === f.id;
                return (
                  <button
                    key={f.id}
                    onClick={() => handleSelectFinding(f.id)}
                    className={`w-full text-left px-4 py-2.5 transition-none flex items-start gap-3 ${
                      isSelected
                        ? 'bg-primary/[0.06] border-l-2 border-primary'
                        : 'border-l-2 border-transparent hover:bg-surface-container-high'
                    }`}
                  >
                    <span
                      className={`text-[9px] font-bold px-1 py-0.5 border shrink-0 mt-0.5 ${sevColor(f.severity)} ${sevBg(f.severity)}`}
                    >
                      {f.severity?.slice(0, 4)}
                    </span>
                    <div className="min-w-0 flex-1">
                      <div
                        className={`text-[12px] truncate ${isSelected ? 'text-primary font-bold' : 'text-on-surface-variant/80'}`}
                      >
                        {f.title}
                      </div>
                      <div className="text-[10px] text-on-surface-variant/30 truncate">
                        {f.file_path || f.file || f.stack || '—'}
                      </div>
                    </div>
                  </button>
                );
              })}
            </div>
          )}
        </div>
      </div>

      {/* ═══ RIGHT PANEL: Triage Workspace ═════════════════════════════ */}
      <div className="flex-1 flex flex-col h-full overflow-hidden">
        {/* Mode Toggle */}
        <div className="flex border-b border-outline-variant/30 shrink-0 bg-surface-container-lowest">
          <button
            onClick={() => setMode('triage')}
            className={`px-5 py-3 text-[11px] font-bold tracking-widest uppercase transition-colors flex items-center gap-2 ${
              mode === 'triage'
                ? 'text-primary border-b-2 border-primary'
                : 'text-on-surface-variant/50 hover:text-on-surface-variant'
            }`}
          >
            <span className="material-symbols-outlined text-[14px]">bug_report</span>
            Single Finding
          </button>
          <button
            onClick={() => setMode('pipeline')}
            className={`px-5 py-3 text-[11px] font-bold tracking-widest uppercase transition-colors flex items-center gap-2 ${
              mode === 'pipeline'
                ? 'text-primary border-b-2 border-primary'
                : 'text-on-surface-variant/50 hover:text-on-surface-variant'
            }`}
          >
            <span className="material-symbols-outlined text-[14px]">rocket_launch</span>
            Full Pipeline
          </button>
        </div>

        {mode === 'pipeline' ? (
          <PipelinePanel />
        ) : selectedFinding ? (
          <>
            {/* ── Finding Header ─────────────────────────────────────── */}
            <div className="shrink-0 px-6 py-4 border-b border-outline-variant/30 bg-surface-container-lowest">
              <div className="flex items-start justify-between gap-4">
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-3 mb-2">
                    <span
                      className={`text-[10px] font-bold px-2 py-0.5 border ${sevColor(selectedFinding.severity)} ${sevBg(selectedFinding.severity)}`}
                    >
                      {selectedFinding.severity}
                    </span>
                    <span className="text-[10px] text-on-surface-variant/30 tracking-widest">
                      #{selectedFinding.id} — {selectedFinding.rule_id}
                    </span>
                  </div>
                  <h2 className="text-lg text-primary font-bold tracking-tight">
                    {selectedFinding.title}
                  </h2>
                  {(selectedFinding.file_path || selectedFinding.file) && (
                    <div className="text-[11px] text-on-surface-variant/50 mt-1 font-mono">
                      {selectedFinding.file_path || selectedFinding.file}
                      {selectedFinding.line_number ? `:${selectedFinding.line_number}` : ''}
                    </div>
                  )}
                </div>
                <div className="text-right shrink-0">
                  <div className="text-[10px] text-on-surface-variant/30 tracking-widest mb-1">
                    STACK
                  </div>
                  <div className="text-mono-data text-primary font-bold">
                    {selectedFinding.stack || 'core'}
                  </div>
                </div>
              </div>

              {/* Description */}
              {(selectedFinding.description ||
                selectedFinding.fix_suggestion ||
                selectedFinding.suggestion) && (
                <div className="mt-3 p-3 border border-outline-variant/20 bg-surface-container/30">
                  <div className="text-[10px] text-on-surface-variant/30 tracking-widest mb-1 font-bold">
                    {t('framework.descriptionLabel')}
                  </div>
                  <p className="text-[12px] text-on-surface-variant/70 leading-relaxed">
                    {selectedFinding.description ||
                      selectedFinding.fix_suggestion ||
                      selectedFinding.suggestion}
                  </p>
                </div>
              )}
            </div>

            {selectedFinding && <div className="px-6 pb-3"><FindingEvidence finding={selectedFinding} /></div>}
            {/* ── Action Bar ─────────────────────────────────────────── */}
            <div className="shrink-0 px-6 py-3 border-b border-outline-variant/20 bg-surface-container-lowest flex items-center gap-2 overflow-x-auto">
              <span className="text-[9px] text-on-surface-variant/30 tracking-widest font-bold mr-2 shrink-0">
                {t('framework.promptLabel')}
              </span>
              {PROMPT_ACTIONS.map((action) => {
                const isActive = activeAction === action.id;
                return (
                  <button
                    key={action.id}
                    onClick={() => handleAction(action.id)}
                    className={`skeuo-button flex items-center gap-2 px-3 py-2 text-[10px] font-bold tracking-widest shrink-0 ${
                      isActive ? 'border-ai-accent text-ai-accent' : ''
                    }`}
                  >
                    <span className="material-symbols-outlined text-[14px]">{action.icon}</span>
                    {t(`framework.actions.${action.id}.label`)}
                  </button>
                );
              })}
            </div>

            {/* ── Prompt Output ───────────────────────────────────────── */}
            {activePrompt ? (
              <div className="flex-1 flex flex-col min-h-0 overflow-hidden">
                {/* Toolbar */}
                <div className="shrink-0 px-6 py-2 border-b border-outline-variant/20 bg-surface-container-lowest flex items-center justify-between">
                  <span className="text-[10px] text-on-surface-variant/40 tracking-widest font-bold">
                    {t('framework.generatedPrompt', { action: activeAction?.toUpperCase() })}
                  </span>
                  <div className="flex items-center gap-2">
                    <button
                      onClick={handleSendToCopilot}
                      className="flex items-center gap-1.5 px-3 py-1.5 border border-primary/30 text-primary text-[10px] font-bold tracking-widest hover:bg-primary/10 transition-none"
                    >
                      <span className="material-symbols-outlined text-[14px]">smart_toy</span>
                      {t('framework.sendToCopilot')}
                    </button>
                    <button
                      onClick={handleCopy}
                      className={`flex items-center gap-1.5 px-3 py-1.5 border text-[10px] font-bold tracking-widest transition-none ${
                        copied
                          ? 'border-success text-success bg-success/10'
                          : 'border-outline-variant/30 text-on-surface-variant/60 hover:text-primary hover:border-primary/30'
                      }`}
                    >
                      <span className="material-symbols-outlined text-[14px]">
                        {copied ? 'check' : 'content_copy'}
                      </span>
                      {copied ? t('framework.copied') : t('framework.copy')}
                    </button>
                  </div>
                </div>

                {/* Editable prompt */}
                <textarea
                  value={activePrompt}
                  onChange={(e) => setActivePrompt(e.target.value)}
                  className="flex-1 w-full bg-surface-container-lowest skeuo-inset px-6 py-4 text-[12px] font-mono text-on-surface-variant/80 placeholder:text-on-surface-variant/20 resize-none outline-none focus:ring-0 cyber-scrollbar leading-relaxed"
                  spellCheck={false}
                />

                {/* Footer hint */}
                <div className="shrink-0 px-6 py-2 border-t border-outline-variant/10 bg-surface-container-lowest/50 flex items-center justify-between">
                  <span className="text-[10px] text-on-surface-variant/20">
                    {t('framework.footerHint')}
                  </span>
                  <span className="text-[10px] text-on-surface-variant/20 tabular-nums">
                    {t('framework.chars', { count: activePrompt.length })}
                  </span>
                </div>
              </div>
            ) : (
              /* Action not yet selected */
              <div className="flex-1 flex items-center justify-center p-8">
                <div className="text-center max-w-md">
                  <div className="w-16 h-16 border border-outline-variant/10 flex items-center justify-center mx-auto mb-6">
                    <span className="material-symbols-outlined text-[28px] text-on-surface-variant/10">
                      smart_toy
                    </span>
                  </div>
                  <h3 className="text-[11px] text-on-surface-variant/25 tracking-[0.3em] font-bold mb-3">
                    {t('framework.selectAction')}
                  </h3>
                  <p className="text-[11px] text-on-surface-variant/15 leading-relaxed">
                    {t('framework.selectActionDesc')}
                  </p>
                </div>
              </div>
            )}
          </>
        ) : (
          /* ── No finding selected ───────────────────────────────────── */
          <div className="flex-1 flex flex-col items-center justify-center p-12">
            <div className="w-20 h-20 border border-outline-variant/10 flex items-center justify-center mb-8">
              <span className="material-symbols-outlined text-[36px] text-on-surface-variant/10">
                smart_toy
              </span>
            </div>
            <h2 className="text-[12px] text-on-surface-variant/20 tracking-[0.4em] font-bold mb-4">
              {t('framework.title')}
            </h2>
            <p className="text-[11px] text-on-surface-variant/15 max-w-sm text-center leading-relaxed mb-8">
              {t('framework.titleDesc')}
            </p>
            <div className="grid grid-cols-5 gap-3 max-w-lg">
              {PROMPT_ACTIONS.map((a) => (
                <div
                  key={a.id}
                  className="flex flex-col items-center gap-1.5 p-3 border border-outline-variant/10 bg-surface-container-low skeuo-panel"
                >
                  <span className="material-symbols-outlined text-[18px] text-primary opacity-30">
                    {a.icon}
                  </span>
                  <span className="text-[9px] text-on-surface-variant/20 tracking-widest font-bold">
                    {t(`framework.actions.${a.id}.label`)}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
