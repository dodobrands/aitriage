import { FindingEvidence } from '../components/findings/FindingEvidence';
import { isActive, terminalStatuses } from '../lib/findingStatus';
import React, { useState, useMemo, useCallback } from 'react';
import { useTranslation } from 'react-i18next';
import { useFindings } from '../hooks/useFindings';
import { useMetrics } from '../hooks/useMetrics';
import { usePrompts, interpolatePrompt } from '../hooks/usePrompts';
import type { PromptTemplate } from '../hooks/usePrompts';
import { useCopilotStore } from '../store/CopilotStore';
import { useTitle } from '../hooks/useTitle';
import type { Finding } from '../types';
import { CountUp } from '../ui/CountUp';
import { AnimatedProgressCircle } from '../ui/AnimatedProgressCircle';
import { AIPromptsPanel } from '../components/AIPromptsPanel';

export const DashboardPage: React.FC = () => {
  const { t } = useTranslation('pages');
  useTitle(t('dashboard.title'));
  const { findings, loading: findingsLoading } = useFindings();
  const { metrics, loading: metricsLoading, error: metricsError } = useMetrics();
  const { templates: PROMPT_TEMPLATES, loading: promptsLoading } = usePrompts();
  const { setIsOpen, setContext } = useCopilotStore();

  const [selectedFindingId, setSelectedFindingId] = useState<number | null>(null);
  const [activePrompt, setActivePrompt] = useState<string>('');
  const [activeAction, setActiveAction] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [search, setSearch] = useState('');
  const [isPromptsPanelOpen, setIsPromptsPanelOpen] = useState(() => {
    try {
      return localStorage.getItem('ai_prompts_panel_open') === 'true';
    } catch {
      return false;
    }
  });
  const [filterSev, setFilterSev] = useState<string | null>(null);

  const loading = findingsLoading || metricsLoading || promptsLoading;
  const selectedFinding: Finding | null =
    findings?.find((f: Finding) => f.id === selectedFindingId) || null;

  const scoreValue = metrics?.security_score ?? 0;
  const closedStatuses = terminalStatuses;
  const totalOpenValue = useMemo(() => {
    if (!findings) return 0;
    return findings.filter((f: Finding) => {
      const st = (f.status || 'open').toLowerCase();
      return !closedStatuses.includes(st);
    }).length;
  }, [findings]);

  /* ── Filtered findings ── */
  const filteredFindings = useMemo(() => {
    if (!findings) return [];
    return findings.filter((f: Finding) => {
      const matchesSearch =
        !search ||
        f.title?.toLowerCase().includes(search.toLowerCase()) ||
        String(f.id).includes(search);
      const matchesSev = !filterSev || f.severity?.toUpperCase() === filterSev;
      return isActive(f) && matchesSearch && matchesSev;
    });
  }, [findings, search, filterSev]);

  /* ── Statistics Summary ── */
  const stats = useMemo(() => {
    if (!findings || findings.length === 0) return null;
    const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    findings.forEach((f: Finding) => {
      // Only count open/active findings — match backend metrics behavior
      const st = (f.status || 'open').toLowerCase();
      if (closedStatuses.includes(st)) return;
      const sev = f.severity?.toUpperCase();
      if (sev in counts) {
        counts[sev as keyof typeof counts]++;
      }
    });
    return counts;
  }, [findings]);

  /* ── Actions ── */
  const handleSelectFinding = useCallback((id: number) => {
    setSelectedFindingId(id);
    setActivePrompt('');
    setActiveAction(null);
  }, []);

  const handleAction = useCallback(
    (actionId: string) => {
      if (!selectedFinding) return;
      const template = PROMPT_TEMPLATES.find((t: PromptTemplate) => t.id === actionId);
      if (!template) return;
      setActiveAction(actionId);
      setActivePrompt(interpolatePrompt(template.template, selectedFinding));
    },
    [selectedFinding, PROMPT_TEMPLATES],
  );

  const handleCopy = useCallback(() => {
    navigator.clipboard.writeText(activePrompt);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }, [activePrompt]);

  const handleSendToCopilot = useCallback(() => {
    if (!selectedFinding) return;
    setContext(selectedFinding);
    useCopilotStore.getState().setPromptToSubmit(activePrompt);
    setIsOpen(true);
  }, [activePrompt, selectedFinding, setContext, setIsOpen]);

  const handleTogglePromptsPanel = useCallback(() => {
    setIsPromptsPanelOpen((prev) => {
      const next = !prev;
      try {
        localStorage.setItem('ai_prompts_panel_open', String(next));
      } catch { /* Storage is optional. */ }
      return next;
    });
  }, []);

  if (loading) {
    return (
      <div className="flex h-full items-center justify-center bg-v2-bg">
        <div className="flex flex-col items-center gap-6">
          <div className="flex gap-1.5">
            {[0, 1, 2].map((i) => (
              <div
                key={i}
                className="w-2 h-6 bg-primary animate-pulse"
                style={{ animationDelay: `${i * 0.15}s` }}
              />
            ))}
          </div>
          <span className="text-label-caps tracking-[0.3em] text-v2-muted">
            {t('dashboard.loading')}
          </span>
        </div>
      </div>
    );
  }

  return (
    <div className="advanced-review flex h-full overflow-hidden bg-v2-bg relative">
      {/* ═══ LEFT PANEL: Browse Findings ═══ */}
      <div className="advanced-review__list w-[340px] shrink-0 border-r border-v2-border-soft flex flex-col h-full bg-v2-surface overflow-hidden font-sans">
        {/* Posture Header */}
        {stats && (
          <div className="p-4 border-b border-v2-border-soft bg-v2-surface-2 shrink-0">
            <div className="flex items-center gap-2 mb-3">
              <span className="w-1.5 h-3.5 bg-primary rounded-sm" />
              <span className="text-[10px] font-bold tracking-widest text-v2-fg uppercase font-mono">
                {t('dashboard.securityPosture')}
              </span>
            </div>

            {/* Score Strip */}
              <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-4">
                <AnimatedProgressCircle 
                  progress={scoreValue} 
                  size={64} 
                  strokeWidth={4} 
                  color={scoreValue < 50 ? '#ef4444' : scoreValue < 70 ? '#f59e0b' : '#10b981'} 
                />
                <div>
                  <div className="text-[9px] text-on-surface-variant tracking-widest uppercase mb-1 font-mono">
                    {t('dashboard.score')} &bull; {metrics?.security_grade || '—'}
                  </div>
                  <div className="text-mono-data text-on-surface font-bold">
                    {metricsError || !metrics ? t('review.scoreUnavailable') : <><CountUp end={scoreValue} />/100</>}
                  </div>
                </div>
              </div>
              <div className="text-right">
                <div className="text-[9px] text-v2-muted tracking-widest uppercase mb-1 font-mono">
                  {t('dashboard.totalOpen')}
                </div>
                <div className="text-mono-data text-on-surface font-bold"><CountUp end={totalOpenValue} /></div>
              </div>
            </div>

            {/* Severity LEDs Filter Row */}
            <div className="flex gap-1.5">
              {(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const).map((sev) => {
                const count = stats[sev] || 0;
                if (count === 0) return null;
                const isActive = filterSev === sev;
                const isCrit = sev === 'CRITICAL';
                return (
                  <button
                    key={sev}
                    onClick={() => setFilterSev(isActive ? null : sev)}
                    className={`flex items-center gap-2 px-2 py-1 rounded border text-[10px] font-bold tracking-wider transition-all duration-300 ${
                      isActive
                        ? isCrit
                          ? 'bg-error/10 border-error text-error severity-critical-glow'
                          : 'bg-surface border-v2-border text-white'
                        : 'border-v2-border-soft text-v2-muted hover:border-v2-border hover:bg-v2-elev'
                    }`}
                  >
                    <span
                      className={`status-dot ${
                        sev === 'CRITICAL'
                          ? 'status-dot-critical'
                          : sev === 'HIGH'
                            ? 'status-dot-high'
                            : sev === 'MEDIUM'
                              ? 'status-dot-medium'
                              : 'status-dot-low'
                      } ${isCrit ? 'pulse-glow-critical' : ''}`}
                    />
                    <span>{sev.slice(0, 4)}</span>
                    <span className="opacity-60">({count})</span>
                  </button>
                );
              })}
            </div>
          </div>
        )}

        {/* Filter Input */}
        <div className="p-3 border-b border-v2-border-soft bg-v2-surface shrink-0">
          <div className="flex items-center border border-v2-border-soft bg-v2-surface-2 rounded-lg h-9 px-3 gap-2 w-full focus-within:border-primary/30 transition-colors">
            <span className="material-symbols-outlined text-v2-muted" style={{ fontSize: '15px' }}>
              search
            </span>
            <input
              className="bg-transparent border-none focus:outline-none focus:ring-0 text-mono-data text-white placeholder:text-v2-muted w-full text-xs"
              placeholder={t('dashboard.searchPlaceholder')}
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </div>
        </div>

        {/* Findings List */}
        <div className="flex-1 overflow-y-auto cyber-scrollbar divide-y divide-v2-border-soft">
          {filteredFindings.length === 0 ? (
            <div className="p-8 text-center flex flex-col items-center opacity-50 font-mono">
              <span className="material-symbols-outlined text-3xl mb-3 text-v2-muted">
                search_off
              </span>
              <span className="text-[10px] font-bold tracking-widest text-v2-muted uppercase">
                {t('dashboard.noFindings')}
              </span>
            </div>
          ) : (
            filteredFindings.map((f: Finding, i: number) => {
              const isSelected = selectedFindingId === f.id;
              const sev = f.severity?.toUpperCase();
              return (
                <button
                  key={f.id}
                  onClick={() => handleSelectFinding(f.id)}
                  style={{ '--stagger-idx': i } as React.CSSProperties}
                  className={`w-full text-left px-4 py-3 flex items-start gap-3 transition-all duration-200 ease-out stagger-enter ${
                    isSelected
                      ? 'bg-surface-bright border-l-2 border-l-primary shadow-[inset_4px_0_12px_rgba(139,92,246,0.1)]'
                      : 'border-l-2 border-l-transparent hover:bg-surface-bright hover:-translate-y-[2px] hover:shadow-[0_4px_16px_rgba(139,92,246,0.08)]'
                  }`}
                >
                  <span
                    className={`status-dot mt-1 shrink-0 ${
                      sev === 'CRITICAL'
                        ? 'status-dot-critical'
                        : sev === 'HIGH'
                          ? 'status-dot-high'
                          : sev === 'MEDIUM'
                            ? 'status-dot-medium'
                            : 'status-dot-low'
                    } ${sev === 'CRITICAL' ? 'pulse-glow-critical' : ''}`}
                  />
                  <div className="min-w-0 flex-1">
                    <div
                      className={`text-[12px] leading-tight font-medium ${isSelected ? 'text-white font-bold' : 'text-v2-fg-2'}`}
                    >
                      {f.title}
                    </div>
                    <div className="text-[10px] text-v2-muted truncate mt-1 flex items-center justify-between font-mono">
                      <span className="truncate">{f.file_path || f.file || t('dashboard.defaultSystem')}</span>
                      <span className="shrink-0 uppercase font-bold tracking-wider pl-2 text-[9px] opacity-70">
                        {f.stack || t('dashboard.defaultCore')}
                      </span>
                    </div>
                  </div>
                </button>
              );
            })
          )}
        </div>
      </div>

      {/* ═══ CENTER PANEL: Triage prompt framework ═══ */}
      <div className="advanced-review__detail flex-1 min-w-0 flex flex-col h-full overflow-hidden bg-v2-bg">
        {selectedFinding ? (
          <>
            {/* Detailed Header panel */}
            <div className="px-6 py-5 border-b border-v2-border-soft bg-v2-surface shrink-0">
              <div className="flex items-start justify-between gap-6">
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-3 mb-2.5">
                    <span
                      className={`text-[10px] font-bold px-2 py-0.5 rounded uppercase border ${
                        selectedFinding.severity?.toUpperCase() === 'CRITICAL' ||
                        selectedFinding.severity?.toUpperCase() === 'HIGH'
                          ? 'bg-v2-red-soft border-v2-red-line text-v2-red'
                          : 'bg-v2-surface-2 border-v2-border-soft text-v2-muted'
                      }`}
                    >
                      {selectedFinding.severity}
                    </span>
                    <span className="text-[10px] text-v2-muted font-mono select-all">
                      #{selectedFinding.id} &bull; {selectedFinding.rule_id || t('dashboard.generalRule')}
                    </span>
                  </div>
                  <h2 className="text-base text-white font-bold tracking-tight leading-snug">
                    {selectedFinding.title}
                  </h2>
                  {(selectedFinding.file_path || selectedFinding.file) && (
                    <div className="text-[11px] text-v2-fg-2 mt-1.5 font-mono truncate select-all">
                      {selectedFinding.file_path || selectedFinding.file}
                      {selectedFinding.line_number ? `:${selectedFinding.line_number}` : ''}
                    </div>
                  )}
                </div>
                <div className="text-right shrink-0">
                  <span className="text-[9px] text-v2-muted tracking-widest block uppercase font-bold mb-1">
                    {t('dashboard.analysisStack')}
                  </span>
                  <span className="v2-tag">{selectedFinding.stack || t('dashboard.defaultCore')}</span>
                </div>
              </div>

              {/* Description box */}
              {(selectedFinding.description ||
                selectedFinding.suggestion ||
                selectedFinding.fix_suggestion) && (
                <div className="mt-4 p-4 border border-v2-border-soft rounded-xl bg-v2-surface-2">
                  <div className="text-[9px] text-v2-muted tracking-widest font-bold mb-2">
                    {t('dashboard.vulnDescription')}
                  </div>
                  <p className="text-[13px] text-v2-fg-2 leading-relaxed max-h-24 overflow-y-auto cyber-scrollbar">
                    {selectedFinding.description ||
                      selectedFinding.suggestion ||
                      selectedFinding.fix_suggestion}
                  </p>
                </div>
              )}
            </div>

            <div className="shrink-0 px-6 pb-4 max-h-64 overflow-y-auto"><FindingEvidence finding={selectedFinding} /></div>
            {/* Prompt Template selectors */}
            <div className="shrink-0 px-6 py-3 border-b border-v2-border-soft bg-v2-surface flex flex-wrap items-center gap-2">
              <span className="text-[10px] text-v2-muted tracking-widest font-bold mr-2 shrink-0">
                {t('dashboard.templates')}
              </span>
              {PROMPT_TEMPLATES.map((tmpl) => {
                const isActive = activeAction === tmpl.id;
                return (
                  <button
                    key={tmpl.id}
                    onClick={() => handleAction(tmpl.id)}
                    className={`v2-tag inline-flex items-center gap-2 shrink-0 cursor-pointer transition-all duration-200 ease-out hover:-translate-y-[2px] hover:shadow-[0_4px_12px_rgba(139,92,246,0.15)] ${
                      isActive
                        ? 'bg-v2-red-soft border-v2-red-line text-v2-red'
                        : 'hover:bg-v2-surface-2'
                    }`}
                  >
                    <span
                      aria-hidden="true" className="material-symbols-outlined text-[13px]"
                      style={{ fontVariationSettings: isActive ? "'FILL' 1" : "'FILL' 0" }}
                    >
                      {tmpl.icon}
                    </span>
                    {tmpl.label}
                  </button>
                );
              })}
            </div>

            {/* Editable Prompt Workspace */}
            {activePrompt ? (
              <div className="flex-1 flex flex-col min-h-0 overflow-hidden bg-v2-bg">
                {/* Actions Toolbar */}
                <div className="shrink-0 px-6 py-3 border-b border-v2-border-soft bg-v2-surface-2 flex items-center justify-between">
                  <span className="text-[10px] text-v2-muted tracking-widest font-bold">
                    {t('dashboard.workspace')} ({activeAction?.toUpperCase()})
                  </span>
                  <div className="flex items-center gap-3">
                    <button
                      onClick={handleCopy}
                      className="v2-btn v2-btn-ghost px-3 py-1.5 h-8 text-[11px]"
                    >
                      <span aria-hidden="true" className="material-symbols-outlined text-[13px]">
                        {copied ? 'check' : 'content_copy'}
                      </span>
                      {copied ? t('dashboard.copied') : t('dashboard.copy')}
                    </button>
                    <button
                      onClick={handleSendToCopilot}
                      className="v2-btn v2-btn-red px-3.5 py-1.5 h-8 text-[11px]"
                    >
                      <span aria-hidden="true" className="material-symbols-outlined text-[13px]">smart_toy</span>
                      {t('dashboard.sendToCopilot')}
                    </button>
                  </div>
                </div>

                {/* Inner Textarea */}
                <div className="flex-1 p-6 overflow-hidden">
                  <textarea
                    value={activePrompt}
                    onChange={(e) => setActivePrompt(e.target.value)}
                    className="w-full h-full bg-v2-surface rounded-xl border border-v2-border-soft p-5 text-[13px] font-mono text-white leading-relaxed resize-none outline-none focus:ring-0 focus:border-v2-red/50 cyber-scrollbar transition-colors"
                    spellCheck={false}
                  />
                </div>

                {/* Info footer */}
                <div className="shrink-0 px-6 py-3 border-t border-v2-border-soft bg-v2-surface flex items-center justify-between text-[10px] text-v2-muted font-mono">
                  <span>
                    {t('dashboard.promptInfo')}
                  </span>
                  <span>{activePrompt.length} {t('dashboard.chars')}</span>
                </div>
              </div>
            ) : (
              /* Prompt not yet chosen state */
              <div className="flex-1 flex flex-col items-center justify-center p-8 bg-v2-bg">
                <div className="text-center max-w-sm">
                  <div className="w-14 h-14 border border-v2-border-soft rounded-2xl flex items-center justify-center mx-auto mb-5 bg-v2-surface">
                    <span className="material-symbols-outlined text-[24px] text-v2-muted">
                      smart_toy
                    </span>
                  </div>
                  <h3 className="text-[11px] text-v2-muted tracking-[0.25em] font-bold mb-2 uppercase">
                    {t('dashboard.selectPromptType')}
                  </h3>
                  <p className="text-[12px] text-v2-fg-2 leading-relaxed">
                    {t('dashboard.chooseTemplate')}
                  </p>
                </div>
              </div>
            )}
          </>
        ) : (
          /* Finding not yet chosen state */
          <div className="flex-1 flex flex-col items-center justify-center p-12 bg-v2-bg">
            <div className="w-16 h-16 border border-v2-border-soft rounded-2xl flex items-center justify-center mb-6 bg-v2-surface">
              <span className="material-symbols-outlined text-[28px] text-v2-muted">security</span>
            </div>
            <h2 className="text-[12px] text-v2-muted tracking-[0.3em] font-bold mb-3 uppercase">
              {t('dashboard.aiTriageWorkspace')}
            </h2>
            <p className="text-[12px] text-v2-fg-2 max-w-xs text-center leading-relaxed mb-6">
              {t('dashboard.selectVulnerability')}
            </p>
            <div className="flex gap-2 flex-wrap justify-center max-w-md opacity-50 select-none pointer-events-none">
              {PROMPT_TEMPLATES.map((t) => (
                <div
                  key={t.id}
                  className="flex items-center gap-1.5 px-3 py-1.5 border border-v2-border-soft rounded-full bg-v2-surface text-[10px] font-bold tracking-widest text-v2-muted"
                >
                  <span className="material-symbols-outlined text-[12px]">{t.icon}</span>
                  {t.label}
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* ═══ RIGHT PANEL: AI IDE Prompts ═══ */}
      <AIPromptsPanel isOpen={isPromptsPanelOpen} onToggle={handleTogglePromptsPanel} />
    </div>
  );
};
