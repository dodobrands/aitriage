import api from '../services/api';
import { isActive, isResolved, isSuppressed, severityCounts } from '../lib/findingStatus';
import React, { useState, useMemo, useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { useFindings } from '../hooks/useFindings';
import { useProducts } from '../hooks/useProducts';
import type { Finding, Product } from '../types';
import { motion, AnimatePresence } from 'framer-motion';
import Markdown from 'react-markdown';
import { securityService } from '../services/securityService';

interface ProjectStats {
  product: Product;
  total: number;
  open: number;
  fixed: number;
  triaged: number;
  falsePositive: number;
  riskAccepted: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export const RepositoriesPage: React.FC = () => {
  const { t, i18n } = useTranslation('pages');
  const {
    findings,
    loading: findingsLoading,
    error: findingsError,
    refresh: refreshFindings,
  } = useFindings();
  const {
    products,
    loading: productsLoading,
    error: productsError,
    refresh: refreshProducts,
  } = useProducts();
  const [expandedId, setExpandedId] = useState<number | null>(null);
  const [filter, setFilter] = useState<'all' | 'has_issues' | 'clean'>('all');
  const [summaries, setSummaries] = useState<Record<string, string>>({});
  const [loadingSummary, setLoadingSummary] = useState<Record<string, boolean>>({});
  const [scoreResult, setScoreResult] = useState<{
    products: Product[];
    findings: Finding[];
    scores: Record<number, number>;
  } | null>(null);
  const projectScores =
    scoreResult?.products === products && scoreResult.findings === findings
      ? scoreResult.scores
      : {};
  useEffect(() => {
    const controller = new AbortController();
    const scores: Record<number, number> = {};
    let index = 0;
    const worker = async () => {
      while (!controller.signal.aborted && index < products.length) {
        const product = products[index++];
        try {
          const { data } = await api.get(`/metrics?product_id=${product.id}`, {
            signal: controller.signal,
          });
          const score = data.metrics?.security_score;
          if (data.ok && typeof score === 'number' && score >= 0 && score <= 100)
            scores[product.id] = score;
        } catch {
          /* Unavailable scores remain unknown, never reuse an earlier 100. */
        }
      }
    };
    Promise.all(Array.from({ length: Math.min(4, products.length) }, worker)).then(() => {
      if (!controller.signal.aborted) setScoreResult({ products, findings, scores });
    });
    return () => controller.abort();
  }, [products, findings]);
  const [summaryLang, setSummaryLang] = useState<'ru' | 'en'>(
    i18n.language?.startsWith('ru') ? 'ru' : 'en',
  );

  const projectStats = useMemo(() => {
    if (!products || !findings) return [];
    return products
      .map((p: Product): ProjectStats => {
        const pFindings = findings.filter((f: Finding) => f.product_id === p.id);
        return {
          product: p,
          total: pFindings.length,
          open: pFindings.filter((f: Finding) => isActive(f)).length,
          fixed: pFindings.filter((f: Finding) => isResolved(f)).length,
          triaged: pFindings.filter((f: Finding) => f.status === 'triage').length,
          falsePositive: pFindings.filter((f: Finding) => f.status === 'false_positive').length,
          riskAccepted: pFindings.filter(
            (f: Finding) => isSuppressed(f) && f.status !== 'false_positive',
          ).length,
          critical: severityCounts(pFindings).critical,
          high: severityCounts(pFindings).high,
          medium: severityCounts(pFindings).medium,
          low: severityCounts(pFindings).low,
        };
      })
      .sort((a, b) => {
        if (a.critical !== b.critical) return b.critical - a.critical;
        return b.total - a.total;
      });
  }, [products, findings]);

  const filtered = useMemo(() => {
    if (filter === 'has_issues') return projectStats.filter((s) => s.open > 0);
    if (filter === 'clean') return projectStats.filter((s) => s.open === 0);
    return projectStats;
  }, [projectStats, filter]);

  const totals = useMemo(
    () => ({
      projects: projectStats.length,
      total: projectStats.reduce((s, p) => s + p.total, 0),
      open: projectStats.reduce((s, p) => s + p.open, 0),
      fixed: projectStats.reduce((s, p) => s + p.fixed, 0),
      critical: projectStats.reduce((s, p) => s + p.critical, 0),
    }),
    [projectStats],
  );

  // Load previously generated summaries so they survive tab switches/refreshes.
  // Uses the persisted /api/ai-summary path (ai_summaries table), same as the
  // dashboard — no LLM call, and generate=false returns "" when none stored.
  useEffect(() => {
    if (expandedId === null) return;
    let cancelled = false;
    products
      .filter((product) => product.id === expandedId)
      .forEach((p: Product) => {
        securityService
          .getAISummary(p.id, summaryLang, false)
          .then((stored) => {
            if (cancelled || !stored) return;
            setSummaries((prev) => ({ ...prev, [`${summaryLang}:${p.id}`]: stored }));
          })
          .catch(() => {
            /* none stored yet */
          });
      });
    return () => {
      cancelled = true;
    };
  }, [products, summaryLang, expandedId]);

  const generateSummary = (projectId: number) => {
    const stats = projectStats.find((s) => s.product.id === projectId);
    if (!stats || stats.total === 0) return;

    const key = `${summaryLang}:${projectId}`;
    if (loadingSummary[key]) return;
    setLoadingSummary((prev) => ({ ...prev, [key]: true }));

    // Reuse the persisted summary pipeline: the server builds evidence from the
    // DB, runs the SecureCoder prompt, and stores the result in ai_summaries so
    // it is not lost on refresh (previously this used a stateless /api/chat call
    // whose output was only kept in React state).
    securityService
      .getAISummary(projectId, summaryLang, true)
      .then((summary) => {
        setSummaries((prev) => ({ ...prev, [key]: summary || 'No response' }));
      })
      .catch(() => {
        setSummaries((prev) => ({ ...prev, [key]: 'Failed to generate summary.' }));
      })
      .finally(() => {
        setLoadingSummary((prev) => ({ ...prev, [key]: false }));
      });
  };

  const sevDot = (sev: string) => {
    switch (sev) {
      case 'critical':
        return '#ef4444';
      case 'high':
        return '#f97316';
      case 'medium':
        return '#eab308';
      case 'low':
        return '#3f3f46';
      default:
        return '#3f3f46';
    }
  };

  if (findingsError || productsError)
    return (
      <div role="alert" className="m-6 p-4 border border-error rounded-lg">
        <p>{t('review.loadFailed')}</p>
        <p className="text-sm text-on-surface-variant my-2">{findingsError || productsError}</p>
        <button
          type="button"
          className="btn-secondary px-4 py-2"
          onClick={() => {
            refreshFindings();
            refreshProducts();
          }}
        >
          {t('review.retry')}
        </button>
      </div>
    );
  if (findingsLoading || productsLoading)
    return (
      <div role="status" className="p-8 text-on-surface-variant">
        {t('framework.loading')}
      </div>
    );

  return (
    <div
      className="h-full overflow-y-auto"
      style={{ scrollbarWidth: 'thin', scrollbarColor: 'rgba(255,255,255,0.06) transparent' }}
    >
      <div className="max-w-5xl mx-auto px-4 md:px-8 py-8 space-y-6">
        {/* Summary cards */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {[
            { label: t('projects'), value: totals.projects, icon: 'folder', color: '#a1a1aa' },
            { label: t('total_issues'), value: totals.total, icon: 'bug_report', color: '#f97316' },
            { label: t('open'), value: totals.open, icon: 'error', color: '#ef4444' },
            { label: t('status_fixed'), value: totals.fixed, icon: 'psychology', color: '#38bdf8' },
          ].map((c) => (
            <div
              key={c.label}
              className="border border-[rgba(255,255,255,0.06)] rounded-lg p-4 bg-[rgba(255,255,255,0.01)]"
            >
              <div className="flex items-center gap-2 mb-2">
                <span className="material-symbols-outlined text-[16px]" style={{ color: c.color }}>
                  {c.icon}
                </span>
                <span className="text-[11px] text-[#52525b] uppercase tracking-wider font-medium">
                  {c.label}
                </span>
              </div>
              <div className="text-2xl font-bold text-[#f4f4f5] tabular-nums">{c.value}</div>
            </div>
          ))}
        </div>

        {/* Filter */}
        <div className="flex items-center gap-2">
          {(['all', 'has_issues', 'clean'] as const).map((f) => (
            <button
              key={f}
              onClick={() => setFilter(f)}
              className={`text-[12px] px-3 py-1.5 rounded-md border transition-colors ${filter === f ? 'border-[rgba(255,255,255,0.12)] bg-[rgba(255,255,255,0.05)] text-[#f4f4f5]' : 'border-[rgba(255,255,255,0.06)] text-[#52525b] hover:text-[#a1a1aa]'}`}
            >
              {f === 'all'
                ? `${t('all')} (${projectStats.length})`
                : f === 'has_issues'
                  ? `${t('with_issues')} (${projectStats.filter((s) => s.open > 0).length})`
                  : `${t('clean')} (${projectStats.filter((s) => s.open === 0).length})`}
            </button>
          ))}
        </div>

        {/* Project list */}
        <div className="space-y-2">
          {filtered.length === 0 ? (
            <div className="py-12 text-center text-[13px] text-[#3f3f46]">
              {t('no_projects_found_desc')}
            </div>
          ) : (
            filtered.map((stats) => {
              const isExpanded = expandedId === stats.product.id;
              const summaryKey = `${summaryLang}:${stats.product.id}`;
              const healthPercent =
                stats.total === 0
                  ? 100
                  : Math.round(
                      ((stats.fixed + stats.triaged + stats.falsePositive + stats.riskAccepted) /
                        stats.total) *
                        100,
                    );
              const findingsForProject =
                findings?.filter((f: Finding) => f.product_id === stats.product.id) || [];

              return (
                <div
                  key={stats.product.id}
                  className="border border-[rgba(255,255,255,0.06)] rounded-lg overflow-hidden bg-[rgba(255,255,255,0.01)]"
                >
                  {/* Project header */}
                  <button
                    onClick={() => setExpandedId(isExpanded ? null : stats.product.id)}
                    className="w-full text-left px-5 py-4 flex flex-wrap items-center gap-4 hover:bg-[rgba(255,255,255,0.02)] transition-colors"
                  >
                    <div
                      className={`w-2.5 h-2.5 rounded-full shrink-0 ${stats.critical > 0 ? 'bg-[#ef4444]' : stats.open > 0 ? 'bg-[#f97316]' : 'bg-[#22c55e]'}`}
                    />
                    <div className="flex-1 min-w-0">
                      <div className="text-[14px] text-[#f4f4f5] font-medium break-all">
                        {stats.product.name}
                      </div>
                      <div className="text-[11px] text-[#3f3f46] mt-0.5 font-mono truncate">
                        {stats.product.repo_url || stats.product.description || t('no_path')}
                      </div>
                    </div>
                    <div className="flex items-center gap-1 shrink-0">
                      {(['critical', 'high', 'medium', 'low'] as const).map((sev) => {
                        const count = stats[sev];
                        return count > 0 ? (
                          <span
                            key={sev}
                            className="flex items-center gap-1 text-[10px] px-1.5 py-0.5 rounded"
                            style={{ color: sevDot(sev), backgroundColor: `${sevDot(sev)}15` }}
                          >
                            {count}
                          </span>
                        ) : null;
                      })}
                    </div>
                    <div className="shrink-0 text-xs" aria-label={t('securityScore')}>
                      {projectScores[stats.product.id] ?? '—'}/100
                    </div>
                    <div className="w-24 shrink-0">
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-[10px] text-[#52525b]">
                          {healthPercent}% {t('triaged')}
                        </span>
                      </div>
                      <div className="w-full h-1 bg-[#18181b] rounded-full overflow-hidden flex">
                        {stats.triaged > 0 && (
                          <div
                            className="h-full bg-[#38bdf8]"
                            style={{ width: `${(stats.triaged / stats.total) * 100}%` }}
                          />
                        )}
                        {stats.fixed > 0 && (
                          <div
                            className="h-full bg-[#38bdf8]"
                            style={{ width: `${(stats.fixed / stats.total) * 100}%` }}
                          />
                        )}
                        {stats.riskAccepted > 0 && (
                          <div
                            className="h-full bg-[#f59e0b]"
                            style={{ width: `${(stats.riskAccepted / stats.total) * 100}%` }}
                          />
                        )}
                        {stats.falsePositive > 0 && (
                          <div
                            className="h-full bg-[#52525b]"
                            style={{ width: `${(stats.falsePositive / stats.total) * 100}%` }}
                          />
                        )}
                      </div>
                    </div>
                    <span className="text-[12px] text-[#52525b] tabular-nums w-16 text-right shrink-0">
                      {stats.total} {t('issues')}
                    </span>
                    <span
                      className={`material-symbols-outlined text-[16px] text-[#3f3f46] transition-transform ${isExpanded ? 'rotate-180' : ''}`}
                    >
                      expand_more
                    </span>
                  </button>

                  {/* Expanded detail */}
                  <AnimatePresence initial={false}>
                    {isExpanded && (
                      <motion.div
                        key="details"
                        initial={{ height: 0, opacity: 0 }}
                        animate={{ height: 'auto', opacity: 1 }}
                        exit={{ height: 0, opacity: 0 }}
                        transition={{ type: 'spring' as const, stiffness: 300, damping: 30 }}
                        className="overflow-hidden border-t border-[rgba(255,255,255,0.06)]"
                      >
                        <div className="px-5 py-4 space-y-4">
                          {/* AI Summary — Manual */}
                          <div className="border border-[rgba(255,255,255,0.08)] rounded-xl p-5 bg-[rgba(255,255,255,0.015)] shadow-inner">
                            <div className="flex items-center justify-between mb-3 border-b border-[rgba(255,255,255,0.04)] pb-3">
                              <div className="flex items-center gap-2">
                                <span className="material-symbols-outlined text-[15px] text-[#71717a]">
                                  shield_lock
                                </span>
                                <span className="text-[10px] text-[#e4e4e7] uppercase tracking-[0.2em] font-black">
                                  {t('ai_summary')}
                                </span>
                              </div>
                              <div className="flex items-center gap-3">
                                <select
                                  value={summaryLang}
                                  onChange={(e) => setSummaryLang(e.target.value as 'en' | 'ru')}
                                  className="text-[10px] text-[#a1a1aa] bg-[rgba(255,255,255,0.03)] border border-[rgba(255,255,255,0.08)] rounded px-1.5 py-0.5 outline-none hover:border-[rgba(255,255,255,0.15)] focus:border-[#71717a] transition-colors appearance-none font-bold tracking-wider"
                                >
                                  <option value="ru">RU</option>
                                  <option value="en">EN</option>
                                </select>
                                {loadingSummary[summaryKey] && (
                                  <div className="w-3 h-3 border border-[#52525b] border-t-[#e4e4e7] rounded-full animate-spin ml-1" />
                                )}
                                {summaries[summaryKey] && !loadingSummary[summaryKey] && (
                                  <button
                                    onClick={(e) => {
                                      e.stopPropagation();
                                      generateSummary(stats.product.id);
                                    }}
                                    className="ml-auto text-[10px] text-[#71717a] hover:text-[#e4e4e7] transition-colors flex items-center gap-1.5 font-bold uppercase tracking-wider"
                                  >
                                    <span className="material-symbols-outlined text-[13px]">
                                      refresh
                                    </span>
                                    {t('regenerate')}
                                  </button>
                                )}
                              </div>
                            </div>

                            <div className="pt-1">
                              {loadingSummary[summaryKey] ? (
                                <div className="flex items-center gap-3 py-3">
                                  <div className="flex gap-1.5">
                                    {[0, 1, 2].map((i) => (
                                      <div
                                        key={i}
                                        className="w-1.5 h-1.5 rounded-full bg-[#52525b] animate-pulse"
                                        style={{ animationDelay: `${i * 150}ms` }}
                                      />
                                    ))}
                                  </div>
                                  <span className="text-[11px] text-[#71717a] font-mono tracking-widest uppercase">
                                    {t('analyzing_repo')}
                                  </span>
                                </div>
                              ) : summaries[summaryKey] ? (
                                <div className="text-[12px] text-[#a1a1aa] leading-relaxed prose prose-invert max-w-none [&_strong]:text-[#e4e4e7] [&_strong]:font-semibold [&_code]:text-[#e4e4e7] [&_code]:bg-[#27272a] [&_code]:border [&_code]:border-[#3f3f46] [&_code]:px-1.5 [&_code]:py-0.5 [&_code]:rounded-md [&_code]:text-[11px]">
                                  <Markdown>{summaries[summaryKey]}</Markdown>
                                </div>
                              ) : stats.total === 0 ? (
                                <p className="text-[11px] text-[#52525b] font-mono tracking-widest uppercase py-2">
                                  SECURE // {t('no_security_issues')}
                                </p>
                              ) : (
                                <div className="flex items-center justify-between py-2">
                                  <p className="text-[11px] font-mono text-[#71717a] tracking-wide">
                                    {t('security_analysis_ready')}
                                  </p>
                                  <button
                                    onClick={(e) => {
                                      e.stopPropagation();
                                      generateSummary(stats.product.id);
                                    }}
                                    className="flex items-center gap-2 px-4 py-2 rounded-md bg-[#18181b] border border-[#3f3f46] text-[#e4e4e7] text-[10px] font-black uppercase tracking-[0.15em] hover:bg-[#27272a] hover:border-[#52525b] transition-all"
                                  >
                                    <span className="material-symbols-outlined text-[14px] text-[#a1a1aa]">
                                      analytics
                                    </span>
                                    {t('generate')}
                                  </button>
                                </div>
                              )}
                            </div>
                          </div>

                          {/* Metrics grid */}
                          <div className="grid grid-cols-6 gap-3">
                            {[
                              { label: t('open'), value: stats.open, color: '#ef4444' },
                              { label: t('status_fixed'), value: stats.fixed, color: '#38bdf8' },
                              {
                                label: t('false_positive'),
                                value: stats.falsePositive,
                                color: '#71717a',
                              },
                              {
                                label: t('accepted_risk'),
                                value: stats.riskAccepted,
                                color: '#f59e0b',
                              },
                              { label: t('critical'), value: stats.critical, color: '#ef4444' },
                              { label: t('high'), value: stats.high, color: '#f97316' },
                            ].map((s) => (
                              <div key={s.label} className="text-center">
                                <div
                                  className="text-xl font-bold tabular-nums"
                                  style={{ color: s.color }}
                                >
                                  {s.value}
                                </div>
                                <div className="text-[10px] text-[#52525b] mt-0.5">{s.label}</div>
                              </div>
                            ))}
                          </div>

                          {/* Severity breakdown bar */}
                          {stats.total > 0 && (
                            <div>
                              <div className="text-[10px] text-[#3f3f46] uppercase tracking-wider mb-1.5">
                                {t('severity_breakdown')}
                              </div>
                              <div className="w-full h-2 bg-[#18181b] rounded-full overflow-hidden flex">
                                {stats.critical > 0 && (
                                  <div
                                    className="h-full bg-[#ef4444]"
                                    style={{ width: `${(stats.critical / stats.total) * 100}%` }}
                                  />
                                )}
                                {stats.high > 0 && (
                                  <div
                                    className="h-full bg-[#f97316]"
                                    style={{ width: `${(stats.high / stats.total) * 100}%` }}
                                  />
                                )}
                                {stats.medium > 0 && (
                                  <div
                                    className="h-full bg-[#eab308]"
                                    style={{ width: `${(stats.medium / stats.total) * 100}%` }}
                                  />
                                )}
                                {stats.low > 0 && (
                                  <div
                                    className="h-full bg-[#3f3f46]"
                                    style={{ width: `${(stats.low / stats.total) * 100}%` }}
                                  />
                                )}
                              </div>
                              <div className="flex items-center gap-3 mt-1.5 text-[10px] text-[#52525b]">
                                {stats.critical > 0 && (
                                  <span className="flex items-center gap-1">
                                    <span className="w-1.5 h-1.5 rounded-full bg-[#ef4444]" />
                                    {stats.critical} {t('critical')}
                                  </span>
                                )}
                                {stats.high > 0 && (
                                  <span className="flex items-center gap-1">
                                    <span className="w-1.5 h-1.5 rounded-full bg-[#f97316]" />
                                    {stats.high} {t('high')}
                                  </span>
                                )}
                                {stats.medium > 0 && (
                                  <span className="flex items-center gap-1">
                                    <span className="w-1.5 h-1.5 rounded-full bg-[#eab308]" />
                                    {stats.medium} {t('medium')}
                                  </span>
                                )}
                                {stats.low > 0 && (
                                  <span className="flex items-center gap-1">
                                    <span className="w-1.5 h-1.5 rounded-full bg-[#3f3f46]" />
                                    {stats.low} {t('low')}
                                  </span>
                                )}
                              </div>
                            </div>
                          )}

                          {/* Top issues */}
                          {findingsForProject.length > 0 && (
                            <div>
                              <div className="text-[10px] text-[#3f3f46] uppercase tracking-wider mb-2">
                                {t('top_issues')}
                              </div>
                              <div className="space-y-1">
                                {findingsForProject
                                  .filter((f: Finding) => isActive(f))
                                  .sort((a: Finding, b: Finding) => {
                                    const order: Record<string, number> = {
                                      critical: 0,
                                      high: 1,
                                      medium: 2,
                                      low: 3,
                                    };
                                    return (
                                      (order[a.severity?.toLowerCase()] ?? 4) -
                                      (order[b.severity?.toLowerCase()] ?? 4)
                                    );
                                  })
                                  .slice(0, 5)
                                  .map((f: Finding) => (
                                    <div
                                      key={f.id}
                                      className="flex items-center gap-2 px-3 py-1.5 rounded hover:bg-[rgba(255,255,255,0.02)] text-[12px]"
                                    >
                                      <span
                                        className="w-1.5 h-1.5 rounded-full shrink-0"
                                        style={{ backgroundColor: sevDot(f.severity) }}
                                      />
                                      <span className="text-[#a1a1aa] flex-1 truncate">
                                        {f.title}
                                      </span>
                                      <span className="text-[10px] text-[#3f3f46] font-mono truncate max-w-[200px]">
                                        {f.file_path}
                                      </span>
                                      <span
                                        className="text-[10px] uppercase font-medium px-1.5 py-0.5 rounded"
                                        style={{
                                          color: sevDot(f.severity),
                                          backgroundColor: `${sevDot(f.severity)}15`,
                                        }}
                                      >
                                        {f.severity}
                                      </span>
                                    </div>
                                  ))}
                                {findingsForProject.filter((f: Finding) => isActive(f)).length >
                                  5 && (
                                  <div className="text-[11px] text-[#3f3f46] px-3 py-1">
                                    +
                                    {findingsForProject.filter((f: Finding) => isActive(f)).length -
                                      5}{' '}
                                    {t('more_open_issues')}
                                  </div>
                                )}
                              </div>
                            </div>
                          )}

                          <div className="flex items-center gap-4 text-[10px] text-[#3f3f46] pt-2 border-t border-[rgba(255,255,255,0.04)]">
                            <span>
                              {t('created')}{' '}
                              {new Date(stats.product.created_at).toLocaleDateString()}
                            </span>
                            {stats.product.lifecycle && (
                              <span>
                                {t('lifecycle')} {stats.product.lifecycle}
                              </span>
                            )}
                            {stats.product.business_criticality && (
                              <span>
                                {t('criticality')} {stats.product.business_criticality}
                              </span>
                            )}
                          </div>
                        </div>
                      </motion.div>
                    )}
                  </AnimatePresence>
                </div>
              );
            })
          )}
        </div>
      </div>
    </div>
  );
};
