import { isResolved } from '../lib/findingStatus';
import React, { useState, useMemo } from 'react';
import { useFindings } from '../hooks/useFindings';
import { useProducts } from '../hooks/useProducts';
import type { Finding, Product } from '../types';
import { useTranslation } from 'react-i18next';
import { motion, AnimatePresence } from 'framer-motion';

type TriageStatus = 'resolved' | 'triage' | 'false_positive' | 'risk_accepted';
type TabFilter = 'all' | TriageStatus;

const statusConfig: Record<TriageStatus, { labelKey: string; icon: string; color: string; bg: string }> = {
  resolved: { labelKey: 'status_fixed', icon: 'check_circle', color: '#22c55e', bg: 'rgba(34,197,94,0.08)' },
  triage: { labelKey: 'triage', icon: 'psychology', color: '#38bdf8', bg: 'rgba(56,189,248,0.08)' },
  false_positive: { labelKey: 'false_positive', icon: 'block', color: '#71717a', bg: 'rgba(255,255,255,0.04)' },
  risk_accepted: { labelKey: 'accepted_risk', icon: 'verified_user', color: '#f59e0b', bg: 'rgba(245,158,11,0.08)' },
};

const containerVariants = {
  hidden: { opacity: 0 },
  visible: {
    opacity: 1,
    transition: {
      staggerChildren: 0.05,
    },
  },
};

const itemVariants = {
  hidden: { opacity: 0, y: 12 },
  visible: {
    opacity: 1,
    y: 0,
    transition: {
      type: "spring" as const,
      stiffness: 260,
      damping: 25,
    },
  },
};

export const TriagedPage: React.FC = () => {
  const { t } = useTranslation('pages');
  const { findings } = useFindings() as any;
  const { products } = useProducts();
  const [tab, setTab] = useState<TabFilter>('all');
  const [expandedId, setExpandedId] = useState<number | null>(null);
  const [productFilter, setProductFilter] = useState<number | null>(null);

  const productMap = useMemo(() => {
    const m = new Map<number, Product>();
    products?.forEach((p: Product) => m.set(p.id, p));
    return m;
  }, [products]);

  const triagedFindings = useMemo(() => {
    if (!findings) return [];
    let filtered = findings.filter((f: Finding) =>
      isResolved(f) || f.status === 'triage' || f.status === 'false_positive' || f.status === 'risk_accepted'
    );
    if (tab !== 'all') filtered = filtered.filter((f: Finding) => (tab === 'resolved' ? isResolved(f) : f.status === tab));
    if (productFilter !== null) filtered = filtered.filter((f: Finding) => f.product_id === productFilter);
    return filtered;
  }, [findings, tab, productFilter]);

  const counts = useMemo(() => {
    if (!findings) return { resolved: 0, triage: 0, false_positive: 0, risk_accepted: 0, total: 0 };
    const triaged = findings.filter((f: Finding) =>
      isResolved(f) || f.status === 'triage' || f.status === 'false_positive' || f.status === 'risk_accepted'
    );
    return {
      resolved: triaged.filter(isResolved).length,
      triage: triaged.filter((f: Finding) => f.status === 'triage').length,
      false_positive: triaged.filter((f: Finding) => f.status === 'false_positive').length,
      risk_accepted: triaged.filter((f: Finding) => f.status === 'risk_accepted').length,
      total: triaged.length,
    };
  }, [findings]);

  const activeProducts = useMemo(() => {
    if (!findings || !products) return [];
    const ids = new Set<number>();
    findings.filter((f: Finding) => isResolved(f) || f.status === 'triage' || f.status === 'false_positive' || f.status === 'risk_accepted')
      .forEach((f: Finding) => { if (f.product_id) ids.add(f.product_id); });
    return products.filter((p: Product) => ids.has(p.id));
  }, [findings, products]);

  const sevDot = (sev: string) => {
    switch (sev?.toLowerCase()) {
      case 'critical': return '#ef4444'; case 'high': return '#f97316'; case 'medium': return '#eab308'; default: return '#3f3f46';
    }
  };

  const handleReopen = async (f: Finding) => {
    try {
      await fetch(`/api/findings/${f.id}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ action: 'status', status: 'open' }) });
      window.location.reload();
    } catch { /* ignore */ }
  };

  return (
    <div className="h-full overflow-y-auto" style={{ scrollbarWidth: 'thin', scrollbarColor: 'rgba(255,255,255,0.06) transparent' }}>
      <motion.div 
        variants={containerVariants}
        initial="hidden"
        animate="visible"
        className="max-w-5xl mx-auto px-8 py-8 space-y-6"
      >

        {/* Summary cards */}
        <motion.div variants={itemVariants} className="grid grid-cols-2 md:grid-cols-5 gap-3">
          {[
            { label: t('total_triaged'), value: counts.total, icon: 'task_alt', color: '#a1a1aa' },
            { label: t('status_fixed'), value: counts.resolved, icon: 'check_circle', color: '#22c55e' },
            { label: t('triage'), value: counts.triage, icon: 'psychology', color: '#38bdf8' },
            { label: t('false_positive'), value: counts.false_positive, icon: 'block', color: '#71717a' },
            { label: t('accepted_risk'), value: counts.risk_accepted, icon: 'verified_user', color: '#f59e0b' },
          ].map(c => (
            <div key={c.label} className="border border-[rgba(255,255,255,0.06)] rounded-lg p-4 bg-[rgba(255,255,255,0.01)]">
              <div className="flex items-center gap-2 mb-2">
                <span className="material-symbols-outlined text-[16px]" style={{ color: c.color }}>{c.icon}</span>
                <span className="text-[11px] text-[#52525b] uppercase tracking-wider font-medium">{c.label}</span>
              </div>
              <div className="text-2xl font-bold text-[#f4f4f5] tabular-nums">{c.value}</div>
            </div>
          ))}
        </motion.div>

        {/* Tab filter */}
        <motion.div variants={itemVariants} className="flex items-center gap-2 flex-wrap">
          <button onClick={() => setTab('all')}
            className={`text-[12px] px-3 py-1.5 rounded-md border transition-colors ${tab === 'all' ? 'border-[rgba(255,255,255,0.12)] bg-[rgba(255,255,255,0.05)] text-[#f4f4f5]' : 'border-[rgba(255,255,255,0.06)] text-[#52525b] hover:text-[#a1a1aa]'}`}>
            {t('all')} ({counts.total})
          </button>
          {(Object.keys(statusConfig) as TriageStatus[]).map(s => (
            <button key={s} onClick={() => setTab(s)}
              className={`text-[12px] px-3 py-1.5 rounded-md border transition-colors flex items-center gap-1.5 ${tab === s ? 'border-[rgba(255,255,255,0.12)] bg-[rgba(255,255,255,0.05)] text-[#f4f4f5]' : 'border-[rgba(255,255,255,0.06)] text-[#52525b] hover:text-[#a1a1aa]'}`}>
              <span className="material-symbols-outlined text-[13px]" style={{ color: statusConfig[s].color }}>{statusConfig[s].icon}</span>
              {t(statusConfig[s].labelKey)} ({counts[s]})
            </button>
          ))}

          <div className="flex-1" />

          {activeProducts.length > 0 && (
            <select value={productFilter ?? ''} onChange={e => setProductFilter(e.target.value ? Number(e.target.value) : null)}
              className="bg-transparent border border-[rgba(255,255,255,0.06)] rounded-md px-2.5 py-1.5 text-[12px] text-[#71717a] outline-none hover:border-[rgba(255,255,255,0.1)] cursor-pointer appearance-none pr-6"
              style={{ backgroundImage: `url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 24 24' fill='none' stroke='%2352525b' stroke-width='2'%3E%3Cpath d='m6 9 6 6 6-6'/%3E%3C/svg%3E")`, backgroundRepeat: 'no-repeat', backgroundPosition: 'right 6px center' }}>
              <option value="">{t('all_projects')}</option>
              {activeProducts.map((p: Product) => <option key={p.id} value={p.id}>{p.name}</option>)}
            </select>
          )}
        </motion.div>

        {/* Findings list */}
        {triagedFindings.length === 0 ? (
          <div className="py-16 text-center">
            <span className="material-symbols-outlined text-[48px] text-[#18181b] block mb-3">inbox</span>
            <div className="text-[14px] text-[#3f3f46]">{t('no_triaged_findings')}</div>
            <div className="text-[12px] text-[#27272a] mt-1">{t('mark_findings_desc')}</div>
          </div>
        ) : (
          <motion.div variants={itemVariants} className="border border-[rgba(255,255,255,0.06)] rounded-lg overflow-hidden divide-y divide-[rgba(255,255,255,0.06)] bg-[rgba(255,255,255,0.01)]">
            {triagedFindings.map((f: Finding) => {
              const isExpanded = expandedId === f.id;
              const sc = statusConfig[(isResolved(f) ? 'resolved' : f.status) as TriageStatus];
              return (
                <div key={f.id}>
                  <button onClick={() => setExpandedId(isExpanded ? null : f.id)}
                    className="w-full text-left px-5 py-3 flex items-center gap-3 hover:bg-[rgba(255,255,255,0.02)] transition-colors group">
                    {/* Status badge */}
                    <span className="material-symbols-outlined text-[16px] shrink-0" style={{ color: sc?.color }}>{sc?.icon}</span>

                    {/* Severity dot */}
                    <span className="w-2 h-2 rounded-full shrink-0" style={{ backgroundColor: sevDot(f.severity) }} />

                    {/* Title */}
                    <div className="flex-1 min-w-0">
                      <div className="text-[13px] text-[#a1a1aa] font-medium truncate">{f.title}</div>
                      <div className="flex items-center gap-2 mt-0.5">
                        {f.file_path && <span className="text-[10px] text-[#3f3f46] font-mono truncate max-w-[300px]">{f.file_path}{f.line_number ? `:${f.line_number}` : ''}</span>}
                        {f.product_id && productMap.has(f.product_id) && (
                          <span className="text-[10px] text-[#52525b] border border-[rgba(255,255,255,0.06)] rounded px-1.5 py-0.5">{productMap.get(f.product_id!)?.name}</span>
                        )}
                      </div>
                    </div>

                    {/* Status label */}
                    <span className="text-[10px] px-2 py-0.5 rounded font-medium shrink-0" style={{ color: sc?.color, backgroundColor: sc?.bg }}>{sc ? t(sc.labelKey) : ''}</span>

                    {/* Severity */}
                    <span className="text-[10px] uppercase font-medium shrink-0 px-1.5 py-0.5 rounded" style={{ color: sevDot(f.severity), backgroundColor: `${sevDot(f.severity)}15` }}>{f.severity}</span>

                    <span className={`material-symbols-outlined text-[14px] text-[#3f3f46] transition-transform ${isExpanded ? 'rotate-180' : ''}`}>expand_more</span>
                  </button>

                  <AnimatePresence initial={false}>
                    {isExpanded && (
                      <motion.div
                        key="details"
                        initial={{ height: 0, opacity: 0 }}
                        animate={{ height: "auto", opacity: 1 }}
                        exit={{ height: 0, opacity: 0 }}
                        transition={{ type: "spring", stiffness: 300, damping: 30 }}
                        className="overflow-hidden border-l border-[rgba(255,255,255,0.06)] ml-8"
                      >
                        <div className="px-5 pb-4 pt-1 space-y-3">
                          {f.description && <p className="text-[12px] text-[#71717a] leading-relaxed">{f.description}</p>}
                          {(f.fix_suggestion || f.suggestion) && (
                            <div className="text-[12px] text-[#71717a] leading-relaxed border-l-2 border-[rgba(255,255,255,0.06)] pl-3">
                              <span className="text-[10px] text-[#52525b] uppercase tracking-wider block mb-1">{t('recommendation')}</span>
                              {f.fix_suggestion || f.suggestion}
                            </div>
                          )}
                          <div className="flex items-center gap-2 pt-1">
                            <button onClick={e => { e.stopPropagation(); handleReopen(f); }}
                              className="text-[11px] text-[#f97316] border border-[rgba(249,115,22,0.2)] hover:bg-[rgba(249,115,22,0.08)] px-2.5 py-1 rounded-md flex items-center gap-1 transition-colors">
                              <span className="material-symbols-outlined text-[13px]">undo</span>{t('reopen')}
                            </button>
                            <span className="text-[10px] text-[#27272a]">·</span>
                            <span className="text-[10px] text-[#3f3f46]">
                              {f.stack && `${t('scanner')} ${f.stack}`}
                              {f.updated_at && ` · ${t('triaged_date')} ${new Date(f.updated_at).toLocaleDateString()}`}
                            </span>
                          </div>
                        </div>
                      </motion.div>
                    )}
                  </AnimatePresence>
                </div>
              );
            })}
          </motion.div>
        )}
      </motion.div>
    </div>
  );
};
