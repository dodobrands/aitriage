import React, { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useReports } from '../hooks/useReports';
import { useProducts } from '../hooks/useProducts';
import { useTitle } from '../hooks/useTitle';
import { LoadingScreen } from '../components/common/LoadingScreen';

const FORMATS = [
  { id: 'sarif', name: 'SARIF v2.1.0', tag: 'VULN', icon: 'security' },
  {
    id: 'cyclonedx',
    name: 'CycloneDX 1.5 JSON',
    tag: 'SBOM',
    icon: 'inventory_2',
  },
  { id: 'spdx', name: 'SPDX 2.3', tag: 'SBOM', icon: 'verified_user' },
  {
    id: 'pdf',
    name: 'Executive Summary PDF',
    tag: 'EXEC',
    icon: 'summarize',
  },
];

export const ReportsPage: React.FC = () => {
  const { t } = useTranslation('pages');
  useTitle(t('reports.title'));
  const { products } = useProducts();
  // A report covers one repository unless the user deliberately widens it.
  // `undefined` means "not chosen yet", which is different from an explicit
  // `null` ("all products"), so the default below is derived rather than
  // written into state by an effect.
  const [chosenScope, setChosenScope] = useState<number | null | undefined>(undefined);
  const scopeProductId = chosenScope === undefined ? (products[0]?.id ?? null) : chosenScope;

  const {
    executiveSummary,
    reportHistory,
    loading,
    generating,
    generateError,
    generateSuccess,
    lastDownloadURL,
    downloadCSV,
    generateReport,
    refresh,
  } = useReports(scopeProductId);
  const [selectedFormat, setSelectedFormat] = useState(0);
  const [includeDeps, setIncludeDeps] = useState(true);
  const [signArtifact, setSignArtifact] = useState(false);

  const total = executiveSummary?.total_findings || 0;
  const bySev = executiveSummary?.by_severity || {};
  const sevBars = [
    {
      label: t('reports.severity.critical'),
      value: bySev.CRITICAL ?? bySev.critical ?? 0,
      color: 'bg-severity-critical',
    },
    { label: t('reports.severity.high'), value: bySev.HIGH ?? bySev.high ?? 0, color: 'bg-severity-high' },
    { label: t('reports.severity.medium'), value: bySev.MEDIUM ?? bySev.medium ?? 0, color: 'bg-severity-medium' },
    { label: t('reports.severity.low'), value: bySev.LOW ?? bySev.low ?? 0, color: 'bg-severity-low' },
  ];

  const handleGenerate = () => {
    if (generating) return;
    // Send the machine-readable id, not the display name: the backend selects
    // the renderer by id and cannot parse "SARIF v2.1.0".
    generateReport(FORMATS[selectedFormat].id, { includeDeps, sign: signArtifact });
  };

  return (
    <div className="flex flex-col h-full overflow-hidden bg-transparent">
      {/* Page Header */}
      <div className="cyber-header-premium px-4 py-2 flex justify-between items-center shrink-0 relative z-10 border-b border-outline-variant/30">
        <div className="flex items-center gap-4">
          <div className="hidden md:flex w-8 h-8 border border-outline-variant items-center justify-center bg-surface-container-low">
            <span
              className="material-symbols-outlined text-primary/60"
              style={{ fontSize: '16px' }}
            >
              description
            </span>
          </div>
          <div>
            <div className="flex items-center gap-2 mb-0.5">
              <span className="text-[9px] font-bold tracking-widest text-on-surface-variant opacity-60 uppercase">
                {t('reports.compliance')}
              </span>
              <span className="text-[9px] font-bold tracking-widest text-on-surface-variant opacity-20">
                /
              </span>
              <span className="text-[9px] font-bold tracking-widest text-on-surface-variant opacity-60 uppercase">
                {t('reports.artifactGenerator')}
              </span>
            </div>
            <h1 className="text-title-lg font-bold tracking-tight text-primary uppercase">
              {t('reports.exportArtifacts')}
            </h1>
          </div>
        </div>
        <div className="flex items-center gap-3">
          {/* Report scope. The artifact covers exactly what is selected here,
              and the selection is echoed in the generated document itself. */}
          <label className="flex items-center gap-2">
            <span className="text-[9px] font-bold tracking-widest text-on-surface-variant opacity-60 uppercase hidden sm:inline">
              {t('reports.scope.label')}
            </span>
            <select
              value={scopeProductId === null ? 'all' : String(scopeProductId)}
              onChange={(e) => setChosenScope(e.target.value === 'all' ? null : Number(e.target.value))}
              className="h-8 px-2 bg-surface-container-low border border-outline-variant text-[11px] text-on-surface focus:border-primary outline-none max-w-[240px]"
            >
              {products.map((p) => (
                <option key={p.id} value={String(p.id)}>
                  {p.name}
                </option>
              ))}
              <option value="all">{t('reports.scope.allProducts')}</option>
            </select>
          </label>
          <button
            onClick={refresh}
            className="btn-secondary h-8 px-4 flex items-center gap-2 group relative overflow-hidden"
          >
            <div className="absolute inset-0 bg-primary/5 translate-y-[100%] group-hover:translate-y-0 transition-none" />
            <span className="material-symbols-outlined text-[16px] group-hover:rotate-180 transition-none ">
              refresh
            </span>
            <span className="tracking-[0.15em] text-[9px] font-bold hidden sm:inline">{t('reports.refresh')}</span>
          </button>
          <button
            onClick={downloadCSV}
            className="btn-secondary h-8 px-4 flex items-center gap-3 group relative overflow-hidden"
          >
            <div className="absolute inset-0 bg-primary/5 translate-y-[100%] group-hover:translate-y-0 transition-none" />
            <span className="material-symbols-outlined text-[16px]">download</span>
            <span className="tracking-[0.2em] text-[9px] font-bold">{t('reports.exportCsv')}</span>
          </button>
        </div>
      </div>

      <div className="flex-1 overflow-y-auto cyber-scrollbar bg-transparent">
        {loading ? (
          <LoadingScreen />
        ) : (
          <div className="p-8 grid grid-cols-1 lg:grid-cols-12 gap-8 max-w-[1600px] mx-auto">
            {/* Left: Config Form */}
            <div className="lg:col-span-5 space-y-6">
              {/* ── Severity Density ────────────────────────────────────────── */}
              <div className="cyber-panel overflow-hidden">
                <div className="px-6 py-4 border-b border-outline-variant bg-surface-container/50 flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <div className="w-1 h-4 bg-primary" />
                    <span className="text-label-caps text-primary tracking-widest uppercase">
                      {t('reports.vulnerabilityDensity')}
                    </span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-label-xs text-primary font-bold">{total}</span>
                    <span className="text-label-xs text-on-surface-variant opacity-40">
                      {t('reports.findings')}
                    </span>
                  </div>
                </div>

                <div className="p-6 space-y-4">
                  {sevBars.map((s, i) => {
                    const pct = total > 0 ? (s.value / total) * 100 : 0;
                    return (
                      <div key={i} className="group">
                        <div className="flex justify-between text-label-xs text-on-surface-variant mb-1.5 font-bold tracking-widest opacity-60 group-hover:opacity-100 transition-none">
                          <span>{s.label}</span>
                          <span className="text-primary tabular-nums">{s.value}</span>
                        </div>
                        <div className="h-1 bg-surface-container-high relative overflow-hidden">
                          <div
                            className={`absolute inset-y-0 left-0 ${s.color} transition-none `}
                            style={{ width: `${pct}%` }}
                          />
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* ── Output Format Protocol ──────────────────────────────────── */}
              <div className="cyber-panel overflow-hidden">
                <div className="px-6 py-4 border-b border-outline-variant bg-surface-container/50 flex items-center gap-3">
                  <div className="w-1 h-4 bg-primary" />
                  <span className="text-label-caps text-primary tracking-widest uppercase">
                    {t('reports.outputFormat')}
                  </span>
                </div>

                <div className="p-6 space-y-3">
                  {FORMATS.map((fmt, i) => {
                    const active = selectedFormat === i;
                    return (
                      <button
                        key={i}
                        onClick={() => setSelectedFormat(i)}
                        className={`w-full flex items-center justify-between p-4 border transition-none relative overflow-hidden group ${
                          active
                            ? 'border-primary bg-primary/[0.04]'
                            : 'border-outline-variant/30 hover:border-outline-variant hover:bg-surface-container-high'
                        }`}
                      >
                        <div className="flex items-center gap-4 relative z-10">
                          {/* Radio indicator */}
                          <div
                            className={`w-[18px] h-[18px] border-2 flex items-center justify-center ${
                              active ? 'border-primary' : 'border-outline-variant/50'
                            }`}
                          >
                            {active && <div className="w-2 h-2 bg-primary" />}
                          </div>
                          <div className="text-left">
                            <div
                              className={`text-mono-data font-bold transition-none ${active ? 'text-primary' : 'text-on-surface-variant opacity-60'}`}
                            >
                              {t(`reports.formats.${fmt.id}.name`, fmt.name)}
                            </div>
                            <div className="text-[10px] text-on-surface-variant/40 mt-0.5">
                              {t(`reports.formats.${fmt.id}.desc`)}
                            </div>
                          </div>
                        </div>
                        <span
                          className={`text-label-xs px-2 py-0.5 border relative z-10 ${
                            active
                              ? 'border-primary/40 text-primary'
                              : 'border-outline-variant/20 text-on-surface-variant opacity-40'
                          }`}
                        >
                          {fmt.tag}
                        </span>
                      </button>
                    );
                  })}
                </div>
              </div>

              {/* ── Security Flags ──────────────────────────────────────────── */}
              <div className="cyber-panel overflow-hidden">
                <div className="px-6 py-4 border-b border-outline-variant bg-surface-container/50 flex items-center gap-3">
                  <div className="w-1 h-4 bg-primary" />
                  <span className="text-label-caps text-primary tracking-widest uppercase">
                    {t('reports.securityFlags')}
                  </span>
                </div>

                <div className="p-6 space-y-5">
                  {[
                    {
                      label: t('reports.flags.includeDeps.label'),
                      desc: t('reports.flags.includeDeps.desc'),
                      val: includeDeps,
                      set: setIncludeDeps,
                      icon: 'account_tree',
                    },
                    {
                      label: t('reports.flags.signArtifact.label'),
                      desc: t('reports.flags.signArtifact.desc'),
                      val: signArtifact,
                      set: setSignArtifact,
                      icon: 'verified_user',
                    },
                  ].map((opt, i) => (
                    <div key={i} className="flex items-center justify-between group">
                      <div className="flex items-center gap-3">
                        <span className="material-symbols-outlined text-[18px] text-on-surface-variant opacity-30 group-hover:opacity-60 transition-none">
                          {opt.icon}
                        </span>
                        <div>
                          <div className="text-mono-data text-on-surface-variant opacity-70 group-hover:opacity-100 transition-none">
                            {opt.label}
                          </div>
                          <div className="text-[10px] text-on-surface-variant/30 mt-0.5">
                            {opt.desc}
                          </div>
                        </div>
                      </div>
                      <button
                        onClick={() => opt.set(!opt.val)}
                        className={`w-10 h-5 border relative transition-none ${
                          opt.val
                            ? 'border-primary bg-primary/10'
                            : 'border-outline-variant bg-transparent'
                        }`}
                      >
                        <div
                          className={`absolute top-1 w-2.5 h-2.5 transition-none ${
                            opt.val ? 'left-6 bg-primary' : 'left-1 bg-outline-variant'
                          }`}
                        />
                      </button>
                    </div>
                  ))}
                </div>
              </div>

              {/* ── Generate Button ──────────────────────────────────────────── */}
              <div className="space-y-3">
                {generateError && (
                  <div className="p-3 border border-error bg-error-container/10 flex items-center gap-3">
                    <div className="w-2 h-2 bg-error shrink-0" />
                    <span className="text-label-xs text-error uppercase tracking-widest">
                      {generateError}
                    </span>
                  </div>
                )}
                {generateSuccess && (
                  <div className="p-3 border border-success bg-success/5 flex items-center gap-3">
                    <div className="w-2 h-2 bg-success shrink-0" />
                    <span className="text-label-xs text-success uppercase tracking-widest">
                      {t('reports.successMessage')}
                    </span>
                    {/* Open the artifact straight away: the point of generating
                        a report is to read or send it. */}
                    {lastDownloadURL && (
                      <button
                        onClick={() => window.open(lastDownloadURL, '_blank')}
                        className="ml-auto text-label-xs font-bold uppercase tracking-widest text-success underline decoration-success/40 underline-offset-4"
                      >
                        {t('reports.pull')}
                      </button>
                    )}
                  </div>
                )}
                <button
                  onClick={handleGenerate}
                  disabled={generating || total === 0}
                  className="btn-primary w-full h-14 flex items-center justify-center gap-3 group relative overflow-hidden disabled:opacity-40"
                >
                  <div className="absolute inset-0 bg-white/10 translate-x-[-100%] group-hover:translate-x-[100%] transition-none " />
                  {generating ? (
                    <>
                      <div className="w-4 h-4 border-2 border-on-primary/30 border-t-on-primary animate-spin" />
                      <span className="tracking-[0.3em] font-bold">{t('reports.generating')}</span>
                    </>
                  ) : (
                    <>
                      <span className="material-symbols-outlined text-[20px]">bolt</span>
                      <span className="tracking-[0.3em] font-bold">{t('reports.generateArtifact')}</span>
                    </>
                  )}
                </button>
                {total === 0 && (
                  <p className="text-[10px] text-on-surface-variant/40 text-center tracking-widest">
                    {t('reports.runScanFirst')}
                  </p>
                )}
              </div>
            </div>

            {/* Right: History Table */}
            <div className="lg:col-span-7">
              <div className="cyber-panel flex flex-col h-full overflow-hidden">
                <div className="px-6 py-4 border-b border-outline-variant flex justify-between items-center bg-surface-container/50">
                  <div className="flex items-center gap-3">
                    <div className="w-1 h-4 bg-primary" />
                    <span className="text-label-caps text-primary tracking-widest uppercase">
                      {t('reports.artifactArchive')}
                    </span>
                    {reportHistory.length > 0 && (
                      <span className="text-[10px] text-on-surface-variant/40 ml-1">
                        {t('reports.recordsCount', { count: reportHistory.length })}
                      </span>
                    )}
                  </div>
                  <button
                    onClick={refresh}
                    className="w-8 h-8 flex items-center justify-center border border-outline-variant/30 hover:border-primary transition-none text-on-surface-variant hover:text-primary group"
                  >
                    <span className="material-symbols-outlined text-[18px] group-hover:rotate-180 transition-none ">
                      refresh
                    </span>
                  </button>
                </div>

                <div className="flex flex-col flex-1 min-h-0">
                  {/* Table Header */}
                  <div className="cyber-grid-header flex items-center text-label-xs font-bold text-on-surface-variant/60 shrink-0 uppercase tracking-[0.2em] bg-surface-container/40">
                    <div className="flex-1 py-3 px-6 border-r border-outline-variant/20">
                      {t('reports.table.timestamp')}
                    </div>
                    <div className="w-40 py-3 px-6 border-r border-outline-variant/20 shrink-0">
                      {t('reports.table.scope')}
                    </div>
                    <div className="w-32 py-3 px-6 border-r border-outline-variant/20 shrink-0">
                      {t('reports.table.format')}
                    </div>
                    <div className="w-28 py-3 px-6 border-r border-outline-variant/20 shrink-0">
                      {t('reports.table.status')}
                    </div>
                    <div className="w-24 py-3 px-6 shrink-0 text-right">{t('reports.table.action')}</div>
                  </div>

                  {/* Table Body */}
                  {reportHistory.length > 0 ? (
                    <div className="divide-y divide-outline-variant/20 overflow-y-auto cyber-scrollbar flex-1">
                      {reportHistory.map((row) => (
                        <div
                          key={row.id}
                          className="cyber-grid-row flex items-center group hover:bg-surface-container-high transition-none"
                        >
                          <div className="flex-1 py-3.5 px-6 text-mono-data text-on-surface-variant/80 border-r border-outline-variant/10 group-hover:text-primary transition-none tabular-nums">
                            {(() => {
                              try {
                                return (
                                  new Date(row.timestamp)
                                    .toISOString()
                                    .replace('T', ' ')
                                    .split('.')[0] + 'Z'
                                );
                              } catch {
                                return row.timestamp;
                              }
                            })()}
                          </div>
                          <div className="w-40 py-3.5 px-6 text-mono-data text-primary font-bold truncate shrink-0 border-r border-outline-variant/10">
                            {row.target_scope}
                          </div>
                          <div className="w-32 py-3.5 px-6 text-mono-data text-on-surface-variant/60 shrink-0 border-r border-outline-variant/10">
                            <span className="text-label-xs border border-outline-variant/20 px-2 py-0.5">
                              {row.format}
                            </span>
                          </div>
                          <div className="w-28 py-3.5 px-6 shrink-0 flex items-center gap-2 border-r border-outline-variant/10">
                            <div
                              className={`skeuo-led ${row.status === 'READY' ? 'text-success bg-success' : row.status === 'ERROR' ? 'text-error bg-error animate-pulse' : 'text-ai-accent bg-ai-accent animate-pulse'}`}
                            />
                            <span
                              className={`text-label-xs font-bold ${
                                row.status === 'READY'
                                  ? 'text-success'
                                  : row.status === 'ERROR'
                                    ? 'text-error'
                                    : 'text-tertiary-container'
                              }`}
                            >
                              {row.status}
                            </span>
                          </div>
                          <div className="w-24 py-3.5 px-6 text-right shrink-0">
                            {row.status === 'READY' ? (
                              <button
                                onClick={() => {
                                  if (row.download_url) {
                                    window.open(row.download_url, '_blank');
                                  } else {
                                    downloadCSV();
                                  }
                                }}
                                className="text-label-xs font-bold uppercase tracking-widest text-primary hover:text-primary/80 underline decoration-primary/30 underline-offset-4 transition-none"
                              >
                                {t('reports.pull')}
                              </button>
                            ) : (
                              <span className="text-label-xs text-on-surface-variant/30">—</span>
                            )}
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    /* Empty State */
                    <div className="flex-1 flex flex-col items-center justify-center p-12 text-center">
                      <div className="w-16 h-16 border border-outline-variant/20 flex items-center justify-center mb-6">
                        <span className="material-symbols-outlined text-[32px] text-on-surface-variant/15">
                          inventory_2
                        </span>
                      </div>
                      <h3 className="text-label-caps text-on-surface-variant/30 tracking-[0.3em] mb-2">
                        {t('reports.noArtifacts.title')}
                      </h3>
                      <p className="text-[11px] text-on-surface-variant/20 max-w-[240px]">
                        {t('reports.noArtifacts.desc')}
                      </p>
                    </div>
                  )}

                  {/* Footer Status */}
                  <div className="shrink-0 px-6 py-3 border-t border-outline-variant/10 flex items-center justify-between bg-surface-container/30">
                    <div className="flex items-center gap-2">
                      <span className="material-symbols-outlined text-[14px] text-on-surface-variant/20">
                        policy
                      </span>
                      <span className="text-[10px] text-on-surface-variant/20 tracking-[0.3em]">
                        {t('reports.complianceVault')}
                      </span>
                    </div>
                    <span className="text-[10px] text-on-surface-variant/20 tracking-widest">
                      {reportHistory.length > 0
                        ? t('reports.artifactsStored', { count: reportHistory.length })
                        : t('reports.statusStandby')}
                    </span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
