import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useFindings } from '../hooks/useFindings';
import { useEngagements } from '../hooks/useEngagements';
import { useTitle } from '../hooks/useTitle';
import { useCopilotStore } from '../store/CopilotStore';
import api from '../services/api';
import type { Product } from '../types';
import { useTranslation } from 'react-i18next';

const PageHeader = ({
  title,
  product,
  setIsOpen,
  setContext,
  navigate,
}: {
  title: string;
  product: Product | null;
  setIsOpen: (o: boolean) => void;
  setContext: (c: string) => void;
  navigate: any;
}) => {
  const { t } = useTranslation('pages');
  return (
    <div className="px-4 py-2 border-b border-outline-variant flex flex-wrap gap-3 justify-between items-center flex-shrink-0">
      <div>
        <p className="text-[9px] font-bold tracking-widest text-on-surface-variant mb-0.5">
          {t('assets.detail.breadcrumb')}
        </p>
        <h1 className="text-title-lg font-bold tracking-tight text-primary uppercase">{title}</h1>
      </div>
      <div className="flex items-center gap-3">
        <button
          onClick={() => {
            if (product) {
              setContext(
                t('assets.detail.copilotContext', {
                  name: product.name,
                  type: product.product_type_id,
                  criticality: product.business_criticality,
                  description: product.description || t('assets.detail.notAvailable'),
                })
              );
              setIsOpen(true);
            }
          }}
          className="flex items-center gap-1.5 text-label-caps text-primary hover:underline mr-4"
        >
          <span className="material-symbols-outlined" style={{ fontSize: '14px' }}>
            smart_toy
          </span>
          {t('ask_copilot')}
        </button>
        <button
          onClick={() => navigate('/products')}
          className="btn-secondary h-8 px-4 flex items-center gap-2"
        >
          <span className="material-symbols-outlined" style={{ fontSize: '14px' }}>
            arrow_back
          </span>
          {t('assets.detail.back')}
        </button>
        <button className="btn-primary h-8 px-4 flex items-center gap-2">
          <span className="material-symbols-outlined" style={{ fontSize: '14px' }}>
            edit
          </span>
          {t('assets.detail.editAsset')}
        </button>
      </div>
    </div>
  );
};

export const ProductDetailPage: React.FC = () => {
  const { t } = useTranslation('pages');
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  useTitle(t('assets.detail.title'));
  const { setIsOpen, setContext } = useCopilotStore();

  const getSeverityLabel = (severity: string) => {
    const s = severity?.toUpperCase();
    if (s === 'CRITICAL') return t('critical');
    if (s === 'HIGH') return t('high');
    if (s === 'MEDIUM') return t('medium');
    if (s === 'LOW') return t('low');
    return severity;
  };

  const [product, setProduct] = useState<Product | null>(null);
  const [productLoading, setProductLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<
    'OVERVIEW' | 'FINDINGS' | 'ENGAGEMENTS' | 'MEMBERS' | 'SETTINGS'
  >('OVERVIEW');

  const { findings } = useFindings(id ? parseInt(id) : undefined);
  const { engagements } = useEngagements(id ? parseInt(id) : undefined);

  useEffect(() => {
    const fetchProduct = async () => {
      try {
        if (id) {
          const { data } = await api.get<Product[]>(`/products`);
          const found = data.find((p: Product) => p.id === parseInt(id));
          setProduct(found || null);
        }
      } catch (_err: unknown) {
        setError(_err instanceof Error ? _err.message : t('assets.detail.errorFetch'));
      } finally {
        setProductLoading(false);
      }
    };
    if (id) {
      fetchProduct();
    }
  }, [id]);

  const tabs = ['OVERVIEW', 'FINDINGS', 'ENGAGEMENTS', 'MEMBERS', 'SETTINGS'] as const;

  if (productLoading) {
    return (
      <div className="flex flex-col h-full overflow-hidden">
        <PageHeader
          title={t('assets.detail.title')}
          product={product}
          setIsOpen={setIsOpen}
          setContext={setContext}
          navigate={navigate}
        />
        <div className="flex-1 flex items-center justify-center">
          <span className="text-label-caps text-on-surface-variant animate-pulse">
            {t('assets.detail.loading')}
          </span>
        </div>
      </div>
    );
  }

  if (error || !product) {
    return (
      <div className="flex flex-col h-full overflow-hidden">
        <PageHeader
          title={t('assets.detail.title')}
          product={product}
          setIsOpen={setIsOpen}
          setContext={setContext}
          navigate={navigate}
        />
        <div className="flex-1 flex items-center justify-center p-8">
          <div className="p-4 border border-error bg-error/5 flex items-center gap-3">
            <div className="w-2 h-2 bg-error shrink-0" />
            <span className="text-label-caps text-error">{error || t('assets.detail.notFound')}</span>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="flex flex-col min-h-full">
      <PageHeader
        title={product.name}
        product={product}
        setIsOpen={setIsOpen}
        setContext={setContext}
        navigate={navigate}
      />

      {/* Tab Bar */}
      <div className="flex overflow-x-auto whitespace-nowrap border-b border-outline-variant shrink-0">
        {tabs.map((tab) => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={`h-10 px-6 text-label-caps transition-none relative ${
              activeTab === tab
                ? 'text-primary border-b-2 border-primary'
                : 'text-on-surface-variant opacity-50 hover:opacity-100'
            }`}
          >
            {t(`assets.detail.tabs.${tab.toLowerCase()}`)}
          </button>
        ))}
      </div>

      <div className="flex-1 overflow-y-auto cyber-scrollbar p-4 md:p-8">
        {activeTab === 'OVERVIEW' && (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
            <div className="lg:col-span-2 min-w-0 overflow-hidden border border-outline-variant p-6 bg-surface-container-lowest relative group">
              <div className="absolute top-0 left-0 w-1 h-1 bg-primary" />
              <div className="absolute top-0 right-0 w-1 h-1 bg-primary" />
              <div className="absolute bottom-0 left-0 w-1 h-1 bg-primary" />
              <div className="absolute bottom-0 right-0 w-1 h-1 bg-primary" />

              <h2 className="text-headline-sm text-on-surface mb-6 uppercase tracking-tight">
                {t('assets.detail.specifications')}
              </h2>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                <div>
                  <h3 className="text-label-xs text-on-surface-variant mb-2 opacity-50">
                    {t('assets.detail.descriptionLabel')}
                  </h3>
                  <p className="text-body-base text-on-surface leading-relaxed">
                    {product.description || t('assets.detail.notAvailable')}
                  </p>
                </div>
                <div className="space-y-6">
                  <div>
                    <h3 className="text-label-xs text-on-surface-variant mb-2 opacity-50">
                      {t('assets.detail.lifecyclePhase')}
                    </h3>
                    <div className="px-2 py-1 bg-surface-container-high border border-outline-variant inline-block text-mono-data text-primary">
                      {product.lifecycle?.toUpperCase() || t('assets.detail.lifecycleDevelopment')}
                    </div>
                  </div>
                  <div>
                    <h3 className="text-label-xs text-on-surface-variant mb-2 opacity-50">
                      {t('assets.detail.origin')}
                    </h3>
                    <p className="text-body-base text-on-surface">{product.origin || t('assets.detail.originInternal')}</p>
                  </div>
                  <div>
                    <h3 className="text-label-xs text-on-surface-variant mb-2 opacity-50">
                      {t('assets.detail.criticality')}
                    </h3>
                    <span
                      className={`text-label-caps font-black ${
                        product.business_criticality === 'CRITICAL'
                          ? 'text-severity-critical'
                          : 'text-primary'
                      }`}
                    >
                      {product.business_criticality?.toUpperCase() || t('assets.detail.criticalityMedium')}
                    </span>
                  </div>
                </div>
              </div>
            </div>

            <div className="min-w-0 overflow-hidden border border-outline-variant p-6 bg-surface-container-lowest relative">
              <h3 className="text-label-xs text-on-surface-variant mb-6 opacity-50">
                {t('assets.detail.slaThresholds')}
              </h3>
              <div className="space-y-4">
                {[
                  { label: t('critical').toUpperCase(), val: product.sla_critical, color: 'text-severity-critical' },
                  { label: t('high').toUpperCase(), val: product.sla_high, color: 'text-severity-high' },
                  { label: t('medium').toUpperCase(), val: product.sla_medium, color: 'text-severity-medium' },
                  { label: t('low').toUpperCase(), val: product.sla_low, color: 'text-severity-low' },
                ].map((sla) => (
                  <div
                    key={sla.label}
                    className="flex justify-between items-center border-b border-outline-variant/20 pb-2 group hover:border-outline-variant transition-none"
                  >
                    <span className={`text-label-caps font-black ${sla.color}`}>{sla.label}</span>
                    <span className="text-mono-data font-bold text-on-surface">{sla.val}</span>
                  </div>
                ))}
              </div>
              <div className="mt-8 pt-4 border-t border-outline-variant/30 break-words italic text-[10px] text-on-surface-variant opacity-40">
                {t('assets.detail.autoEnforced')}
              </div>
            </div>
          </div>
        )}

        {activeTab === 'FINDINGS' && (
          <div className="space-y-6">
            <div className="flex justify-between items-center mb-2">
              <h3 className="text-label-caps text-on-surface-variant tracking-[0.2em]">
                {t('assets.detail.findingsSnapshot')}
              </h3>
            </div>
            <div className="border border-outline-variant bg-surface-container-lowest overflow-hidden">
              <table className="w-full border-collapse text-left">
                <thead className="bg-surface-container border-b border-outline-variant">
                  <tr className="text-label-xs text-on-surface-variant opacity-60">
                    <th className="px-6 py-4 font-normal">{t('assets.detail.findings.findingId')}</th>
                    <th className="px-6 py-4 font-normal">{t('assets.detail.findings.severity')}</th>
                    <th className="px-6 py-4 font-normal">{t('assets.detail.findings.status')}</th>
                    <th className="px-6 py-4 font-normal">{t('assets.detail.findings.location')}</th>
                    <th className="px-6 py-4 font-normal text-right">{t('assets.detail.findings.action')}</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-outline-variant/20">
                  {findings.length === 0 ? (
                    <tr>
                      <td
                        colSpan={5}
                        className="px-6 py-12 text-center text-label-caps opacity-30 italic"
                      >
                        {t('assets.detail.findings.noFindings')}
                      </td>
                    </tr>
                  ) : (
                    findings.map((f, i) => (
                      <tr key={i} className="hover:bg-primary/5 transition-none group">
                        <td className="px-6 py-4">
                          <div className="text-label-caps font-bold text-on-surface">{f.title}</div>
                          <div className="text-[9px] text-on-surface-variant opacity-50 uppercase tracking-tighter">
                            {f.cwe_id || t('assets.detail.findings.cweUnknown')}
                          </div>
                        </td>
                        <td className="px-6 py-4">
                          <span
                            className={`text-label-caps font-black ${
                              f.severity === 'CRITICAL'
                                ? 'text-severity-critical'
                                : f.severity === 'HIGH'
                                  ? 'text-severity-high'
                                  : f.severity === 'MEDIUM'
                                    ? 'text-severity-medium'
                                    : 'text-severity-low'
                            }`}
                          >
                            {getSeverityLabel(f.severity).toUpperCase()}
                          </span>
                        </td>
                        <td className="px-6 py-4">
                          <span className="text-[10px] px-2 py-0.5 border border-outline-variant bg-surface-container-high text-on-surface-variant uppercase font-bold">
                            {f.status || f.audit_status || t('assets.detail.findings.open')}
                          </span>
                        </td>
                        <td className="px-6 py-4 text-mono-data opacity-40 group-hover:opacity-100 transition-none">
                          {f.file_path || f.file}:{f.line_number}
                        </td>
                        <td className="px-6 py-4 text-right">
                          <button className="text-label-xs text-primary underline underline-offset-4 opacity-0 group-hover:opacity-100 transition-none uppercase">
                            {t('assets.detail.findings.view')}
                          </button>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {activeTab === 'ENGAGEMENTS' && (
          <div className="space-y-6">
            <div className="flex justify-between items-center mb-2">
              <h3 className="text-label-caps text-on-surface-variant tracking-[0.2em]">
                {t('assets.detail.engagementLogs')}
              </h3>
              <button className="btn-primary h-8 px-4 text-label-xs flex items-center gap-2">
                <span className="material-symbols-outlined" style={{ fontSize: '14px' }}>
                  add_box
                </span>
                {t('assets.detail.engagements.new')}
              </button>
            </div>
            <div className="grid grid-cols-1 gap-1">
              {engagements.length === 0 ? (
                <div className="p-12 border border-dashed border-outline-variant text-center text-label-caps opacity-30 italic">
                  {t('assets.detail.engagements.empty')}
                </div>
              ) : (
                engagements.map((eng, i) => (
                  <div
                    key={i}
                    className="border border-outline-variant bg-surface-container-low p-5 flex justify-between items-center group hover:bg-surface-container transition-none"
                  >
                    <div className="flex flex-col gap-1">
                      <div className="text-label-caps font-bold text-primary">{eng.name}</div>
                      <div className="text-mono-data opacity-40 uppercase tracking-tighter text-[10px]">
                        ID_{eng.id || 'N/A'} // {eng.start_date} //{' '}
                        {(eng as any).engagement_type || t('assets.detail.engagements.manual')}
                      </div>
                    </div>
                    <div className="flex gap-6 items-center">
                      <div className="flex items-center gap-2">
                        <div
                          className={`w-1.5 h-1.5 ${eng.status === 'completed' ? 'bg-success' : 'bg-severity-high animate-pulse'}`}
                        />
                        <span className="text-label-caps text-[10px] opacity-60 uppercase">
                          {eng.status}
                        </span>
                      </div>
                      <button className="btn-secondary h-8 px-4 text-label-xs opacity-0 group-hover:opacity-100 transition-none">
                        {t('assets.detail.engagements.reportLogs')}
                      </button>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        )}

        {activeTab === 'MEMBERS' && (
          <div className="space-y-6">
            <div className="flex justify-between items-center mb-2">
              <h3 className="text-label-caps text-on-surface-variant tracking-[0.2em]">
                {t('assets.detail.findings.snapshot')}
              </h3>
              <button className="btn-primary h-8 px-4 text-label-xs">{t('assets.detail.members.provision')}</button>
            </div>
            <div className="border border-outline-variant bg-surface-container-lowest overflow-hidden">
              <table className="w-full border-collapse text-left">
                <thead className="bg-surface-container border-b border-outline-variant">
                  <tr className="text-label-xs text-on-surface-variant opacity-60">
                    <th className="px-6 py-4 font-normal">{t('assets.detail.table.entityName')}</th>
                    <th className="px-6 py-4 font-normal">{t('assets.detail.table.designation')}</th>
                    <th className="px-6 py-4 font-normal">{t('assets.detail.table.authLevel')}</th>
                    <th className="px-6 py-4 font-normal text-right">{t('assets.detail.table.action')}</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-outline-variant/20">
                  <tr>
                    <td
                      colSpan={4}
                      className="px-6 py-12 text-center text-label-caps opacity-30 italic"
                    >
                      {t('assets.detail.members.noRules')}
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
            <div className="p-4 border border-dashed border-outline-variant bg-surface-container-lowest/30 flex items-center justify-between">
              <div className="text-[10px] text-on-surface-variant italic opacity-40 uppercase tracking-wider">
                {t('assets.detail.members.heartbeat')}
              </div>
              <div className="flex items-center gap-2">
                <div className="w-1.5 h-1.5 bg-success" />
                <span className="text-[9px] text-success font-bold uppercase">{t('assets.detail.members.policyEnforced')}</span>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'SETTINGS' && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
            <div className="border border-outline-variant bg-surface-container-low p-6 space-y-8 relative">
              <div className="absolute top-0 right-0 p-4 opacity-10">
                <span className="material-symbols-outlined" style={{ fontSize: '48px' }}>
                  settings
                </span>
              </div>
              <h4 className="text-label-caps text-on-surface font-black border-b border-outline-variant pb-2 tracking-widest">
                {t('assets.detail.settings.envConfig')}
              </h4>
              <div className="space-y-6">
                <div className="flex justify-between items-center group">
                  <div className="flex flex-col gap-1">
                    <span className="text-label-xs text-on-surface tracking-widest uppercase">
                      {t('assets.detail.settings.autoScan')}
                    </span>
                    <span className="text-[10px] text-on-surface-variant opacity-40 italic">
                      {t('assets.detail.settings.webhookId')}
                    </span>
                  </div>
                  <button className="px-4 py-2 border-2 border-primary bg-primary text-on-primary text-label-xs font-black">
                    {t('assets.detail.settings.enabled')}
                  </button>
                </div>
                <div className="flex justify-between items-center group opacity-40 hover:opacity-100 transition-none">
                  <div className="flex flex-col gap-1">
                    <span className="text-label-xs text-on-surface tracking-widest uppercase">
                      {t('assets.detail.deepLlmAnalysis')}
                    </span>
                    <span className="text-[10px] text-on-surface-variant opacity-40 italic">
                      {t('assets.detail.modelCloudOrchestrator')}
                    </span>
                  </div>
                  <button className="px-4 py-2 border border-outline-variant text-on-surface-variant text-label-xs hover:border-primary hover:text-primary transition-none">
                    {t('assets.detail.settings.disabled')}
                  </button>
                </div>
              </div>
            </div>
            <div className="border border-severity-critical/20 bg-severity-critical/5 p-6 space-y-6">
              <h4 className="text-label-caps text-severity-critical font-black border-b border-severity-critical/30 pb-2 tracking-widest">
                {t('assets.detail.settings.terminationZone')}
              </h4>
              <div className="space-y-4">
                <p className="text-mono-data text-on-surface-variant leading-relaxed opacity-60">
                  {t('assets.detail.settings.purgeWarning')}
                </p>
                <button className="w-full py-4 border border-severity-critical text-severity-critical bg-transparent text-label-xs font-black hover:bg-severity-critical hover:text-on-error transition-none group overflow-hidden relative">
                  <span className="relative z-10 flex items-center justify-center gap-2">
                    <span className="material-symbols-outlined" style={{ fontSize: '16px' }}>
                      dangerous
                    </span>
                    {t('assets.detail.settings.purgeAction')}
                  </span>
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
