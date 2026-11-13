import React, { useState, useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { useAdmin } from '../../hooks/useAdmin';

// Models offered for the Web engine: the current default model of each
// provider (internal/agent/llm/factory.go). A model saved earlier that is not
// on this list is still shown, so the form always displays the stored value.
const ENGINE_MODELS = [
  { value: 'gemini-3.5-flash-lite', label: 'admin.gemini35FlashLite' },
  { value: 'claude-sonnet-5-5', label: 'admin.claudeSonnet55' },
  { value: 'gpt-6-luna', label: 'admin.gpt6Luna' },
];

export const SystemConfigTab: React.FC = () => {
  const { t } = useTranslation('pages');
  const { config, updateConfig, loading: loadingConfig } = useAdmin();
  const [localConfig, setLocalConfig] = useState<Record<string, string>>({});
  const [saving, setSaving] = useState(false);
  const [lastSaved, setLastSaved] = useState<string | null>(null);
  const [message, setMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  useEffect(() => {
    if (config) {
      setLocalConfig(config);
    }
  }, [config]);

  const handleSave = async () => {
    setSaving(true);
    setMessage(null);
    const result = await updateConfig(localConfig);
    setSaving(false);

    if (result.ok) {
      setLastSaved(new Date().toLocaleTimeString());
      setMessage({ type: 'success', text: t('admin.configurationPersisted') });
    } else {
      setMessage({ type: 'error', text: result.error || t('admin.persistenceFailed') });
    }
  };

  const updateField = (key: string, value: string) => {
    setLocalConfig((prev) => ({ ...prev, [key]: value }));
  };

  if (loadingConfig && Object.keys(localConfig).length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-20 space-y-4">
        <div className="w-12 h-1 bg-outline-variant relative overflow-hidden">
          <div className="absolute top-0 left-0 h-full bg-primary animate-progress" />
        </div>
        <span className="text-[10px] font-black uppercase tracking-[0.2em] opacity-40 italic animate-pulse">
          {t('admin.initConfiguration')}
        </span>
      </div>
    );
  }

  return (
    <div className="space-y-8 animate-in fade-in ">
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-8">
        {/* Engine Parameters */}
        <div className="cyber-panel p-6 space-y-6 relative overflow-hidden bg-surface-container-low">
          <div className="absolute top-0 left-0 w-1 h-full bg-primary/40" />
          <h4 className="text-label-caps text-on-surface-variant tracking-widest border-b border-outline-variant pb-3 italic flex justify-between items-center">
            <span className="flex items-center gap-2">
              <span className="material-symbols-outlined text-[16px] text-primary">
                settings_applications
              </span>
              {t('admin.engineParameters')}
            </span>
            <span className="opacity-20 text-[8px]">{t('admin.cfgPersistent')}</span>
          </h4>
          <div className="space-y-6">
            <div className="flex justify-between items-center group">
              <div className="flex flex-col">
                <span className="text-label-caps text-[10px] text-on-surface tracking-tight">
                  {t('admin.slaCriticalThreshold')}
                </span>
                <span className="text-[8px] opacity-40 uppercase mt-0.5">
                  {t('admin.maxResponseTime')}
                </span>
              </div>
              <div className="relative group">
                <input
                  type="text"
                  value={localConfig.sla_critical || ''}
                  onChange={(e) => updateField('sla_critical', e.target.value)}
                  className="bg-surface-container-lowest border border-outline-variant px-4 py-2 text-mono-data text-primary focus:border-primary outline-none w-28 text-right transition-none group-hover:bg-white/5"
                />
                <div className="absolute bottom-0 right-0 w-1 h-1 bg-primary/40" />
              </div>
            </div>
            <div className="flex justify-between items-center group">
              <div className="flex flex-col">
                <span className="text-label-caps text-[10px] text-on-surface tracking-tight">
                  {t('admin.scanConcurrency')}
                </span>
                <span className="text-[8px] opacity-40 uppercase mt-0.5">
                  {t('admin.parallelExecutionThreads')}
                </span>
              </div>
              <div className="relative group">
                <input
                  type="text"
                  value={localConfig.engine_concurrency || ''}
                  onChange={(e) => updateField('engine_concurrency', e.target.value)}
                  className="bg-surface-container-lowest border border-outline-variant px-4 py-2 text-mono-data text-primary focus:border-primary outline-none w-28 text-right transition-none group-hover:bg-white/5"
                />
                <div className="absolute bottom-0 right-0 w-1 h-1 bg-primary/40" />
              </div>
            </div>
            <div className="flex justify-between items-center group">
              <div className="flex flex-col">
                <span className="text-label-caps text-[10px] text-ai-accent tracking-tight">
                  {t('admin.scanDepth')}
                </span>
                <span className="text-[8px] opacity-40 uppercase mt-0.5">
                  {t('admin.analysisThoroughnessLevel')}
                </span>
              </div>
              <div className="relative group">
                <select
                  value={localConfig.engine_scan_depth || 'thorough'}
                  onChange={(e) => updateField('engine_scan_depth', e.target.value)}
                  className="bg-surface-container-lowest border border-outline-variant px-3 py-2 text-label-caps text-[10px] text-ai-accent outline-none focus:border-ai-accent cursor-pointer transition-none group-hover:bg-white/5 appearance-none min-w-[112px] text-right"
                >
                  <option value="fast">{t('admin.fast')}</option>
                  <option value="thorough">{t('admin.thorough')}</option>
                  <option value="insane">{t('admin.insane')}</option>
                </select>
                <div className="absolute bottom-0 right-0 w-1 h-1 bg-ai-accent/40" />
              </div>
            </div>
          </div>
        </div>

        {/* LLM Gateway */}
        <div className="cyber-panel p-6 space-y-6 relative overflow-hidden bg-surface-container-low">
          <div className="absolute top-0 left-0 w-1 h-full bg-ai-accent/40" />
          <h4 className="text-label-caps text-on-surface-variant tracking-widest border-b border-outline-variant pb-3 italic flex justify-between items-center">
            <span className="flex items-center gap-2">
              <span className="material-symbols-outlined text-[16px] text-ai-accent animate-pulse">
                hub
              </span>
              {t('admin.llmProviderGateway')}
            </span>
            <span className="text-ai-accent text-[8px] tracking-[0.2em]">{t('admin.connected')}</span>
          </h4>
          <div className="space-y-6">
            <div className="flex justify-between items-center group">
              <span className="text-label-caps text-[10px] text-on-surface tracking-tight">
                {t('admin.primaryOrchestrator')}
              </span>
              <div className="relative group">
                <select
                  value={localConfig.engine_llm_model || ''}
                  onChange={(e) => updateField('engine_llm_model', e.target.value)}
                  className="bg-surface-container-lowest border border-outline-variant px-3 py-2 text-label-caps text-[10px] text-primary outline-none focus:border-ai-accent cursor-pointer transition-none group-hover:bg-white/5 appearance-none min-w-[160px] text-right"
                >
                  {ENGINE_MODELS.map((model) => (
                    <option key={model.value} value={model.value}>{t(model.label)}</option>
                  ))}
                  {localConfig.engine_llm_model &&
                    !ENGINE_MODELS.some((model) => model.value === localConfig.engine_llm_model) && (
                      <option value={localConfig.engine_llm_model}>{localConfig.engine_llm_model}</option>
                    )}
                </select>
                <div className="absolute bottom-0 right-0 w-1 h-1 bg-primary/40" />
              </div>
            </div>
            <div className="flex justify-between items-center group">
              <span className="text-label-caps text-[10px] text-on-surface tracking-tight">
                {t('admin.llmProvider')}
              </span>
              <div className="relative group">
                <select
                  value={localConfig.engine_llm_provider || ''}
                  onChange={(e) => updateField('engine_llm_provider', e.target.value)}
                  className="bg-surface-container-lowest border border-outline-variant px-3 py-2 text-label-caps text-[10px] text-on-surface outline-none focus:border-ai-accent cursor-pointer transition-none group-hover:bg-white/5 appearance-none min-w-[160px] text-right"
                >
                  <option value="gemini">{t('admin.googleGemini')}</option>
                  <option value="anthropic">{t('admin.anthropic')}</option>
                  <option value="openai">{t('admin.openai')}</option>
                </select>
                <div className="absolute bottom-0 right-0 w-1 h-1 bg-on-surface/40" />
              </div>
            </div>
            <div className="p-4 bg-ai-accent/5 border border-ai-accent/10 text-[9px] text-ai-accent uppercase leading-relaxed font-mono relative">
              <div className="absolute top-0 left-0 w-full h-[1px] bg-ai-accent/20" />
              {t('admin.privacyGatewayNotice')}
            </div>
          </div>
        </div>
      </div>

      {/* Save Action */}
      <div className="flex items-center justify-between cyber-panel bg-surface-container-lowest p-6 px-8 relative overflow-hidden">
        <div className="absolute top-0 right-0 w-32 h-full bg-primary/5 -skew-x-12 translate-x-16" />
        <div className="flex flex-col relative z-10">
          <span className="text-label-caps text-on-surface-variant tracking-widest">
            {t('admin.configurationStatus')}
          </span>
          {message ? (
            <div className="flex items-center gap-2 mt-1">
              <div
                className={`w-1 h-1 ${message.type === 'success' ? 'bg-success' : 'bg-error'}`}
              />
              <span
                className={`text-[9px] uppercase font-mono ${message.type === 'success' ? 'text-success' : 'text-error'}`}
              >
                {message.text} {lastSaved && `[${t('admin.timestamp')}: ${lastSaved}]`}
              </span>
            </div>
          ) : (
            <span className="text-[9px] uppercase font-mono text-on-surface-variant opacity-40 mt-1">
              {t('admin.noUnsavedChanges')}
            </span>
          )}
        </div>
        <div className="flex items-center gap-6 relative z-10">
          {saving && <div className="w-1.5 h-1.5 bg-primary animate-ping" />}
          <button
            onClick={handleSave}
            disabled={saving || loadingConfig}
            className="btn-primary px-10 py-3 min-w-[180px] flex items-center justify-center gap-3 relative overflow-hidden group"
          >
            <div className="absolute inset-0 bg-white/10 translate-x-[-100%] group-hover:translate-x-[100%] transition-none " />
            <span className="tracking-[0.2em] font-black">
              {saving ? t('admin.persisting') : t('admin.saveConfiguration')}
            </span>
          </button>
        </div>
      </div>
    </div>
  );
};
