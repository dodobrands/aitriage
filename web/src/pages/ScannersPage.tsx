import { ModalDialog } from '../ui/ModalDialog';
import React, { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useTitle } from '../hooks/useTitle';
import { securityService } from '../services/securityService';
import { FileBrowser } from '../components/FileBrowser';
import { useCopilotStore } from '../store/CopilotStore';
import api from '../services/api';
import { ProgressRing } from '../ui/ProgressRing';

interface ScannerInfo {
  id: string;
  name: string;
  version: string;
  status: 'ACTIVE' | 'IDLE';
  type: string;
}

export const ScannersPage: React.FC = () => {
  const { t } = useTranslation('pages');
  useTitle(t('scanners.title'));
  const { setIsOpen, setContext } = useCopilotStore();
  const [tools, setTools] = useState<Record<string, boolean>>({});
  const [loading, setLoading] = useState(true);
  const [showBrowser, setShowBrowser] = useState(false);
  const [selectedScanner, setSelectedScanner] = useState<string | null>(null);
  const [scanning, setScanning] = useState(false);
  const [scanError, setScanError] = useState('');
  const [scanResult, setScanResult] = useState('');

  useEffect(() => {
    securityService
      .getHealth()
      .then((res) => setTools(res.tools || {})).catch(() => setScanError(t('review.healthError')))
      .finally(() => setLoading(false));
  }, [t]);

  const [configScanner, setConfigScanner] = useState<ScannerInfo | null>(null);

  const [minSeverity, setMinSeverity] = useState('INFO');
  const [exclusionPatterns, setExclusionPatterns] = useState('');
  const [configLoading, setConfigLoading] = useState(false);
  const [savingConfig, setSavingConfig] = useState(false);
  const [configError, setConfigError] = useState('');
  const [configReady, setConfigReady] = useState(false);
  const [configAttempt, setConfigAttempt] = useState(0);
  useEffect(() => {
    if (!configScanner) return;
    const controller = new AbortController();
    api.get('/scanner-config/core', { signal: controller.signal }).then(({ data }) => {
      setConfigReady(true); setMinSeverity(data.min_severity || 'INFO'); setExclusionPatterns((data.exclude_paths || []).join(', '));
    }).catch(error => { if (!controller.signal.aborted) setConfigError(error.message); }).finally(() => { if (!controller.signal.aborted) setConfigLoading(false); });
    const closeOnEscape = (event: KeyboardEvent) => { if (event.key === 'Escape') setConfigScanner(null); };
    window.addEventListener('keydown', closeOnEscape);
    return () => { controller.abort(); window.removeEventListener('keydown', closeOnEscape); };
  }, [configScanner, configAttempt]);
  const saveScannerConfig = async () => {
    setSavingConfig(true); setConfigError('');
    try {
      await api.put('/scanner-config/core', { min_severity: minSeverity, exclude_paths: exclusionPatterns.split(',').map(p => p.trim()).filter(Boolean) });
      setConfigScanner(null);
    } catch (error) { setConfigError(error instanceof Error ? error.message : 'Failed to save'); }
    finally { setSavingConfig(false); }
  };

  const handleRunNow = (scannerId: string) => {
    setSelectedScanner(scannerId);
    setShowBrowser(true);
  };

  const handleStartScan = async (path: string) => {
    setShowBrowser(false);
    setScanning(true); setScanError(''); setScanResult('');
    try {
      const { data } = await api.post('/scan', { path, external: ['semgrep', 'trivy', 'bandit', 'gitleaks'].includes(selectedScanner || '') });
      if (!data.ok) throw new Error(data.error || t('review.actionFailed'));
      setScanResult(t('review.scanDone', { count: data.findings?.length || 0 }));
    } catch (err) {
      setScanError(err instanceof Error ? err.message : t('review.actionFailed'));
    } finally {
      setScanning(false);
      setSelectedScanner(null);
    }
  };

  const scanners: ScannerInfo[] = [
    {
      id: 'core',
      name: 'AITriage Core Engine',
      version: 'Built-in',
      status: 'ACTIVE',
      type: t('scanners.types.coreEngine', 'SAST • 50+ Rules'),
    },
    {
      id: 'semgrep',
      name: 'Semgrep SAST',
      version: 'N/A',
      status: tools['semgrep'] ? 'ACTIVE' : 'IDLE',
      type: t('scanners.types.codeAnalysis'),
    },
    {
      id: 'trivy',
      name: 'Trivy Container Security',
      version: 'N/A',
      status: tools['trivy'] ? 'ACTIVE' : 'IDLE',
      type: t('scanners.types.dependenciesImages'),
    },
    {
      id: 'gitleaks',
      name: 'Gitleaks Secret Scanner',
      version: 'N/A',
      status: tools['gitleaks'] ? 'ACTIVE' : 'IDLE',
      type: t('scanners.types.secrets'),
    },
    {
      id: 'bandit',
      name: 'Bandit Python Scanner',
      version: 'N/A',
      status: tools['bandit'] ? 'ACTIVE' : 'IDLE',
      type: t('scanners.types.codeAnalysisPython'),
    },
    {
      id: 'nfr',
      name: 'NFR Checks',
      version: 'Built-in',
      status: 'ACTIVE',
      type: t('scanners.types.nfr', 'Non-Functional Requirements'),
    },
    {
      id: 'deploy',
      name: 'Deploy / IaC Audit',
      version: 'Built-in',
      status: 'ACTIVE',
      type: t('scanners.types.deploy', 'Dockerfile • K8s • Compose'),
    },
    {
      id: 'network',
      name: 'Network Probe',
      version: 'Built-in',
      status: 'ACTIVE',
      type: t('scanners.types.network', 'Port Scan • Service Discovery'),
    },
    {
      id: 'git-history',
      name: 'Git History Entropy',
      version: 'Built-in',
      status: 'ACTIVE',
      type: t('scanners.types.gitHistory', 'Leaked Secrets in Commits'),
    },
  ];

  return (
    <div className="flex flex-col h-full overflow-hidden relative">
      {scanError && <p role="alert" className="review-error">{scanError}</p>}
      {scanResult && <p role="status" className="p-4 text-on-surface">{scanResult}</p>}
      {showBrowser && (
        <FileBrowser onSelect={handleStartScan} onCancel={() => setShowBrowser(false)} />
      )}

      {configScanner && (
        <ModalDialog onClose={() => setConfigScanner(null)} label={t('scanners.engineConfig')} className="scanner-dialog">
          <div className="cyber-modal w-full">
            <div className="px-6 py-4 border-b border-white/10 flex justify-between items-center bg-white/5">
              <div className="flex flex-col">
                <span className="text-label-caps text-on-surface-variant mb-1 opacity-70">
                  {t('scanners.engineConfig')}
                </span>
                <h3 className="text-headline-sm text-primary">
                  {configScanner.name.toUpperCase()}
                </h3>
              </div>
              <button
                onClick={() => setConfigScanner(null)}
                aria-label={t('scanners.cancel')}
                className="text-on-surface-variant hover:text-white transition-none"
              >
                <span className="material-symbols-outlined">close</span>
              </button>
            </div>
            <div className="p-8 space-y-6">
              <div className="space-y-4">
                <div className="flex flex-col gap-2">
                  <label className="text-label-caps text-on-surface-variant">
                    {t('scanners.minSeverityLevel')}
                  </label>
                  <select aria-label={t('scanners.minSeverityLevel')} disabled={configLoading} value={minSeverity} onChange={e => setMinSeverity(e.target.value)} className="cyber-input w-full p-2 text-mono-data uppercase">
                    <option>INFO</option>
                    <option value="LOW">LOW</option>
                    <option>MEDIUM</option>
                    <option>HIGH</option>
                    <option>CRITICAL</option>
                  </select>
                </div>
                <div className="flex flex-col gap-2">
                  <label className="text-label-caps text-on-surface-variant">
                    {t('scanners.exclusionPatterns')}
                  </label>
                  <textarea
                    className="cyber-input w-full p-2 text-mono-data h-20 resize-none"
                    placeholder="**/vendor/*, **/tests/*, *.md"
                    disabled={configLoading} aria-label={t('scanners.exclusionPatterns')} value={exclusionPatterns} onChange={e => setExclusionPatterns(e.target.value)}
                  />
                  <span className="text-label-caps text-on-surface-variant opacity-40 lowercase">
                    {t('scanners.exclusionDesc')}
                  </span>
                </div>
                <p className="text-xs text-on-surface-variant">{t('scanners.incrementalCli')}</p>
              </div>

              {configError && <p role="alert" className="text-error">{configError}</p>}
              {!configReady && !configLoading && <button type="button" onClick={() => { setConfigLoading(true); setConfigError(''); setConfigAttempt(value => value + 1); }}>{t('review.retry')}</button>}
              <div className="pt-4 flex gap-4">
                <button
                  onClick={saveScannerConfig}
                  disabled={savingConfig || configLoading || !configReady}
                  className="btn-primary flex-1 py-3 text-label-caps"
                >
                  {t('scanners.saveParameters')}
                </button>
                <button
                  onClick={() => setConfigScanner(null)}
                  className="btn-secondary flex-1 py-3 text-label-caps"
                >
                  {t('scanners.cancel')}
                </button>
              </div>
            </div>
          </div>
        </ModalDialog>
      )}

      {scanning && (
        <div className="fixed inset-0 z-[60] flex items-center justify-center bg-black/95 backdrop-blur-sm animate-modal-enter">
          <div className="flex flex-col items-center gap-6">
            <ProgressRing size={80} strokeWidth={3} indeterminate />
            <span className="text-[12px] font-semibold text-primary tracking-[0.2em] uppercase font-mono animate-pulse">
              {t('review.scanRunning')}
            </span>
          </div>
        </div>
      )}

      {/* Page Header */}
      <div className="px-4 py-2 border-b border-outline-variant flex justify-between items-center flex-shrink-0 bg-surface-container-lowest/30">
        <div>
          <p className="text-[9px] font-bold tracking-widest text-on-surface-variant mb-0.5">
            {t('scanners.breadcrumb')}
          </p>
          <h1 className="text-title-lg font-bold tracking-tight text-primary uppercase">
            {t('scanners.header')}
          </h1>
        </div>
        <div className="flex items-center gap-3">
          {loading && <div className="w-4 h-4 bg-primary animate-pulse" />}
          <button
            onClick={() => {
              setContext(
                `Current Security Engines Status:\n${scanners.map((s) => `- ${s.name} (${s.type}): ${s.status}`).join('\n')}\n\nPlease explain how these engines work together and suggest the best configuration for a production environment.`,
              );
              setIsOpen(true);
            }}
            className="flex items-center gap-1.5 text-label-caps text-primary hover:underline"
          >
            <span className="material-symbols-outlined" style={{ fontSize: '14px' }}>
              smart_toy
            </span>
            {t('scanners.askAiCopilot')}
          </button>

          <button
            className="btn-primary h-8 px-4 flex items-center gap-2 text-label-caps"
            onClick={() => handleRunNow('')} // Empty string for full scan
          >
            <span className="material-symbols-outlined" style={{ fontSize: '14px' }}>
              security
            </span>
            {t('scanners.fullAudit')}
          </button>

          <button
            className="btn-secondary h-8 px-4 flex items-center gap-2 text-label-caps"
            onClick={() => {
              setLoading(true);
              securityService
                .getHealth()
                .then((res) => setTools(res.tools || {})).catch(() => setScanError(t('review.healthError')))
                .finally(() => setLoading(false));
            }}
          >
            <span className="material-symbols-outlined" style={{ fontSize: '14px' }}>
              refresh
            </span>
            {t('scanners.refresh')}
          </button>
        </div>
      </div>

      <div className="flex-1 overflow-y-auto cyber-scrollbar p-8">
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
          {scanners.map((scanner) => (
            <div
              key={scanner.id}
              className="cyber-panel flex flex-col group hover:border-primary/50 transition-none "
            >
              <div className="p-4 border-b border-outline-variant flex justify-between items-start bg-surface-container-high">
                <div className="flex-1 min-w-0 pr-3">
                  <h3 className="text-mono-data text-primary font-bold truncate">{scanner.name}</h3>
                  <div className="text-label-caps text-on-surface-variant opacity-70 mt-1">
                    {scanner.type}
                  </div>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  <div
                    className={`skeuo-led ${scanner.status === 'ACTIVE' ? 'text-success bg-success' : 'text-on-surface-variant/40 bg-on-surface-variant/40'}`}
                  />
                  <span
                    className="text-label-caps"
                    style={{
                      color:
                        scanner.status === 'ACTIVE'
                          ? 'var(--color-success)'
                          : 'var(--color-on-surface-variant)',
                    }}
                  >
                    {t('scanners.states.' + scanner.status.toLowerCase())}
                  </span>
                </div>
              </div>
              <div className="p-4 flex-1 flex flex-col justify-between">
                <div className="flex flex-col gap-2 mb-5">
                  {[
                    { label: t('scanners.version'), value: scanner.version },
                    { label: t('scanners.lastUpdate'), value: 'Live' },
                    { label: t('scanners.execMode'), value: 'Pre-commit, CI/CD' },
                  ].map((row) => (
                    <div key={row.label} className="flex justify-between items-center">
                      <span className="text-label-caps text-on-surface-variant opacity-70">
                        {row.label}
                      </span>
                      <span className="text-mono-data text-on-surface">{row.value === 'Live' ? t('scanners.valLive') : (row.value === 'Pre-commit, CI/CD' ? t('scanners.valExecMode') : row.value)}</span>
                    </div>
                  ))}
                </div>
                <div className="flex gap-2">
                  <button
                    className="btn-secondary flex-1 py-1.5 text-label-caps"
                    disabled={scanner.id !== 'core'}
                    title={scanner.id !== 'core' ? t('scanners.externalConfig') : undefined}
                    onClick={() => { setConfigReady(false); setConfigLoading(true); setConfigError(''); setConfigScanner(scanner); }}
                  >
                    {t('scanners.configure')}
                  </button>
                  <button
                    className="btn-primary flex-1 py-1.5 text-label-caps"
                    disabled={scanner.status !== 'ACTIVE' || scanner.id === 'network'} title={scanner.id === 'network' ? t('review.networkScope') : t('review.scanScope')}
                    onClick={() => handleRunNow(scanner.id)}
                  >
                    {t('review.startScan')}
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
