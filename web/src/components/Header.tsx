import React from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { ModalDialog } from '../ui/ModalDialog';
import { useCopilotStore } from '../store/CopilotStore';
import { useViewModeStore } from '../store/ViewModeStore';
import { motion, AnimatePresence, useReducedMotion } from 'framer-motion';
import { useTranslation } from 'react-i18next';
import api from '../services/api';

const PALETTES = [
  { id: 'violet', name: 'Obsidian Violet', hex: '#8b5cf6' },
  { id: 'cyan', name: 'Aurora Cyan', hex: '#06b6d4' },
  { id: 'emerald', name: 'Emerald Secure', hex: '#10b981' },
  { id: 'amber', name: 'Magma Orange', hex: '#f97316' },
  { id: 'rose', name: 'Sakura Pink', hex: '#f472b6' },
  { id: 'crimson', name: 'Bordeaux Red', hex: '#e11d48' },
  { id: 'cobalt', name: 'Royal Cobalt', hex: '#2563eb' },
  { id: 'bronze', name: 'Imperial Gold', hex: '#eab308' },
  { id: 'teal', name: 'Acid Lime', hex: '#84cc16' },
  { id: 'white', name: 'Quartz White', hex: '#f8fafc' },
];

const BACKGROUND_PALETTES = [
  { id: 'obsidian', name: 'Obsidian Black', hex: '#050506', surface: '#1a1a1e', glow: '#52525b' },
  { id: 'graphite', name: 'Arctic Steel', hex: '#0b111c', surface: '#1e293b', glow: '#38bdf8' },
  { id: 'midnight', name: 'Cobalt Abyss', hex: '#020b1f', surface: '#0b2454', glow: '#0ea5e9' },
  { id: 'bordeaux', name: 'Crimson Reactor', hex: '#18030b', surface: '#3a0d1e', glow: '#f43f5e' },
  { id: 'evergreen', name: 'Emerald Matrix', hex: '#02120d', surface: '#0a3525', glow: '#34d399' },
  { id: 'indigo', name: 'Ultraviolet Core', hex: '#0b0520', surface: '#241454', glow: '#a855f7' },
];

export const Header: React.FC = () => {
  const reduceMotion = useReducedMotion();
  const [scrolled, setScrolled] = React.useState(false);
  const [showSettings, setShowSettings] = React.useState(false);
  const [settingsTab, setSettingsTab] = React.useState('theme');
  const navigate = useNavigate();
  const [search, setSearch] = React.useState('');
  const { t, i18n } = useTranslation();
  
  const { mode, toggleMode } = useViewModeStore();
  const isCopilotOpen = useCopilotStore((state) => state.isOpen);
  const [accent, setAccent] = React.useState(() => {
    try {
      return localStorage.getItem('aitriage_accent') || 'white';
    } catch {
      return 'white';
    }
  });
  const [background, setBackground] = React.useState(() => {
    try {
      return localStorage.getItem('aitriage_background') || 'obsidian';
    } catch {
      return 'obsidian';
    }
  });
  const [backgroundMotion, setBackgroundMotion] = React.useState(() => {
    try {
      return localStorage.getItem('aitriage_background_motion') !== 'off';
    } catch {
      return true;
    }
  });

  React.useEffect(() => {
    try {
      localStorage.setItem('aitriage_accent', accent);
    } catch { /* Storage is optional. */ }
    document.documentElement.setAttribute('data-accent', accent);
  }, [accent]);

  React.useEffect(() => {
    try {
      localStorage.setItem('aitriage_background', background);
    } catch { /* Storage is optional. */ }
    document.documentElement.setAttribute('data-bg', background);
  }, [background]);

  React.useEffect(() => {
    const motionValue = backgroundMotion ? 'on' : 'off';
    try {
      localStorage.setItem('aitriage_background_motion', motionValue);
    } catch { /* Storage is optional. */ }
    document.documentElement.setAttribute('data-bg-motion', motionValue);
  }, [backgroundMotion]);

  React.useEffect(() => {
    const handleAccentChange = () => {
      try {
        setAccent(localStorage.getItem('aitriage_accent') || 'white');
      } catch { /* Storage is optional. */ }
    };
    window.addEventListener('aitriage_accent_change', handleAccentChange);
    return () => window.removeEventListener('aitriage_accent_change', handleAccentChange);
  }, []);

  React.useEffect(() => {
    const handleBackgroundChange = () => {
      try {
        setBackground(localStorage.getItem('aitriage_background') || 'obsidian');
      } catch { /* Storage is optional. */ }
    };
    window.addEventListener('aitriage_background_change', handleBackgroundChange);
    return () => window.removeEventListener('aitriage_background_change', handleBackgroundChange);
  }, []);

  React.useEffect(() => {
    const handleScroll = () => setScrolled(window.scrollY > 16);
    window.addEventListener('scroll', handleScroll);
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  return (
    <header
      className={`sticky top-0 z-50 transition-all duration-400 ease-out border-b ${
        scrolled 
          ? 'luxury-glass border-outline shadow-md' 
          : 'bg-background/40 border-transparent'
      }`}
    >
      <div className="flex justify-between w-full h-14 items-center px-3 sm:px-6">
        {/* Left Section: Logo & Search */}
        <div className="flex items-center gap-3 min-w-0">
          <Link to="/" className="flex items-center gap-3 text-on-background no-underline group">
            <div 
              className="w-7 h-7 rounded-md bg-primary text-on-primary grid place-items-center font-display font-bold text-sm tracking-tight transition-all duration-300"
              style={{ boxShadow: '0 0 12px var(--accent-color-line)' }}
            >
              AI
            </div>
            <div className="flex flex-col leading-[1.1]">
              <span className="text-sm font-sans font-semibold tracking-wide text-on-background">
                AITriage
              </span>
              <span className="text-label-caps text-on-surface-variant">
                {t('components.security_platform')}
              </span>
            </div>
          </Link>

          {mode === 'advanced' && (
            <form onSubmit={event => { event.preventDefault(); navigate(`/findings?q=${encodeURIComponent(search.trim())}`); }} role="search" className="hidden lg:flex items-center bg-surface border border-outline rounded-md h-8 px-3 w-64 ml-4 transition-all duration-300 ease-out focus-within:border-primary focus-within:shadow-[0_0_0_1px_rgba(139,92,246,0.2)]">
              <span aria-hidden="true" className="material-symbols-outlined text-on-surface-variant mr-2 text-[16px]">search</span>
              <input
                className="bg-transparent border-none focus:ring-0 focus:outline-none text-xs text-on-surface placeholder:text-on-surface-variant w-full h-full p-0 font-mono"
                placeholder={t('components.search')}
                type="search" value={search} onChange={event => setSearch(event.target.value)} aria-label={t('components.search')}
              />
            </form>
          )}
        </div>

        {/* Right Section: Status, Notifications, Copilot, Mode Toggle */}
        <div className="flex items-center gap-2 sm:gap-4 shrink-0">
          <button
            onClick={() => {
              document.body.classList.add('lang-changing');
              setTimeout(() => {
                i18n.changeLanguage(i18n.language.startsWith('ru') ? 'en' : 'ru');
                setTimeout(() => {
                  document.body.classList.remove('lang-changing');
                }, 80);
              }, 220);
            }}
            className="flex items-center justify-center w-8 h-8 rounded-md bg-surface text-on-surface border border-outline hover:border-outline-variant hover:bg-surface-bright transition-all duration-300 hover:-translate-y-[1px] relative overflow-hidden"
            title={t('components.switch_language')} aria-label={t('components.switch_language')}
          >
            <AnimatePresence mode="wait" initial={false}>
              <motion.span
                key={i18n.language}
                initial={{ y: 8, opacity: 0 }}
                animate={{ y: 0, opacity: 1 }}
                exit={{ y: -8, opacity: 0 }}
                transition={{ duration: reduceMotion ? 0 : 0.25, ease: [0.16, 1, 0.3, 1] }}
                className="text-[12px] font-bold uppercase font-sans tracking-wider absolute"
              >
                {i18n.language.startsWith('ru') ? 'RU' : 'EN'}
              </motion.span>
            </AnimatePresence>
          </button>

          <button
            onClick={() => setShowSettings(true)}
            className="flex items-center justify-center w-8 h-8 rounded-md bg-surface text-on-surface border border-outline hover:border-outline-variant hover:bg-surface-bright transition-all duration-300 hover:-translate-y-[1px]"
            title={t('components.theme_settings')} aria-label={t('components.theme_settings')}
          >
            <span aria-hidden="true" className="material-symbols-outlined text-[18px]">settings</span>
          </button>

          {mode === 'advanced' && (
            <button
              onClick={() => useCopilotStore.getState().toggle()}
              className={`flex items-center gap-2 px-3 py-1.5 rounded-md text-[11px] font-semibold uppercase tracking-wider transition-all duration-300 ease-out hover:-translate-y-[1px] ${
                isCopilotOpen
                  ? 'bg-primary text-on-primary'
                  : 'bg-surface text-on-surface border border-outline hover:border-outline-variant hover:bg-surface-bright'
              }`}
              style={isCopilotOpen ? { boxShadow: '0 0 12px var(--accent-color-line)' } : undefined}
            >
              <span aria-hidden="true" className="material-symbols-outlined text-[16px]">smart_toy</span>
              <span className="hidden xl:inline">{t('components.copilot')}</span>
            </button>
          )}

          <button
            onClick={toggleMode}
            className={`flex items-center gap-2 px-3 py-1.5 rounded-md text-[11px] font-semibold uppercase tracking-wider transition-all duration-300 ease-out hover:-translate-y-[1px] bg-surface text-on-surface border border-outline hover:border-outline-variant hover:bg-surface-bright`}
            title={mode === 'simple' ? t('components.switch_advanced') : t('components.switch_simple')}
          >
            <span aria-hidden="true" className="material-symbols-outlined text-[16px]">
              {mode === 'simple' ? 'dashboard_customize' : 'web_asset'}
            </span>
            <span className="hidden sm:inline">{mode === 'simple' ? t('components.advanced') : t('components.simple')}</span>
          </button>
        </div>
      </div>

      <AnimatePresence>
        {showSettings && (
          <ModalDialog onClose={() => setShowSettings(false)} label={t('components.system_settings')} className="settings-dialog">
            <div className="flex flex-col min-h-0 h-full">
              {/* Subtle top glow */}
              <div className="absolute top-0 left-1/4 right-1/4 h-[1px] bg-gradient-to-r from-transparent via-[var(--accent-color-line)] to-transparent" />
              
              <div className="px-4 sm:px-8 py-4 flex justify-between items-center relative z-10">
                <h2 className="text-[12px] uppercase tracking-[0.2em] text-[#f4f4f5] flex items-center gap-3 font-semibold">
                  <span aria-hidden="true" className="material-symbols-outlined text-[18px] text-[var(--accent-color)]">settings</span>
                  {t('components.system_settings')}
                </h2>
                <button
                  onClick={() => setShowSettings(false)}
                  aria-label={t('components.close', 'Close')}
                  className="w-11 h-8 rounded-full flex items-center justify-center text-[#71717a] hover:text-[#f4f4f5] hover:bg-[rgba(255,255,255,0.05)] transition-all duration-300"
                >
                  <span aria-hidden="true" className="material-symbols-outlined text-[20px]">close</span>
                </button>
              </div>
              
              <div className="settings-dialog__body flex flex-1 min-h-0 overflow-hidden border-t border-[rgba(255,255,255,0.04)] relative z-10">
                <div className="settings-dialog__tabs w-44 shrink-0 border-r border-[rgba(255,255,255,0.04)] bg-[rgba(0,0,0,0.2)] p-6 flex flex-col gap-3">
                  <button
                    onClick={() => setSettingsTab('theme')}
                    className={`text-left px-4 py-2.5 rounded-lg text-[11px] font-bold tracking-widest uppercase transition-all duration-300 ${
                      settingsTab === 'theme' ? 'bg-[var(--accent-color-soft)] text-[var(--accent-color)] border border-[var(--accent-color-line)] shadow-[inset_2px_0_0_0_var(--accent-color)]' : 'text-[#71717a] hover:text-[#f4f4f5] hover:bg-[rgba(255,255,255,0.03)] border border-transparent'
                    }`}
                  >
                    {t('components.theme')}
                  </button>
                  <button
                    onClick={() => setSettingsTab('database')}
                    className={`text-left px-4 py-2.5 rounded-lg text-[11px] font-bold tracking-widest uppercase transition-all duration-300 ${
                      settingsTab === 'database' ? 'bg-[var(--accent-color-soft)] text-[var(--accent-color)] border border-[var(--accent-color-line)] shadow-[inset_2px_0_0_0_var(--accent-color)]' : 'text-[#71717a] hover:text-[#f4f4f5] hover:bg-[rgba(255,255,255,0.03)] border border-transparent'
                    }`}
                  >
                    {t('components.database')}
                  </button>

                </div>

                <div className="settings-dialog__content flex-1 min-w-0 p-4 sm:p-6 overflow-y-auto cyber-scrollbar">
                  <AnimatePresence mode="wait">
                    {settingsTab === 'theme' && (
                      <motion.div
                        key="theme"
                        initial={{ opacity: 0, y: 10 }}
                        animate={{ opacity: 1, y: 0 }}
                        exit={{ opacity: 0, y: -10 }}
                        transition={{ duration: reduceMotion ? 0 : 0.2 }}
                        className="space-y-6"
                      >
                        <section className="space-y-4">
                          <label className="text-[10px] text-[#71717a] tracking-[0.2em] font-semibold uppercase">{t('components.select_accent_palette')}</label>
                          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                            {PALETTES.map((p) => {
                              const isActive = accent === p.id;
                              return (
                                <button
                                  key={p.id}
                                  onClick={() => {
                                    setAccent(p.id);
                                    try {
                                      localStorage.setItem('aitriage_accent', p.id);
                                    } catch { /* Storage is optional. */ }
                                    document.documentElement.setAttribute('data-accent', p.id);
                                    window.dispatchEvent(new Event('aitriage_accent_change'));
                                  }}
                                  className={`group flex items-center gap-4 p-4 rounded-xl transition-all duration-300 text-left relative overflow-hidden ${
                                    isActive
                                      ? 'bg-[rgba(255,255,255,0.03)] border border-[var(--accent-color-line)] shadow-[0_0_20px_var(--accent-color-soft)]'
                                      : 'bg-[rgba(255,255,255,0.01)] border border-[rgba(255,255,255,0.04)] hover:bg-[rgba(255,255,255,0.03)] hover:border-[rgba(255,255,255,0.1)]'
                                  }`}
                                >
                                  {isActive && <div className="absolute inset-0 bg-gradient-to-r from-[var(--accent-color-soft)] to-transparent opacity-50" />}
                                  <span
                                    className="w-4 h-4 rounded-full shrink-0 relative z-10 shadow-lg"
                                    style={{ backgroundColor: p.hex, boxShadow: isActive ? `0 0 12px ${p.hex}` : 'none' }}
                                  />
                                  <span className={`text-[11px] font-mono tracking-widest truncate relative z-10 transition-colors ${isActive ? 'text-[#f4f4f5] font-bold' : 'text-[#a1a1aa] group-hover:text-[#f4f4f5]'}`}>
                                    {p.name.toUpperCase()}
                                  </span>
                                </button>
                              );
                            })}
                          </div>
                        </section>

                        <section className="space-y-4">
                          <label className="text-[10px] text-[#71717a] tracking-[0.2em] font-semibold uppercase">{t('components.select_background_palette')}</label>
                          <div className="flex items-center justify-between p-4 rounded-xl border border-[rgba(255,255,255,0.06)] bg-[rgba(255,255,255,0.015)]">
                            <div className="flex items-center gap-3">
                              <span aria-hidden="true" className="material-symbols-outlined text-[17px] text-[var(--accent-color)]">animation</span>
                              <span className="text-[11px] font-mono tracking-widest text-[#f4f4f5] uppercase">{t('components.background_animation')}</span>
                            </div>
                            <button
                              type="button"
                              onClick={() => setBackgroundMotion((value) => !value)}
                              className={`relative h-7 w-12 rounded-full border transition-all duration-300 ${
                                backgroundMotion
                                  ? 'bg-[var(--accent-color)] border-[var(--accent-color-line)]'
                                  : 'bg-[rgba(255,255,255,0.08)] border-[rgba(255,255,255,0.08)]'
                              }`}
                              aria-pressed={backgroundMotion}
                              title={t('components.background_animation')}
                            >
                              <span
                                className={`absolute top-1 h-5 w-5 rounded-full bg-[#f4f4f5] transition-all duration-300 ${
                                  backgroundMotion ? 'left-6' : 'left-1'
                                }`}
                              />
                            </button>
                          </div>
                          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                            {BACKGROUND_PALETTES.map((p) => {
                              const isActive = background === p.id;
                              return (
                                <button
                                  key={p.id}
                                  onClick={() => {
                                    setBackground(p.id);
                                    try {
                                      localStorage.setItem('aitriage_background', p.id);
                                    } catch { /* Storage is optional. */ }
                                    document.documentElement.setAttribute('data-bg', p.id);
                                    window.dispatchEvent(new Event('aitriage_background_change'));
                                  }}
                                  className={`group flex items-center gap-4 p-3 rounded-xl transition-all duration-300 text-left relative overflow-hidden min-h-[76px] ${
                                    isActive
                                      ? 'bg-[rgba(255,255,255,0.03)] border border-[var(--accent-color-line)] shadow-[0_0_20px_var(--accent-color-soft)]'
                                      : 'bg-[rgba(255,255,255,0.01)] border border-[rgba(255,255,255,0.04)] hover:bg-[rgba(255,255,255,0.03)] hover:border-[rgba(255,255,255,0.1)]'
                                  }`}
                                >
                                  {isActive && <div className="absolute inset-0 bg-gradient-to-r from-[var(--accent-color-soft)] to-transparent opacity-50" />}
                                  <span
                                    className="h-11 w-16 rounded-lg shrink-0 relative z-10 shadow-lg border border-white/10 overflow-hidden"
                                    style={{
                                      background: `radial-gradient(circle at 20% 25%, ${p.glow} 0%, transparent 32%), linear-gradient(135deg, ${p.hex} 0%, ${p.surface} 68%, ${p.glow} 140%)`,
                                      boxShadow: isActive ? `0 0 18px color-mix(in srgb, ${p.glow} 45%, transparent)` : 'none',
                                    }}
                                  />
                                  <span className="min-w-0 relative z-10 flex flex-col gap-1">
                                    <span className={`text-[11px] font-mono tracking-widest truncate transition-colors ${isActive ? 'text-[#f4f4f5] font-bold' : 'text-[#a1a1aa] group-hover:text-[#f4f4f5]'}`}>
                                      {p.name.toUpperCase()}
                                    </span>
                                    <span className="text-[9px] font-mono tracking-[0.18em] text-[#52525b] uppercase">
                                      {p.hex}
                                    </span>
                                  </span>
                                </button>
                              );
                            })}
                          </div>
                        </section>
                      </motion.div>
                    )}

                    {settingsTab === 'database' && (
                      <motion.div
                        key="database"
                        initial={{ opacity: 0, y: 10 }}
                        animate={{ opacity: 1, y: 0 }}
                        exit={{ opacity: 0, y: -10 }}
                        transition={{ duration: reduceMotion ? 0 : 0.2 }}
                        className="space-y-8"
                      >
                      <div>
                        <h3 className="text-[12px] font-bold text-[#ef4444] uppercase tracking-widest mb-2 flex items-center gap-2">
                          <span aria-hidden="true" className="material-symbols-outlined text-[16px]">warning</span>
                          {t('components.danger_zone')}
                        </h3>
                        <p className="text-[11px] text-[#71717a] mb-6 font-mono">
                          {t('components.danger_zone_desc')}
                        </p>
                        
                        <div className="space-y-4">
                          <div className="p-5 border border-[#ef4444]/20 rounded-xl bg-gradient-to-r from-[#ef4444]/[0.02] to-transparent flex justify-between items-center group hover:border-[#ef4444]/40 transition-colors">
                            <div>
                              <div className="text-[13px] font-bold text-[#f4f4f5]">{t('components.clear_findings_cache')}</div>
                              <div className="text-[11px] text-[#a1a1aa] mt-1">{t('components.clear_cache_desc')}</div>
                            </div>
                            <button 
                              onClick={async () => {
                                if (confirm(t('components.confirm_clear_cache'))) {
                                  try {
                                    await api.post('/admin/clear-cache');
                                    window.location.reload();
                                  } catch {
                                    alert(t('components.clear_cache_failed'));
                                  }
                                }
                              }}
                              className="px-5 py-2.5 bg-[rgba(239,68,68,0.1)] text-[#ef4444] border border-[#ef4444]/30 rounded-lg text-[11px] font-bold uppercase tracking-wider hover:bg-[#ef4444]/20 transition-all shadow-[0_0_15px_rgba(239,68,68,0)] hover:shadow-[0_0_15px_rgba(239,68,68,0.2)]"
                            >
                              {t('components.clear_cache_btn')}
                            </button>
                          </div>

                          <div className="p-5 border border-[#ef4444]/30 rounded-xl bg-gradient-to-r from-[#ef4444]/10 to-[#ef4444]/[0.02] flex justify-between items-center group shadow-[0_0_20px_rgba(239,68,68,0.05)]">
                            <div>
                              <div className="text-[13px] font-bold text-[#f4f4f5]">{t('components.purge_all_data')}</div>
                              <div className="text-[11px] text-[#a1a1aa] mt-1">{t('components.purge_all_data_desc')}</div>
                            </div>
                            <button 
                              onClick={async () => {
                                if (confirm(t('components.confirm_purge_data'))) {
                                  try {
                                    await api.post('/admin/purge');
                                    window.location.reload();
                                  } catch {
                                    alert(t('components.purge_data_failed'));
                                  }
                                }
                              }}
                              className="px-5 py-2.5 bg-[#ef4444] text-white rounded-lg text-[11px] font-bold uppercase tracking-wider hover:bg-[#dc2626] transition-all shadow-[0_0_15px_rgba(239,68,68,0.3)] hover:shadow-[0_0_25px_rgba(239,68,68,0.5)]"
                            >
                              {t('components.purge_database_btn')}
                            </button>
                          </div>
                        </div>
                      </div>
                      </motion.div>
                    )}

                  </AnimatePresence>
                </div>
              </div>
              
              <div className="p-6 flex justify-end relative z-10 border-t border-[rgba(255,255,255,0.04)]">
                <button
                  onClick={() => setShowSettings(false)}
                  className="px-8 py-3 bg-[var(--accent-color)] text-[var(--accent-color-on-text)] hover:bg-[var(--accent-color-hover)] rounded-lg text-[12px] font-bold uppercase tracking-widest shadow-[0_0_15px_var(--accent-color-line)] hover:shadow-[0_0_25px_var(--accent-color-soft)] transition-all duration-300"
                >
                  {t('components.apply_close')}
                </button>
              </div>
            </div>
          </ModalDialog>
        )}
      </AnimatePresence>

    </header>
  );
};
