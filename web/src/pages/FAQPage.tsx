import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { useTranslation } from 'react-i18next';
import { useTitle } from '../hooks/useTitle';

type FAQSection = 'overview' | 'scanners' | 'features' | 'guide' | 'score';

export const FAQPage: React.FC = () => {
  const { t } = useTranslation('pages');
  useTitle(t('faq.title'));
  const [activeSection, setActiveSection] = useState<FAQSection>('overview');

  const navItems = [
    { id: 'overview' as FAQSection, label: t('faq.howItWorks.title'), icon: 'info' },
    { id: 'scanners' as FAQSection, label: t('faq.scanners.title'), icon: 'fingerprint' },
    { id: 'features' as FAQSection, label: t('faq.features.title'), icon: 'extension' },
    { id: 'guide' as FAQSection, label: t('faq.howToUse.title'), icon: 'map' },
    { id: 'score' as FAQSection, label: t('faq.scoring.title'), icon: 'analytics' },
  ];

  const contentVariants = {
    hidden: { opacity: 0, x: 15 },
    visible: { opacity: 1, x: 0, transition: { duration: 0.25, ease: 'easeOut' as any } },
    exit: { opacity: 0, x: -15, transition: { duration: 0.15, ease: 'easeIn' as any } },
  };

  return (
    <div className="h-full flex flex-col bg-background relative font-sans overflow-hidden">
      {/* Background Accent Glow Orbs */}
      <div className="absolute -right-20 -top-20 w-[450px] h-[450px] rounded-full bg-[var(--accent-color)] opacity-[0.04] filter blur-[100px] pointer-events-none z-0 transition-all duration-700 ease-in-out" />
      <div className="absolute -left-20 -bottom-20 w-[350px] h-[350px] rounded-full bg-[var(--accent-color)] opacity-[0.03] filter blur-[80px] pointer-events-none z-0 transition-all duration-700 ease-in-out" />

      {/* Top Banner */}
      <div className="px-8 py-6 border-b border-[rgba(255,255,255,0.06)] bg-[rgba(255,255,255,0.01)] shrink-0 z-10 relative">
        <div className="flex items-center gap-3 mb-2">
          <span className="material-symbols-outlined text-[20px]" style={{ color: 'var(--accent-color)', textShadow: '0 0 12px var(--accent-color-line)' }}>
            menu_book
          </span>
          <span className="text-[10px] font-bold tracking-[0.2em] text-[#a1a1aa] uppercase">
            {t('faq.title')}
          </span>
        </div>
        <h1 className="text-xl text-white font-bold tracking-tight">
          {t('faq.title')}
        </h1>
        <p className="text-xs text-[#71717a] mt-1">
          {t('faq.subtitle')}
        </p>
      </div>

      {/* Main Workspace Grid */}
      <div className="flex-1 flex overflow-hidden z-10 relative">
        {/* Left inner navigation sidebar */}
        <div className="w-64 border-r border-[rgba(255,255,255,0.06)] bg-[rgba(0,0,0,0.15)] p-4 flex flex-col gap-1 shrink-0 overflow-y-auto cyber-scrollbar">
          {navItems.map((item) => {
            const isActive = activeSection === item.id;
            return (
              <button
                key={item.id}
                onClick={() => setActiveSection(item.id)}
                className={`flex items-center h-10 px-4 gap-3 rounded-lg text-[12px] font-medium tracking-wide transition-all duration-200 border text-left ${
                  isActive
                    ? 'bg-[var(--accent-color-soft)] border-[var(--accent-color-line)] text-[var(--accent-color)] shadow-[0_0_15px_var(--accent-color-soft),_inset_2px_0_0_0_var(--accent-color)]'
                    : 'border-transparent text-[#71717a] hover:bg-[rgba(255,255,255,0.02)] hover:border-[rgba(255,255,255,0.04)] hover:text-[#f4f4f5]'
                }`}
              >
                <span className="material-symbols-outlined text-[16px] shrink-0">
                  {item.icon}
                </span>
                <span className="truncate">{item.label}</span>
              </button>
            );
          })}
        </div>

        {/* Right content view area */}
        <div className="flex-1 p-8 overflow-y-auto cyber-scrollbar bg-[#09090b]/40 relative">
          <AnimatePresence mode="wait">
            <motion.div
              key={activeSection}
              variants={contentVariants}
              initial="hidden"
              animate="visible"
              exit="exit"
              className="max-w-3xl space-y-6"
            >
              {/* SECTION: Overview */}
              {activeSection === 'overview' && (
                <div className="space-y-6">
                  <div className="border border-[rgba(255,255,255,0.06)] rounded-xl p-6 bg-[rgba(255,255,255,0.01)] space-y-4">
                    <h2 className="text-sm font-semibold tracking-widest text-[#f4f4f5] uppercase flex items-center gap-2">
                      <span className="material-symbols-outlined text-[16px]" style={{ color: 'var(--accent-color)', textShadow: '0 0 10px var(--accent-color-line)' }}>info</span>
                      {t('faq.howItWorks.title')}
                    </h2>
                    <p className="text-[13px] leading-relaxed text-[#a1a1aa]">
                      {t('faq.howItWorks.content')}
                    </p>
                  </div>

                  <div className="grid grid-cols-2 gap-4">
                    <div className="border border-[rgba(255,255,255,0.04)] rounded-xl p-5 bg-[rgba(255,255,255,0.005)] hover:border-[var(--accent-color-line)] hover:bg-[var(--accent-color-soft)] transition-all duration-300 group space-y-2">
                      <span className="material-symbols-outlined text-lg transition-transform duration-300 group-hover:scale-110" style={{ color: 'var(--accent-color)', textShadow: '0 0 10px var(--accent-color-line)' }}>hub</span>
                      <h3 className="text-xs font-bold text-white uppercase tracking-wider">Orchestration</h3>
                      <p className="text-[11px] leading-relaxed text-[#71717a]">
                        Runs multi-threaded scanning tools asynchronously to identify vulnerabilities instantly without managing separate CLI workflows.
                      </p>
                    </div>
                    <div className="border border-[rgba(255,255,255,0.04)] rounded-xl p-5 bg-[rgba(255,255,255,0.005)] hover:border-[var(--accent-color-line)] hover:bg-[var(--accent-color-soft)] transition-all duration-300 group space-y-2">
                      <span className="material-symbols-outlined text-lg transition-transform duration-300 group-hover:scale-110" style={{ color: 'var(--accent-color)', textShadow: '0 0 10px var(--accent-color-line)' }}>psychology</span>
                      <h3 className="text-xs font-bold text-white uppercase tracking-wider">Cognitive Triage</h3>
                      <p className="text-[11px] leading-relaxed text-[#71717a]">
                        Combines traditional heuristics with LLM agents (SecureCoder) to generate remediation suggestions, threat models, and vulnerability explanations.
                      </p>
                    </div>
                  </div>
                </div>
              )}

              {/* SECTION: Scanners */}
              {activeSection === 'scanners' && (
                <div className="space-y-6">
                  <div className="border border-[rgba(255,255,255,0.06)] rounded-xl p-6 bg-[rgba(255,255,255,0.01)] space-y-4">
                    <h2 className="text-sm font-semibold tracking-widest text-[#f4f4f5] uppercase flex items-center gap-2">
                      <span className="material-symbols-outlined text-[16px]" style={{ color: 'var(--accent-color)', textShadow: '0 0 10px var(--accent-color-line)' }}>fingerprint</span>
                      {t('faq.scanners.title')}
                    </h2>
                    <p className="text-[13px] leading-relaxed text-[#a1a1aa]">
                      {t('faq.scanners.subtitle')}
                    </p>

                    <div className="divide-y divide-[rgba(255,255,255,0.06)] mt-4">
                      {[
                        { name: 'Semgrep', desc: t('faq.scanners.semgrep'), tech: 'SAST / Rules' },
                        { name: 'Trivy', desc: t('faq.scanners.trivy'), tech: 'Dependencies & SBOM' },
                        { name: 'Gitleaks', desc: t('faq.scanners.gitleaks'), tech: 'Secrets & Keys' },
                        { name: 'Bandit', desc: t('faq.scanners.bandit'), tech: 'Python SAST' },
                        { name: 'SecureCoder', desc: t('faq.scanners.securecoder'), tech: 'AI agent' },
                      ].map((scanner) => (
                        <div key={scanner.name} className="py-4 flex items-start gap-4">
                          <div className="w-24 shrink-0 font-mono font-bold text-xs text-white uppercase tracking-wider mt-0.5">
                            {scanner.name}
                          </div>
                          <div className="flex-1 text-xs text-[#a1a1aa] leading-relaxed">
                            {scanner.desc}
                          </div>
                          <span className="text-[9px] font-bold px-2 py-0.5 rounded border border-[var(--accent-color-line)] bg-[var(--accent-color-soft)] text-[var(--accent-color)] font-mono shrink-0 uppercase tracking-widest shadow-[0_0_8px_var(--accent-color-soft)]">
                            {scanner.tech}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              )}

              {/* SECTION: Features */}
              {activeSection === 'features' && (
                <div className="space-y-4">
                  <h2 className="text-sm font-semibold tracking-widest text-[#f4f4f5] uppercase flex items-center gap-2">
                    <span className="material-symbols-outlined text-[16px]" style={{ color: 'var(--accent-color)', textShadow: '0 0 10px var(--accent-color-line)' }}>extension</span>
                    {t('faq.features.title')}
                  </h2>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {[
                      { icon: 'smart_toy', title: 'AI Triage Workspace', text: t('faq.features.triage') },
                      { icon: 'account_tree', title: 'Topology Mapping', text: t('faq.features.topology') },
                      { icon: 'inventory_2', title: 'Dependency Inventory (SBOM)', text: t('faq.features.sbom') },
                      { icon: 'description', title: 'Compliance Ledger', text: t('faq.features.compliance') },
                    ].map((feat) => (
                      <div key={feat.title} className="border border-[rgba(255,255,255,0.06)] rounded-xl p-5 bg-[rgba(255,255,255,0.01)] hover:border-[var(--accent-color-line)] hover:bg-[var(--accent-color-soft)] transition-all duration-300 flex gap-4 group">
                        <span className="material-symbols-outlined text-lg transition-transform duration-300 group-hover:scale-110 shrink-0 mt-0.5" style={{ color: 'var(--accent-color)', textShadow: '0 0 10px var(--accent-color-line)' }}>{feat.icon}</span>
                        <div className="space-y-1">
                          <h3 className="text-xs font-bold text-white uppercase tracking-wider">{feat.title}</h3>
                          <p className="text-[11px] leading-relaxed text-[#71717a]">{feat.text}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* SECTION: Platform Guide */}
              {activeSection === 'guide' && (
                <div className="space-y-6">
                  <div className="border border-[rgba(255,255,255,0.06)] rounded-xl p-6 bg-[rgba(255,255,255,0.01)] space-y-4">
                    <h2 className="text-sm font-semibold tracking-widest text-[#f4f4f5] uppercase flex items-center gap-2">
                      <span className="material-symbols-outlined text-[16px]" style={{ color: 'var(--accent-color)', textShadow: '0 0 10px var(--accent-color-line)' }}>map</span>
                      {t('faq.howToUse.title')}
                    </h2>

                    <div className="space-y-4 relative pl-4 border-l border-[rgba(255,255,255,0.06)] ml-2">
                      {[
                        t('faq.howToUse.step1'),
                        t('faq.howToUse.step2'),
                        t('faq.howToUse.step3'),
                        t('faq.howToUse.step4'),
                      ].map((step, idx) => (
                        <div key={idx} className="relative">
                          <div className="absolute -left-[27px] top-0.5 w-5 h-5 rounded-full bg-background border border-[var(--accent-color-line)] flex items-center justify-center text-[10px] font-bold text-[var(--accent-color)] shadow-[0_0_10px_var(--accent-color-soft)]">
                            {idx + 1}
                          </div>
                          <p className="text-xs leading-relaxed text-[#a1a1aa]">
                            {step}
                          </p>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              )}

              {/* SECTION: Security Score */}
              {activeSection === 'score' && (
                <div className="space-y-6">
                  <div className="border border-[rgba(255,255,255,0.06)] rounded-xl p-6 bg-[rgba(255,255,255,0.01)] space-y-4">
                    <h2 className="text-sm font-semibold tracking-widest text-[#f4f4f5] uppercase flex items-center gap-2">
                      <span className="material-symbols-outlined text-[16px]" style={{ color: 'var(--accent-color)', textShadow: '0 0 10px var(--accent-color-line)' }}>analytics</span>
                      {t('faq.scoring.title')}
                    </h2>
                    <p className="text-[13px] leading-relaxed text-[#a1a1aa]">
                      {t('faq.scoring.intro')}
                    </p>

                    {/* Penalty Table */}
                    <div className="border border-[rgba(255,255,255,0.06)] rounded-xl overflow-hidden mt-4 bg-[rgba(0,0,0,0.2)]">
                      <div className="grid grid-cols-3 gap-2 px-4 py-2 border-b border-[rgba(255,255,255,0.06)] text-[10px] font-bold tracking-widest text-[#52525b] uppercase font-mono bg-[rgba(255,255,255,0.02)]">
                        <div>Severity</div>
                        <div>Penalty</div>
                        <div>Build Impact</div>
                      </div>
                      {[
                        { sev: 'CRITICAL', penalty: '-25 pts', impact: 'Fails Build Pipeline (CI/CD Gate)', color: '#ef4444' },
                        { sev: 'HIGH', penalty: '-15 pts', impact: 'Fails Build Pipeline (CI/CD Gate)', color: '#f97316' },
                        { sev: 'MEDIUM', penalty: '-5 pts', impact: 'Telemetry Warning', color: '#eab308' },
                        { sev: 'LOW', penalty: '-1 pts', impact: 'Telemetry Info', color: '#a1a1aa' },
                      ].map((r) => (
                        <div key={r.sev} className="grid grid-cols-3 gap-2 px-4 py-3 border-b border-[rgba(255,255,255,0.03)] text-xs text-[#a1a1aa] items-center last:border-none">
                          <div className="font-bold flex items-center gap-2" style={{ color: r.color }}>
                            <span className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: r.color }} />
                            {r.sev}
                          </div>
                          <div className="font-mono text-white font-bold">{r.penalty}</div>
                          <div className="text-[10px] font-mono tracking-wide">{r.impact}</div>
                        </div>
                      ))}
                    </div>

                    <div className="p-4 border border-[var(--accent-color-line)] rounded-lg bg-[var(--accent-color-soft)] text-xs text-[var(--accent-color)] leading-relaxed">
                      <div className="flex gap-2">
                        <span className="material-symbols-outlined text-[16px] shrink-0 mt-0.5" style={{ textShadow: '0 0 8px var(--accent-color-line)' }}>verified_user</span>
                        <span>{t('faq.scoring.triagedNote')}</span>
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </motion.div>
          </AnimatePresence>
        </div>
      </div>
    </div>
  );
};

export default FAQPage;
