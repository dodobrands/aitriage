import React, { useEffect, useState, lazy, Suspense } from 'react';
import { Outlet, useNavigate, useLocation, useSearchParams } from 'react-router-dom';
import { motion, AnimatePresence, useReducedMotion } from 'framer-motion';
import { useTranslation } from 'react-i18next';
import { RouteLoading } from '../ui/RouteLoading';
import { Header } from './Header';
import { Sidebar } from './Sidebar';
import { useAuthStore } from '../store/AuthStore';
import api from '../services/api';
import { useCopilotStore } from '../store/CopilotStore';
import { useViewModeStore } from '../store/ViewModeStore';
const AICopilot = lazy(() => import('./AICopilot').then(module => ({ default: module.AICopilot })));
const SimpleDashboardPage = lazy(() => import('../pages/SimpleDashboardPage').then(module => ({ default: module.SimpleDashboardPage })));
const SimpleAIChatPage = lazy(() => import('../pages/SimpleAIChatPage').then(module => ({ default: module.SimpleAIChatPage })));
const RepositoriesPage = lazy(() => import('../pages/RepositoriesPage').then(module => ({ default: module.RepositoriesPage })));
const TriagedPage = lazy(() => import('../pages/TriagedPage').then(module => ({ default: module.TriagedPage })));
const RunwayReportsPage = lazy(() => import('../pages/RunwayReportsPage').then(module => ({ default: module.RunwayReportsPage })));
const FAQPage = lazy(() => import('../pages/FAQPage').then(module => ({ default: module.FAQPage })));
import type { Finding } from '../types';

type SimpleTab = 'overview' | 'repositories' | 'triaged' | 'reports' | 'chat' | 'faq';

export const Layout: React.FC = () => {
  const { t } = useTranslation('components');
  const { user, setUser, logout } = useAuthStore();
  const viewMode = useViewModeStore((state) => state.mode);
  const navigate = useNavigate();
  const location = useLocation();
  const isCopilotOpen = useCopilotStore((state) => state.isOpen);
  const isCopilotPinned = useCopilotStore((state) => state.isPinned);
  const reduceMotion = useReducedMotion();

  const [searchParams, setSearchParams] = useSearchParams();
  const requestedTab = searchParams.get('tab');
  const simpleTab: SimpleTab = ['repositories', 'triaged', 'reports', 'chat', 'faq'].includes(requestedTab || '') ? requestedTab as SimpleTab : 'overview';
  const setSimpleTab = (tab: SimpleTab) => {
    setSearchParams(previous => { const next = new URLSearchParams(previous); next.set('tab', tab); return next; });
  };
  const [sessionError, setSessionError] = useState(false);
  const [requestedReportId, setRequestedReportId] = useState<number | null>(null);

  const [chatContextFinding, setChatContextFinding] = useState<Finding | null>(null);
  const [chatInitialPrompt, setChatInitialPrompt] = useState<string | null>(null);

  const [isSidebarPinned, setIsSidebarPinned] = useState(() => {
    try {
      return localStorage.getItem('sidebar_pinned') === 'true';
    } catch {
      return false;
    }
  });

  const toggleSidebarPin = () => {
    setIsSidebarPinned((prev) => {
      const next = !prev;
      try {
        localStorage.setItem('sidebar_pinned', String(next));
      } catch {
        // Sidebar pinning remains optional when storage is unavailable.
      }
      return next;
    });
  };

  const handleNavigateToChat = (findingOrPrompt?: Finding | string) => {
    if (findingOrPrompt) {
      if (typeof findingOrPrompt === 'string') {
        setChatInitialPrompt(findingOrPrompt);
        setChatContextFinding(null);
      } else {
        setChatContextFinding(findingOrPrompt);
        setChatInitialPrompt(null);
      }
    } else {
      setChatContextFinding(null);
      setChatInitialPrompt(null);
    }
    setSimpleTab('chat');
  };

  // When entering simple mode, redirect to root so URL is clean
  useEffect(() => {
    if (viewMode === 'simple' && location.pathname !== '/') {
      navigate('/', { replace: true });
    }
  }, [location.pathname, navigate, viewMode]);

  useEffect(() => {
    api
      .get('/me')
      .then((res) => {
        if (res.data.ok) { setUser(res.data); setSessionError(false); }
        else setSessionError(true);
      })
      .catch(() => setSessionError(true));
  }, [setUser]);

  const handleLogout = () => {
    document.cookie = 'token=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;';
    logout();
    navigate('/login');
  };

  if (sessionError) return <div className="session-error" role="alert"><p>{t('session_error', 'Could not verify your session. Please retry.')}</p><button type="button" onClick={() => window.location.reload()}>{t('retry', 'Retry')}</button></div>;

  if (!user) {
    return (
      <div className="h-screen flex flex-col items-center justify-center bg-background gap-6">
        <div className="flex gap-1.5">
          {[0, 1, 2].map((i) => (
            <div
              key={i}
              className="w-2 h-6 bg-primary animate-pulse"
              style={{ animationDelay: `${i * 0.15}s` }}
            />
          ))}
        </div>
        <span className="text-label-caps text-on-surface-variant/40 tracking-[0.25em] text-xs">
          {t('initializing_system')}
        </span>
      </div>
    );
  }

  return (
    <div className="h-screen flex flex-col overflow-hidden bg-background relative noise">
      {/* Background — mode-specific */}
      {viewMode === 'advanced' ? (
        <div className="absolute inset-0 overflow-hidden pointer-events-none z-0">
          <div className="ambient-bg-motion" />
          <div className="luxury-glow-orb-1" />
          <div className="luxury-glow-orb-2" />
          <div className="luxury-glow-orb-3" />
          <div className="absolute inset-0 grid-bg opacity-25" />
        </div>
      ) : (
        <div className="absolute inset-0 overflow-hidden pointer-events-none z-0">
          <div className="absolute inset-0 simple-bg-gradient" />
          <div className="ambient-bg-motion" />
        </div>
      )}

      <a className="skip-link" href="#main-content">{t('skip_to_content', 'Skip to content')}</a>
      <Header />

      {/* Simple Mode Tab Bar */}
      <div
        className={`relative z-20 border-b border-[rgba(255,255,255,0.06)] bg-background overflow-hidden shrink-0 transition-all duration-300 ease-[cubic-bezier(0.4,0,0.2,1)] ${
          viewMode === 'simple'
            ? 'max-h-14 opacity-100 translate-y-0'
            : 'max-h-0 opacity-0 -translate-y-2 pointer-events-none'
        }`}
        inert={viewMode !== 'simple'}
      >
        <div role="tablist" aria-label={t('simple_navigation')} className="simple-tablist flex w-full items-center gap-0 px-3 sm:px-6 overflow-x-auto">
          {([
            { id: 'overview' as SimpleTab, label: t('tab_overview'), icon: 'dashboard' },
            { id: 'reports' as SimpleTab, label: t('tab_reports'), icon: 'description' },
            { id: 'repositories' as SimpleTab, label: t('tab_repositories'), icon: 'folder' },
            { id: 'triaged' as SimpleTab, label: t('tab_triaged'), icon: 'task_alt' },
            { id: 'chat' as SimpleTab, label: t('tab_ai_assistant'), icon: 'smart_toy' },
            { id: 'faq' as SimpleTab, label: t('tab_faq'), icon: 'help' },
          ]).map((tab) => (
            <button
              type="button"
              role="tab"
              id={`simple-tab-${tab.id}`}
              aria-controls={`simple-panel-${tab.id}`}
              tabIndex={simpleTab === tab.id ? 0 : -1}
              onKeyDown={event => {
                const tabs = Array.from(event.currentTarget.parentElement?.querySelectorAll<HTMLButtonElement>('[role="tab"]') || []);
                const index = tabs.indexOf(event.currentTarget);
                const next = event.key === 'ArrowRight' ? (index + 1) % tabs.length : event.key === 'ArrowLeft' ? (index + tabs.length - 1) % tabs.length : event.key === 'Home' ? 0 : event.key === 'End' ? tabs.length - 1 : null;
                if (next !== null) { event.preventDefault(); tabs[next].focus(); tabs[next].click(); tabs[next].scrollIntoView({ block: 'nearest', inline: 'nearest' }); }
              }}
              key={tab.id}
              onClick={() => setSimpleTab(tab.id)}
              aria-selected={simpleTab === tab.id}
              aria-current={simpleTab === tab.id ? 'page' : undefined}
              className={`relative shrink-0 flex items-center gap-1.5 px-4 py-2.5 rounded-md text-[13px] outline-none transition-colors focus-visible:ring-1 focus-visible:ring-inset focus-visible:ring-[var(--accent-color-line)] ${
                simpleTab === tab.id
                  ? 'text-[#f4f4f5] font-semibold'
                  : 'text-[#a1a1aa] font-medium hover:text-[#c4c4cc]'
              }`}
            >
              {tab.icon && <span className="material-symbols-outlined text-[16px]" aria-hidden="true">{tab.icon}</span>}
              {tab.label}
              {simpleTab === tab.id && (
                <motion.div layoutId="simple-tab-indicator" className="absolute bottom-0 left-4 right-4 h-[2px] bg-[var(--accent-color)]" />
              )}
            </button>
          ))}
        </div>
      </div>

      <div className="flex flex-1 overflow-hidden relative z-10">
        <Sidebar
          onLogout={handleLogout}
          isPinned={isSidebarPinned}
          onTogglePin={toggleSidebarPin}
          isVisible={viewMode === 'advanced'}
        />

        {/* AI Copilot — advanced mode only */}
        {viewMode === 'advanced' && isCopilotOpen && (
          <aside
            className={`
 ${isCopilotPinned ? 'relative' : `absolute left-16 top-0 bottom-0 z-50`} 
 w-[400px] border-r border-outline-variant animate-in slide-in-from-left bg-surface shrink-0
 `}
            style={isSidebarPinned && !isCopilotPinned ? { left: '256px' } : undefined}
          >
            <Suspense fallback={<RouteLoading />}><AICopilot
              onClose={() => useCopilotStore.getState().setIsOpen(false)}
              isPinned={isCopilotPinned}
              onTogglePin={() =>
                useCopilotStore.getState().setIsPinned(!useCopilotStore.getState().isPinned)
              }
            /></Suspense>
          </aside>
        )}

        <div className="flex-1 min-w-0 flex overflow-hidden relative">
          <main id="main-content" tabIndex={-1} className="flex-1 h-full bg-transparent relative overflow-hidden"><Suspense fallback={<RouteLoading />}>
            <AnimatePresence mode="wait">
              {viewMode === 'advanced' ? (
                <motion.div
                  key="advanced"
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  exit={{ opacity: 0 }}
                  transition={{ duration: reduceMotion ? 0 : 0.2 }}
                  className="h-full"
                >
                  <Outlet />
                </motion.div>
              ) : (
                <motion.div
                  role="tabpanel" id={`simple-panel-${simpleTab}`} aria-labelledby={`simple-tab-${simpleTab}`}
                  key={`simple-${simpleTab}`}
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  exit={{ opacity: 0 }}
                  transition={{ duration: reduceMotion ? 0 : 0.12, ease: [0.22, 1, 0.36, 1] }}
                  className="h-full w-full absolute inset-0"
                >
                  {simpleTab === 'overview' ? (
                    <SimpleDashboardPage
                      onNavigateToChat={handleNavigateToChat}
                      onNavigateToReports={(sessionId) => {
                        setRequestedReportId(sessionId ?? null);
                        setSimpleTab('reports');
                      }}
                    />
                  ) : simpleTab === 'repositories' ? (
                    <RepositoriesPage />
                  ) : simpleTab === 'triaged' ? (
                    <TriagedPage />
                  ) : simpleTab === 'reports' ? (
                    <RunwayReportsPage
                      initialSessionId={requestedReportId}
                      onNavigateToOverview={() => setSimpleTab('overview')}
                    />
                  ) : simpleTab === 'chat' ? (
                    <SimpleAIChatPage
                      contextFinding={chatContextFinding}
                      initialPrompt={chatInitialPrompt}
                      onClearContext={() => setChatContextFinding(null)}
                      onClearInitialPrompt={() => setChatInitialPrompt(null)}
                    />
                  ) : (
                    <FAQPage />
                  )}
                </motion.div>
              )}
            </AnimatePresence>
          </Suspense></main>
        </div>


      </div>
    </div>
  );
};
