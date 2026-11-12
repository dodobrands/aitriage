import React from 'react';
import { PageLayout } from './PageLayout';
import { useTranslation } from 'react-i18next';
import { useRouteError } from 'react-router-dom';

export const RouteError: React.FC = () => {
  const error = useRouteError() as Error;
  const { t } = useTranslation('components');

  return (
    <PageLayout title={t('ErrorBoundary.systemFailure')} subtitle={t('ErrorBoundary.routingError')}>
      <div className="flex-1 p-8">
        <div className="p-6 border border-error bg-surface-container-low space-y-4">
          <div className="text-[10px] uppercase tracking-widest font-black italic flex items-center gap-2 text-error">
            <div className="w-2 h-2 bg-error animate-pulse" />
            {t('ErrorBoundary.criticalRouting')}
          </div>
          <div className="text-on-surface-variant font-mono text-sm p-4 bg-surface-container-low border border-outline-variant">
            {error?.message || error?.toString()}
          </div>
          <div className="pt-4">
            <button
              onClick={() => window.location.reload()}
              className="px-6 py-2 border border-outline-variant bg-surface-container hover:bg-surface-container-high hover:border-outline text-[10px] font-black tracking-widest transition-none uppercase"
            >
              {t('ErrorBoundary.reboot')}
            </button>
          </div>
        </div>
      </div>
    </PageLayout>
  );
};
