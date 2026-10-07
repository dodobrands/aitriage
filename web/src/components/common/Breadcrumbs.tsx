import React from 'react';
import { useLocation, Link, useParams } from 'react-router-dom';

import { useTranslation } from 'react-i18next';

export const Breadcrumbs: React.FC = () => {
  const location = useLocation();
  const params = useParams();
  const { t } = useTranslation('components');
  const pathnames = location.pathname.split('/').filter((x) => x);

  // Map route segments to human readable names
  const routeMap: Record<string, string> = {
    products: t('Breadcrumbs.products', 'PRODUCTS_INDEX'),
    findings: t('Breadcrumbs.findings', 'FINDINGS_REPOSITORY'),
    reports: t('Breadcrumbs.reports', 'INTEL_REPORTS'),
    admin: t('Breadcrumbs.admin', 'ROOT_ACCESS_PANEL'),
  };

  if (location.pathname === '/') return null;

  return (
    <nav className="flex items-center gap-2 px-8 py-3 bg-surface-container-lowest border-b border-outline-variant/30 text-[9px] font-black uppercase tracking-widest italic shrink-0">
      <Link
        to="/"
        className="text-on-surface-variant hover:text-primary-fixed-dim transition-none flex items-center gap-1"
      >
        <span className="material-symbols-outlined text-[12px]">terminal</span>
        {t('Breadcrumbs.commandCenter', 'COMMAND_CENTER')}
      </Link>

      {pathnames.map((value, index) => {
        const last = index === pathnames.length - 1;
        const to = `/${pathnames.slice(0, index + 1).join('/')}`;

        const isParam = Object.values(params).includes(value);
        const name = routeMap[value] || (isParam ? `${t('Breadcrumbs.idPrefix', 'ID:')}${value}` : value.toUpperCase());

        return (
          <React.Fragment key={to}>
            <span className="text-on-surface-variant/30">/</span>
            {last ? (
              <span className="text-primary-fixed-dim bg-primary-fixed-dim/5 px-1.5 py-0.5">
                {name}
              </span>
            ) : (
              <Link
                to={to}
                className="text-on-surface-variant hover:text-primary-fixed-dim transition-none"
              >
                {name}
              </Link>
            )}
          </React.Fragment>
        );
      })}
    </nav>
  );
};
