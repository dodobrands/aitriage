import { useTranslation } from 'react-i18next';

export function RouteLoading() {
  const { i18n } = useTranslation();
  return (
    <div className="route-loading" role="status" aria-busy="true">
      <p>{i18n.language.startsWith('ru') ? 'Загрузка раздела…' : 'Loading section…'}</p>
      <div className="route-loading__bar" />
      <div className="route-loading__bar" />
    </div>
  );
}
