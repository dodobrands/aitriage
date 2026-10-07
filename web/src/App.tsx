import { lazy } from 'react';
import { createBrowserRouter, redirect, RouterProvider } from 'react-router-dom';
import { Layout } from './components/Layout';
import { ProtectedRoute } from './components/ProtectedRoute';
import { LoginPage } from './components/LoginPage';
const DashboardPage = lazy(() =>
  import('./pages/DashboardPage').then((module) => ({ default: module.DashboardPage })),
);
const ProductsPage = lazy(() =>
  import('./pages/ProductsPage').then((module) => ({ default: module.ProductsPage })),
);
const ProductDetailPage = lazy(() =>
  import('./pages/ProductDetailPage').then((module) => ({ default: module.ProductDetailPage })),
);
const FindingsPage = lazy(() =>
  import('./pages/FindingsPage').then((module) => ({ default: module.FindingsPage })),
);
const AdminPanelPage = lazy(() =>
  import('./pages/AdminPanelPage').then((module) => ({ default: module.AdminPanelPage })),
);
const ReportsPage = lazy(() =>
  import('./pages/ReportsPage').then((module) => ({ default: module.ReportsPage })),
);
const RulesPage = lazy(() =>
  import('./pages/RulesPage').then((module) => ({ default: module.RulesPage })),
);
const TopologyPage = lazy(() =>
  import('./pages/TopologyPage').then((module) => ({ default: module.TopologyPage })),
);
const ScannersPage = lazy(() =>
  import('./pages/ScannersPage').then((module) => ({ default: module.ScannersPage })),
);
const TerminalPage = lazy(() =>
  import('./pages/TerminalPage').then((module) => ({ default: module.TerminalPage })),
);
const AIChatPage = lazy(() =>
  import('./pages/AIChatPage').then((module) => ({ default: module.AIChatPage })),
);
const CommandCenterPage = lazy(() =>
  import('./pages/CommandCenterPage').then((module) => ({ default: module.CommandCenterPage })),
);
const FAQPage = lazy(() =>
  import('./pages/FAQPage').then((module) => ({ default: module.FAQPage })),
);
import { RouteError } from './ui/ErrorBoundary';

const router = createBrowserRouter([
  {
    path: '/login',
    element: <LoginPage />,
  },
  {
    path: '/',
    element: <Layout />,
    errorElement: <RouteError />,
    children: [
      {
        index: true,
        element: (
          <ProtectedRoute>
            <DashboardPage />
          </ProtectedRoute>
        ),
      },
      {
        path: 'cc',
        element: (
          <ProtectedRoute>
            <CommandCenterPage />
          </ProtectedRoute>
        ),
      },
      {
        path: 'products',
        element: (
          <ProtectedRoute>
            <ProductsPage />
          </ProtectedRoute>
        ),
      },
      {
        path: 'products/:id',
        element: (
          <ProtectedRoute>
            <ProductDetailPage />
          </ProtectedRoute>
        ),
      },
      {
        path: 'kanban',
        loader: () => redirect('/'),
      },
      {
        path: 'findings',
        element: (
          <ProtectedRoute>
            <FindingsPage />
          </ProtectedRoute>
        ),
      },
      {
        path: 'chat',
        element: (
          <ProtectedRoute>
            <AIChatPage />
          </ProtectedRoute>
        ),
      },
      {
        path: 'rules',
        element: (
          <ProtectedRoute>
            <RulesPage />
          </ProtectedRoute>
        ),
      },
      {
        path: 'topology',
        element: (
          <ProtectedRoute>
            <TopologyPage />
          </ProtectedRoute>
        ),
      },
      {
        path: 'scanners',
        element: (
          <ProtectedRoute>
            <ScannersPage />
          </ProtectedRoute>
        ),
      },
      {
        path: 'terminal',
        element: (
          <ProtectedRoute>
            <TerminalPage />
          </ProtectedRoute>
        ),
      },
      {
        path: 'faq',
        element: (
          <ProtectedRoute>
            <FAQPage />
          </ProtectedRoute>
        ),
      },
      {
        path: 'reports',
        element: (
          <ProtectedRoute allowedRoles={['security_lead', 'admin', 'superadmin']}>
            <ReportsPage />
          </ProtectedRoute>
        ),
      },
      {
        path: 'admin',
        element: (
          <ProtectedRoute allowedRoles={['admin', 'superadmin']}>
            <AdminPanelPage />
          </ProtectedRoute>
        ),
      },
    ],
  },
]);

function App() {
  return <RouterProvider router={router} />;
}

export default App;
