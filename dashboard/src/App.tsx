import { Routes, Route, Navigate } from 'react-router-dom';
import Layout from './components/Layout';
import LoginPage from './auth/LoginPage';
import { ProtectedRoute } from './auth/ProtectedRoute';
import ValidatePage from './pages/ValidatePage';
import SanitizePage from './pages/SanitizePage';
import TrustScorePage from './pages/TrustScorePage';
import CompliancePage from './pages/CompliancePage';
import IntelligencePage from './pages/IntelligencePage';
import AuditLedgerPage from './pages/AuditLedgerPage';
import AppealsPage from './pages/AppealsPage';
import WebhooksPage from './pages/WebhooksPage';
import FriaPage from './pages/FriaPage';
import MetricsPage from './pages/MetricsPage';
import PolicyEditorPage from './pages/PolicyEditorPage';

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route element={<ProtectedRoute />}>
        <Route element={<Layout />}>
          <Route index element={<Navigate to="/validate" replace />} />
          <Route path="validate" element={<ValidatePage />} />
          <Route path="sanitize" element={<SanitizePage />} />
          <Route path="trust" element={<TrustScorePage />} />
          <Route path="compliance" element={<CompliancePage />} />
          <Route path="intelligence" element={<IntelligencePage />} />
          <Route path="audit" element={<AuditLedgerPage />} />
          <Route path="appeals" element={<AppealsPage />} />
          <Route path="webhooks" element={<WebhooksPage />} />
          <Route path="fria" element={<FriaPage />} />
          <Route path="metrics" element={<MetricsPage />} />
          <Route path="policies" element={<PolicyEditorPage />} />
        </Route>
      </Route>
    </Routes>
  );
}
