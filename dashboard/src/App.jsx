import { Routes, Route, Navigate } from 'react-router-dom';
import { RequireAuth } from './auth';
import Login from './pages/Login';
import Dashboard from './pages/Dashboard';
import Models from './pages/Models';
import AuditTrail from './pages/AuditTrail';
import RiskScanner from './pages/RiskScanner';
import Frameworks from './pages/Frameworks';

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route
        path="/"
        element={
          <RequireAuth>
            <Dashboard />
          </RequireAuth>
        }
      />
      <Route
        path="/models"
        element={
          <RequireAuth>
            <Models />
          </RequireAuth>
        }
      />
      <Route
        path="/audit"
        element={
          <RequireAuth>
            <AuditTrail />
          </RequireAuth>
        }
      />
      <Route
        path="/scan"
        element={
          <RequireAuth>
            <RiskScanner />
          </RequireAuth>
        }
      />
      <Route
        path="/frameworks"
        element={
          <RequireAuth>
            <Frameworks />
          </RequireAuth>
        }
      />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
