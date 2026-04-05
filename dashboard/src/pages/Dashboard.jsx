import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import Layout from '../components/Layout';
import HealthGauge from '../components/HealthGauge';
import Spinner from '../components/Spinner';
import ErrorBanner from '../components/ErrorBanner';
import api from '../api';

export default function Dashboard() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const navigate = useNavigate();

  async function load() {
    setLoading(true);
    setError('');
    try {
      const res = await api.getDashboard();
      setData(res.dashboard);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { load(); }, []);

  if (loading) {
    return (
      <Layout title="Dashboard" breadcrumb="Home">
        <Spinner className="py-20" />
      </Layout>
    );
  }

  if (error) {
    return (
      <Layout title="Dashboard" breadcrumb="Home">
        <ErrorBanner message={error} onRetry={load} />
      </Layout>
    );
  }

  const { health, models, incidents, policies, quick_actions } = data;

  return (
    <Layout title="Dashboard" breadcrumb="Home">
      <div className="space-y-6">
        {/* Top stats row */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {/* Health Score */}
          <div className="card p-6 flex flex-col items-center">
            <HealthGauge score={health.score} />
            {health.issues.length > 0 && (
              <div className="mt-3 w-full space-y-1">
                {health.issues.map((issue, i) => (
                  <div key={i} className="text-xs text-amber-600 flex items-start gap-1.5">
                    <svg className="w-3.5 h-3.5 mt-0.5 shrink-0" fill="currentColor" viewBox="0 0 20 20">
                      <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
                    </svg>
                    {issue}
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Models */}
          <div className="card p-6">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-sm font-medium text-gray-500">AI Models</h3>
              <span className="text-2xl font-bold text-gray-900">{models.total}</span>
            </div>
            <div className="space-y-2">
              {Object.entries(models.by_lifecycle).map(([stage, count]) => (
                <div key={stage} className="flex items-center justify-between text-sm">
                  <span className="text-gray-600 capitalize">{stage}</span>
                  <span className="font-medium">{count}</span>
                </div>
              ))}
            </div>
            <div className="mt-3 pt-3 border-t border-gray-100">
              <div className="flex items-center justify-between text-sm">
                <span className="text-gray-500">Avg Risk Score</span>
                <RiskBadge score={models.average_risk_score} />
              </div>
            </div>
          </div>

          {/* Incidents */}
          <div className="card p-6">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-sm font-medium text-gray-500">Open Incidents</h3>
              <span className={`text-2xl font-bold ${incidents.open > 0 ? 'text-red-600' : 'text-green-600'}`}>
                {incidents.open}
              </span>
            </div>
            <div className="space-y-2">
              {Object.entries(incidents.by_severity).map(([sev, count]) => (
                <div key={sev} className="flex items-center justify-between text-sm">
                  <SeverityLabel severity={sev} />
                  <span className="font-medium">{count}</span>
                </div>
              ))}
            </div>
            {incidents.critical_open > 0 && (
              <div className="mt-3 pt-3 border-t border-gray-100">
                <div className="text-xs text-red-600 font-medium">
                  {incidents.critical_open} critical incident(s) need attention
                </div>
              </div>
            )}
          </div>

          {/* Policies */}
          <div className="card p-6">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-sm font-medium text-gray-500">Active Policies</h3>
              <span className="text-2xl font-bold text-gray-900">{policies.active_policies}</span>
            </div>
            <div className="space-y-2">
              {policies.policies.map((p) => (
                <div key={p.id} className="flex items-center justify-between text-sm">
                  <span className="text-gray-600 truncate mr-2">{p.name}</span>
                  <span className="badge-blue">{p.rules} rules</span>
                </div>
              ))}
            </div>
            <div className="mt-3 pt-3 border-t border-gray-100">
              <div className="flex items-center justify-between text-sm">
                <span className="text-gray-500">Total Rules</span>
                <span className="font-medium">{policies.total_rules}</span>
              </div>
            </div>
          </div>
        </div>

        {/* Recent Incidents */}
        {incidents.recent && incidents.recent.length > 0 && (
          <div className="card">
            <div className="px-6 py-4 border-b border-gray-100">
              <h3 className="font-semibold text-gray-900">Recent Incidents</h3>
            </div>
            <div className="divide-y divide-gray-100">
              {incidents.recent.map((inc) => (
                <div key={inc.id} className="px-6 py-3 flex items-center gap-4">
                  <SeverityDot severity={inc.severity} />
                  <div className="flex-1 min-w-0">
                    <div className="text-sm font-medium text-gray-900 truncate">{inc.title}</div>
                    <div className="text-xs text-gray-500">
                      {inc.created_at ? new Date(inc.created_at).toLocaleDateString() : 'N/A'}
                    </div>
                  </div>
                  <StatusBadge status={inc.status} />
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Quick Actions */}
        <div className="card">
          <div className="px-6 py-4 border-b border-gray-100">
            <h3 className="font-semibold text-gray-900">Quick Actions</h3>
          </div>
          <div className="p-6 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
            {(quick_actions || []).map((qa, i) => (
              <button
                key={i}
                onClick={() => {
                  if (qa.endpoint.includes('/scan')) navigate('/scan');
                  else if (qa.endpoint.includes('/models')) navigate('/models');
                }}
                className="text-left p-4 rounded-lg border border-gray-200 hover:border-brand-blue hover:bg-blue-50 transition-colors group"
              >
                <div className="text-sm font-medium text-gray-900 group-hover:text-brand-blue">
                  {qa.action}
                </div>
                <div className="text-xs text-gray-400 mt-1 font-mono">{qa.endpoint}</div>
                {qa.priority === 'high' && (
                  <span className="badge-red mt-2">High Priority</span>
                )}
              </button>
            ))}
          </div>
        </div>
      </div>
    </Layout>
  );
}

function RiskBadge({ score }) {
  let cls = 'badge-green';
  if (score > 70) cls = 'badge-red';
  else if (score > 40) cls = 'badge-amber';
  return <span className={cls}>{score}</span>;
}

function SeverityLabel({ severity }) {
  const colors = {
    critical: 'text-red-700',
    high: 'text-orange-600',
    medium: 'text-amber-600',
    low: 'text-green-600',
  };
  return (
    <span className={`text-sm capitalize ${colors[severity] || 'text-gray-600'}`}>
      {severity}
    </span>
  );
}

function SeverityDot({ severity }) {
  const colors = {
    critical: 'bg-red-500',
    high: 'bg-orange-500',
    medium: 'bg-amber-500',
    low: 'bg-green-500',
  };
  return <div className={`w-2.5 h-2.5 rounded-full shrink-0 ${colors[severity] || 'bg-gray-400'}`} />;
}

function StatusBadge({ status }) {
  const map = {
    open: 'badge-red',
    investigating: 'badge-amber',
    resolved: 'badge-green',
    closed: 'badge-gray',
  };
  return <span className={map[status] || 'badge-gray'}>{status}</span>;
}
