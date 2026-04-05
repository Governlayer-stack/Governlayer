import { useState, useEffect } from 'react';
import Layout from '../components/Layout';
import Spinner from '../components/Spinner';
import ErrorBanner from '../components/ErrorBanner';
import api from '../api';

export default function Models() {
  const [models, setModels] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [search, setSearch] = useState('');

  async function load() {
    setLoading(true);
    setError('');
    try {
      const res = await api.getModels();
      setModels(res.models || res || []);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { load(); }, []);

  const filtered = models.filter((m) =>
    (m.name || '').toLowerCase().includes(search.toLowerCase()) ||
    (m.owner || '').toLowerCase().includes(search.toLowerCase()) ||
    (m.use_case || '').toLowerCase().includes(search.toLowerCase())
  );

  return (
    <Layout title="AI Models" breadcrumb="Home / Models">
      <div className="space-y-4">
        {/* Search */}
        <div className="flex items-center gap-3">
          <div className="relative flex-1 max-w-md">
            <svg className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
            </svg>
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="input pl-10"
              placeholder="Search models..."
            />
          </div>
          <span className="text-sm text-gray-500">
            {filtered.length} model{filtered.length !== 1 ? 's' : ''}
          </span>
        </div>

        {loading && <Spinner className="py-20" />}
        {error && <ErrorBanner message={error} onRetry={load} />}

        {!loading && !error && (
          <div className="card overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="bg-gray-50 border-b border-gray-200">
                    <th className="text-left text-xs font-medium text-gray-500 uppercase tracking-wider px-6 py-3">Model</th>
                    <th className="text-left text-xs font-medium text-gray-500 uppercase tracking-wider px-6 py-3">Version</th>
                    <th className="text-left text-xs font-medium text-gray-500 uppercase tracking-wider px-6 py-3">Lifecycle</th>
                    <th className="text-left text-xs font-medium text-gray-500 uppercase tracking-wider px-6 py-3">Governance</th>
                    <th className="text-left text-xs font-medium text-gray-500 uppercase tracking-wider px-6 py-3">Risk Score</th>
                    <th className="text-left text-xs font-medium text-gray-500 uppercase tracking-wider px-6 py-3">Owner</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-100">
                  {filtered.length === 0 ? (
                    <tr>
                      <td colSpan={6} className="px-6 py-12 text-center text-sm text-gray-500">
                        {search ? 'No models match your search' : 'No models registered yet'}
                      </td>
                    </tr>
                  ) : (
                    filtered.map((m) => (
                      <tr key={m.id || m.name} className="hover:bg-gray-50 transition-colors">
                        <td className="px-6 py-4">
                          <div className="text-sm font-medium text-gray-900">{m.name}</div>
                          {m.description && (
                            <div className="text-xs text-gray-500 mt-0.5 truncate max-w-xs">{m.description}</div>
                          )}
                        </td>
                        <td className="px-6 py-4 text-sm text-gray-600 font-mono">{m.version || '-'}</td>
                        <td className="px-6 py-4">
                          <LifecycleBadge lifecycle={m.lifecycle} />
                        </td>
                        <td className="px-6 py-4">
                          <GovernanceBadge status={m.governance_status} />
                        </td>
                        <td className="px-6 py-4">
                          <RiskIndicator score={m.risk_score} />
                        </td>
                        <td className="px-6 py-4 text-sm text-gray-600 truncate max-w-[200px]">
                          {m.owner || '-'}
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </Layout>
  );
}

function LifecycleBadge({ lifecycle }) {
  const val = typeof lifecycle === 'string' ? lifecycle : lifecycle?.value || lifecycle || 'unknown';
  const map = {
    production: 'badge-green',
    staging: 'badge-amber',
    development: 'badge-blue',
    retired: 'badge-gray',
    archived: 'badge-gray',
  };
  return <span className={map[val] || 'badge-gray'}>{val}</span>;
}

function GovernanceBadge({ status }) {
  const map = {
    compliant: 'badge-green',
    pending: 'badge-amber',
    non_compliant: 'badge-red',
  };
  return <span className={map[status] || 'badge-gray'}>{(status || 'unknown').replace('_', ' ')}</span>;
}

function RiskIndicator({ score }) {
  if (score == null) return <span className="text-sm text-gray-400">N/A</span>;

  let color = 'text-green-600';
  let bg = 'bg-green-500';
  if (score > 70) { color = 'text-red-600'; bg = 'bg-red-500'; }
  else if (score > 40) { color = 'text-amber-600'; bg = 'bg-amber-500'; }

  const width = Math.min(100, Math.max(0, score));

  return (
    <div className="flex items-center gap-2">
      <div className="w-16 h-1.5 bg-gray-200 rounded-full overflow-hidden">
        <div className={`h-full rounded-full ${bg}`} style={{ width: `${width}%` }} />
      </div>
      <span className={`text-sm font-medium ${color}`}>{score}</span>
    </div>
  );
}
