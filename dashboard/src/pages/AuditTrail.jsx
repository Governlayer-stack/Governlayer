import { useState, useEffect } from 'react';
import Layout from '../components/Layout';
import Spinner from '../components/Spinner';
import ErrorBanner from '../components/ErrorBanner';
import api from '../api';

export default function AuditTrail() {
  const [ledger, setLedger] = useState([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [pages, setPages] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [chainValid, setChainValid] = useState(null);
  const [verifying, setVerifying] = useState(false);

  async function load(p = 1) {
    setLoading(true);
    setError('');
    try {
      const res = await api.getLedger(p, 20);
      setLedger(res.ledger || []);
      setTotal(res.total_records || 0);
      setPages(res.pages || 0);
      setPage(p);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  async function verifyChain() {
    setVerifying(true);
    try {
      const res = await api.verifyChain();
      setChainValid(res.valid);
    } catch (err) {
      setChainValid(false);
    } finally {
      setVerifying(false);
    }
  }

  useEffect(() => { load(); }, []);

  return (
    <Layout title="Audit Trail" breadcrumb="Home / Audit Trail">
      <div className="space-y-4">
        {/* Header bar */}
        <div className="flex flex-wrap items-center gap-3 justify-between">
          <div className="flex items-center gap-3">
            <span className="text-sm text-gray-500">{total} ledger entries</span>
            {chainValid !== null && (
              <span className={chainValid ? 'badge-green' : 'badge-red'}>
                Chain {chainValid ? 'Valid' : 'Broken'}
              </span>
            )}
          </div>
          <button
            onClick={verifyChain}
            disabled={verifying}
            className="btn-secondary text-sm flex items-center gap-2"
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
            </svg>
            {verifying ? 'Verifying...' : 'Verify Chain Integrity'}
          </button>
        </div>

        {error && <ErrorBanner message={error} onRetry={() => load(page)} />}
        {loading && <Spinner className="py-20" />}

        {!loading && !error && (
          <>
            {/* Timeline */}
            <div className="space-y-0">
              {ledger.length === 0 ? (
                <div className="card p-12 text-center text-sm text-gray-500">
                  No audit entries yet. Run a governance scan to create the first entry.
                </div>
              ) : (
                ledger.map((entry, idx) => (
                  <div key={entry.id || idx} className="flex gap-4">
                    {/* Timeline connector */}
                    <div className="flex flex-col items-center">
                      <div className={`w-3 h-3 rounded-full shrink-0 mt-5 ${actionColor(entry.governance_action)}`} />
                      {idx < ledger.length - 1 && (
                        <div className="w-px flex-1 bg-gray-200" />
                      )}
                    </div>

                    {/* Entry card */}
                    <div className="card p-4 mb-3 flex-1">
                      <div className="flex flex-wrap items-start justify-between gap-2 mb-2">
                        <div className="flex items-center gap-2">
                          <ActionBadge action={entry.governance_action} />
                          <span className="text-sm font-medium text-gray-900">
                            {entry.system_name}
                          </span>
                        </div>
                        <time className="text-xs text-gray-400">
                          {entry.created_at ? new Date(entry.created_at).toLocaleString() : 'N/A'}
                        </time>
                      </div>

                      <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-gray-500 mb-2">
                        <span>Risk: <strong className="text-gray-700">{entry.risk_level || 'N/A'}</strong></span>
                        <span>Score: <strong className="text-gray-700">{entry.risk_score != null ? Math.round(entry.risk_score) : 'N/A'}</strong></span>
                        <span>Policy: <strong className="text-gray-700">{entry.policy_version || '-'}</strong></span>
                        <span>ID: <strong className="text-gray-700 font-mono">{(entry.decision_id || '').slice(0, 8)}</strong></span>
                      </div>

                      {/* Hash chain display */}
                      <div className="bg-gray-50 rounded-lg p-3 space-y-1.5">
                        <HashRow label="Current Hash" hash={entry.current_hash} />
                        <HashRow label="Previous Hash" hash={entry.previous_hash} />
                      </div>
                    </div>
                  </div>
                ))
              )}
            </div>

            {/* Pagination */}
            {pages > 1 && (
              <div className="flex items-center justify-center gap-2 pt-2">
                <button
                  onClick={() => load(page - 1)}
                  disabled={page <= 1}
                  className="btn-secondary text-sm"
                >
                  Previous
                </button>
                <span className="text-sm text-gray-500">
                  Page {page} of {pages}
                </span>
                <button
                  onClick={() => load(page + 1)}
                  disabled={page >= pages}
                  className="btn-secondary text-sm"
                >
                  Next
                </button>
              </div>
            )}
          </>
        )}
      </div>
    </Layout>
  );
}

function ActionBadge({ action }) {
  const map = {
    APPROVE: 'badge-green',
    BLOCK: 'badge-red',
    ESCALATE_HUMAN: 'badge-amber',
    AUDIT_COMPLETE: 'badge-blue',
  };
  return <span className={map[action] || 'badge-gray'}>{action || 'UNKNOWN'}</span>;
}

function actionColor(action) {
  const map = {
    APPROVE: 'bg-green-500',
    BLOCK: 'bg-red-500',
    ESCALATE_HUMAN: 'bg-amber-500',
    AUDIT_COMPLETE: 'bg-blue-500',
  };
  return map[action] || 'bg-gray-400';
}

function HashRow({ label, hash }) {
  if (!hash) return null;
  return (
    <div className="flex items-start gap-2">
      <span className="text-xs text-gray-400 w-28 shrink-0">{label}</span>
      <code className="text-xs text-gray-600 font-mono break-all leading-relaxed">
        {hash}
      </code>
    </div>
  );
}
