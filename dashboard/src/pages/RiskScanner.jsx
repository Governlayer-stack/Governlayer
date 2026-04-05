import { useState } from 'react';
import {
  RadarChart, PolarGrid, PolarAngleAxis, PolarRadiusAxis,
  Radar, ResponsiveContainer, Tooltip,
} from 'recharts';
import Layout from '../components/Layout';
import Spinner from '../components/Spinner';
import ErrorBanner from '../components/ErrorBanner';
import api from '../api';

const TOGGLES = [
  { key: 'handles_personal_data', label: 'Handles Personal Data', description: 'Processes PII or sensitive personal information' },
  { key: 'makes_autonomous_decisions', label: 'Makes Autonomous Decisions', description: 'Takes actions without human approval' },
  { key: 'used_in_critical_infrastructure', label: 'Critical Infrastructure', description: 'Used in healthcare, finance, or essential services' },
  { key: 'has_human_oversight', label: 'Has Human Oversight', description: 'Human review exists in the decision loop', defaultOn: true },
  { key: 'is_explainable', label: 'Is Explainable', description: 'Model outputs can be interpreted and explained', defaultOn: true },
  { key: 'has_bias_testing', label: 'Has Bias Testing', description: 'Regular fairness and bias audits are performed' },
];

export default function RiskScanner() {
  const [systemName, setSystemName] = useState('');
  const [toggles, setToggles] = useState(() => {
    const init = {};
    TOGGLES.forEach((t) => { init[t.key] = !!t.defaultOn; });
    return init;
  });
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  function handleToggle(key) {
    setToggles((prev) => ({ ...prev, [key]: !prev[key] }));
  }

  async function handleScan(e) {
    e.preventDefault();
    if (!systemName.trim()) return;

    setLoading(true);
    setError('');
    setResult(null);

    try {
      const res = await api.scoreRisk({
        system_name: systemName.trim(),
        ...toggles,
      });
      setResult(res);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  const radarData = result?.dimension_scores
    ? Object.entries(result.dimension_scores).map(([name, value]) => ({
        dimension: name.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase()),
        score: value,
        fullMark: 100,
      }))
    : [];

  return (
    <Layout title="Risk Scanner" breadcrumb="Home / Risk Scanner">
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Input form */}
        <div className="card p-6">
          <h2 className="font-semibold text-gray-900 mb-4">Configure Risk Assessment</h2>
          <form onSubmit={handleScan} className="space-y-5">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">System Name</label>
              <input
                type="text"
                value={systemName}
                onChange={(e) => setSystemName(e.target.value)}
                className="input"
                placeholder="e.g. loan-approval-v3"
                required
              />
            </div>

            <div className="space-y-3">
              <label className="block text-sm font-medium text-gray-700">Risk Dimensions</label>
              {TOGGLES.map((t) => (
                <div
                  key={t.key}
                  className="flex items-start gap-3 p-3 rounded-lg border border-gray-200 hover:border-gray-300 transition-colors cursor-pointer"
                  onClick={() => handleToggle(t.key)}
                >
                  <div className={`
                    w-10 h-6 rounded-full shrink-0 mt-0.5 flex items-center transition-colors
                    ${toggles[t.key] ? 'bg-brand-blue' : 'bg-gray-300'}
                  `}>
                    <div className={`
                      w-4 h-4 rounded-full bg-white shadow-sm transform transition-transform mx-1
                      ${toggles[t.key] ? 'translate-x-4' : 'translate-x-0'}
                    `} />
                  </div>
                  <div>
                    <div className="text-sm font-medium text-gray-900">{t.label}</div>
                    <div className="text-xs text-gray-500">{t.description}</div>
                  </div>
                </div>
              ))}
            </div>

            <button type="submit" disabled={loading || !systemName.trim()} className="btn-primary w-full">
              {loading ? 'Scanning...' : 'Run Risk Assessment'}
            </button>
          </form>
        </div>

        {/* Results */}
        <div className="space-y-4">
          {error && <ErrorBanner message={error} />}
          {loading && <Spinner className="py-20" />}

          {result && (
            <>
              {/* Score summary */}
              <div className="card p-6">
                <div className="flex items-center justify-between mb-4">
                  <h2 className="font-semibold text-gray-900">Risk Assessment</h2>
                  <RiskLevelBadge level={result.risk_level} />
                </div>

                <div className="flex items-center gap-4 mb-6">
                  <div className="text-5xl font-bold" style={{ color: riskColor(result.overall_score) }}>
                    {result.overall_score}
                  </div>
                  <div>
                    <div className="text-sm text-gray-500">Overall Score</div>
                    <div className="text-sm text-gray-700 font-medium">{result.system}</div>
                  </div>
                </div>

                {/* Risk bar */}
                <div className="h-3 bg-gray-100 rounded-full overflow-hidden">
                  <div
                    className="h-full rounded-full transition-all duration-500"
                    style={{
                      width: `${result.overall_score}%`,
                      backgroundColor: riskColor(result.overall_score),
                    }}
                  />
                </div>
                <div className="flex justify-between text-xs text-gray-400 mt-1">
                  <span>High Risk (0)</span>
                  <span>Low Risk (100)</span>
                </div>
              </div>

              {/* Radar chart */}
              <div className="card p-6">
                <h3 className="font-semibold text-gray-900 mb-4">6-Dimension Risk Radar</h3>
                <ResponsiveContainer width="100%" height={320}>
                  <RadarChart data={radarData} cx="50%" cy="50%" outerRadius="75%">
                    <PolarGrid stroke="#e5e7eb" />
                    <PolarAngleAxis
                      dataKey="dimension"
                      tick={{ fill: '#6b7280', fontSize: 11 }}
                    />
                    <PolarRadiusAxis
                      angle={30}
                      domain={[0, 100]}
                      tick={{ fill: '#9ca3af', fontSize: 10 }}
                    />
                    <Radar
                      name="Risk Score"
                      dataKey="score"
                      stroke="#2563eb"
                      fill="#2563eb"
                      fillOpacity={0.2}
                      strokeWidth={2}
                    />
                    <Tooltip
                      contentStyle={{
                        backgroundColor: '#fff',
                        border: '1px solid #e5e7eb',
                        borderRadius: '8px',
                        fontSize: '12px',
                      }}
                    />
                  </RadarChart>
                </ResponsiveContainer>
              </div>

              {/* Dimension breakdown */}
              <div className="card p-6">
                <h3 className="font-semibold text-gray-900 mb-4">Dimension Breakdown</h3>
                <div className="space-y-3">
                  {radarData.map((d) => (
                    <div key={d.dimension} className="flex items-center gap-3">
                      <span className="text-sm text-gray-600 w-32 shrink-0">{d.dimension}</span>
                      <div className="flex-1 h-2 bg-gray-100 rounded-full overflow-hidden">
                        <div
                          className="h-full rounded-full"
                          style={{
                            width: `${d.score}%`,
                            backgroundColor: riskColor(d.score),
                          }}
                        />
                      </div>
                      <span className="text-sm font-medium w-8 text-right" style={{ color: riskColor(d.score) }}>
                        {d.score}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            </>
          )}

          {!result && !loading && !error && (
            <div className="card p-12 text-center">
              <svg className="w-16 h-16 mx-auto text-gray-300 mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1}
                  d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
              </svg>
              <div className="text-sm text-gray-500">
                Configure the risk dimensions on the left and run an assessment to see results.
              </div>
            </div>
          )}
        </div>
      </div>
    </Layout>
  );
}

function RiskLevelBadge({ level }) {
  const map = { LOW: 'badge-green', MEDIUM: 'badge-amber', HIGH: 'badge-red' };
  return <span className={map[level] || 'badge-gray'}>{level}</span>;
}

function riskColor(score) {
  if (score >= 80) return '#059669';
  if (score >= 50) return '#d97706';
  return '#dc2626';
}
