import { useState, useEffect, useMemo } from 'react';
import Layout from '../components/Layout';
import Spinner from '../components/Spinner';
import ErrorBanner from '../components/ErrorBanner';
import api from '../api';

// Category mapping for the 29 frameworks
const CATEGORIES = {
  'AI Governance': ['NIST_AI_RMF', 'EU_AI_ACT', 'ISO_42001', 'IEEE_ETHICS', 'OECD_AI', 'UNESCO_AI', 'US_EO_AI'],
  'Regional AI': ['SINGAPORE_AI', 'UK_AI', 'CANADA_AIDA', 'CHINA_AI'],
  'Cybersecurity': ['NIST_CSF', 'MITRE_ATLAS', 'OWASP_AI', 'ZERO_TRUST', 'CIS_CONTROLS', 'CSA_AI'],
  'Privacy & Data': ['GDPR', 'CCPA', 'HIPAA'],
  'Compliance': ['SOC2', 'ISO_27001', 'NIS2', 'DORA', 'COBIT', 'ITIL'],
  'Risk & Digital': ['FAIR_RISK', 'DSA', 'DMA'],
};

// Descriptions for each framework
const DESCRIPTIONS = {
  NIST_AI_RMF: 'AI Risk Management Framework by NIST for trustworthy AI systems',
  EU_AI_ACT: 'European Union regulation on artificial intelligence',
  ISO_42001: 'AI Management System standard for responsible AI',
  ISO_27001: 'Information security management system standard',
  NIS2: 'EU directive on network and information systems security',
  DORA: 'Digital Operational Resilience Act for financial entities',
  MITRE_ATLAS: 'Adversarial threat landscape for AI systems',
  OWASP_AI: 'Open Web Application Security Project AI security guidelines',
  SOC2: 'Service Organization Control 2 trust service criteria',
  GDPR: 'General Data Protection Regulation (EU)',
  CCPA: 'California Consumer Privacy Act',
  HIPAA: 'Health Insurance Portability and Accountability Act',
  IEEE_ETHICS: 'IEEE standards for ethically aligned design of autonomous systems',
  OECD_AI: 'OECD principles on artificial intelligence',
  NIST_CSF: 'NIST Cybersecurity Framework',
  UNESCO_AI: 'UNESCO recommendation on ethics of AI',
  SINGAPORE_AI: 'Singapore Model AI Governance Framework',
  UK_AI: 'UK AI regulation framework and principles',
  CANADA_AIDA: 'Artificial Intelligence and Data Act (Canada)',
  CHINA_AI: 'China AI governance and algorithmic regulation',
  COBIT: 'Control Objectives for Information Technologies',
  ITIL: 'IT Infrastructure Library best practices',
  ZERO_TRUST: 'Zero Trust security architecture framework',
  CIS_CONTROLS: 'Center for Internet Security critical security controls',
  FAIR_RISK: 'Factor Analysis of Information Risk quantitative model',
  CSA_AI: 'Cloud Security Alliance AI safety guidelines',
  US_EO_AI: 'US Executive Order on Safe, Secure, and Trustworthy AI',
  DSA: 'Digital Services Act (EU)',
  DMA: 'Digital Markets Act (EU)',
};

const CATEGORY_COLORS = {
  'AI Governance': { bg: 'bg-blue-50', text: 'text-blue-700', border: 'border-blue-200', tag: 'bg-blue-100 text-blue-700' },
  'Regional AI': { bg: 'bg-purple-50', text: 'text-purple-700', border: 'border-purple-200', tag: 'bg-purple-100 text-purple-700' },
  'Cybersecurity': { bg: 'bg-red-50', text: 'text-red-700', border: 'border-red-200', tag: 'bg-red-100 text-red-700' },
  'Privacy & Data': { bg: 'bg-green-50', text: 'text-green-700', border: 'border-green-200', tag: 'bg-green-100 text-green-700' },
  'Compliance': { bg: 'bg-amber-50', text: 'text-amber-700', border: 'border-amber-200', tag: 'bg-amber-100 text-amber-700' },
  'Risk & Digital': { bg: 'bg-teal-50', text: 'text-teal-700', border: 'border-teal-200', tag: 'bg-teal-100 text-teal-700' },
};

function getCategory(framework) {
  for (const [cat, items] of Object.entries(CATEGORIES)) {
    if (items.includes(framework)) return cat;
  }
  return 'Other';
}

export default function Frameworks() {
  const [frameworks, setFrameworks] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [search, setSearch] = useState('');
  const [activeCategory, setActiveCategory] = useState('All');

  async function load() {
    setLoading(true);
    setError('');
    try {
      const res = await api.getFrameworks();
      setFrameworks(res.frameworks || []);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { load(); }, []);

  const categories = useMemo(() => {
    const cats = new Set(['All']);
    frameworks.forEach((f) => cats.add(getCategory(f)));
    return Array.from(cats);
  }, [frameworks]);

  const filtered = useMemo(() => {
    return frameworks.filter((f) => {
      const matchSearch =
        f.toLowerCase().includes(search.toLowerCase()) ||
        (DESCRIPTIONS[f] || '').toLowerCase().includes(search.toLowerCase());
      const matchCategory = activeCategory === 'All' || getCategory(f) === activeCategory;
      return matchSearch && matchCategory;
    });
  }, [frameworks, search, activeCategory]);

  return (
    <Layout title="Governance Frameworks" breadcrumb="Home / Frameworks">
      <div className="space-y-4">
        {/* Search + filter */}
        <div className="flex flex-col sm:flex-row items-start sm:items-center gap-3">
          <div className="relative flex-1 max-w-md">
            <svg className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
            </svg>
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="input pl-10"
              placeholder="Search frameworks..."
            />
          </div>
          <span className="text-sm text-gray-500">
            {filtered.length} of {frameworks.length} frameworks
          </span>
        </div>

        {/* Category tabs */}
        <div className="flex flex-wrap gap-2">
          {categories.map((cat) => (
            <button
              key={cat}
              onClick={() => setActiveCategory(cat)}
              className={`
                px-3 py-1.5 rounded-lg text-sm font-medium transition-colors
                ${activeCategory === cat
                  ? 'bg-brand-blue text-white'
                  : 'bg-gray-100 text-gray-600 hover:bg-gray-200'}
              `}
            >
              {cat}
            </button>
          ))}
        </div>

        {loading && <Spinner className="py-20" />}
        {error && <ErrorBanner message={error} onRetry={load} />}

        {!loading && !error && (
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
            {filtered.length === 0 ? (
              <div className="col-span-full text-center text-sm text-gray-500 py-12">
                No frameworks match your search.
              </div>
            ) : (
              filtered.map((f) => {
                const cat = getCategory(f);
                const colors = CATEGORY_COLORS[cat] || CATEGORY_COLORS['Risk & Digital'];
                return (
                  <div
                    key={f}
                    className={`card p-5 border ${colors.border} hover:shadow-md transition-shadow`}
                  >
                    <div className="flex items-start justify-between gap-2 mb-2">
                      <h3 className="font-semibold text-gray-900 text-sm">
                        {f.replace(/_/g, ' ')}
                      </h3>
                      <span className={`badge ${colors.tag} shrink-0`}>
                        {cat}
                      </span>
                    </div>
                    <p className="text-xs text-gray-500 leading-relaxed">
                      {DESCRIPTIONS[f] || 'Governance framework for AI systems.'}
                    </p>
                  </div>
                );
              })
            )}
          </div>
        )}
      </div>
    </Layout>
  );
}
