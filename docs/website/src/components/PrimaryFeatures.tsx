'use client'

import { useEffect, useState } from 'react'
import { Tab, TabGroup, TabList, TabPanel, TabPanels } from '@headlessui/react'
import clsx from 'clsx'

import { Container } from '@/components/Container'

const features = [
  {
    title: 'Drift Detection',
    description:
      'Real-time behavioral monitoring using sentence-transformer embeddings. Detect when AI agents deviate from safety manifolds before damage occurs. Automatic alerting when drift scores exceed configurable thresholds.',
    icon: (
      <svg className="h-8 w-8" fill="none" viewBox="0 0 32 32" stroke="currentColor" strokeWidth={1.5}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M3 16h4l3-8 4 16 4-12 3 6h8" />
      </svg>
    ),
    preview: (
      <div className="rounded-xl bg-white/5 p-6 ring-1 ring-white/10">
        <div className="mb-4 flex items-center justify-between">
          <span className="text-sm font-medium text-white">Drift Analysis</span>
          <span className="rounded-full bg-red-500/20 px-3 py-1 text-xs font-medium text-red-300">HIGH DRIFT</span>
        </div>
        <div className="space-y-3">
          {[
            { agent: 'support-bot-v3', score: 0.87, status: 'critical' },
            { agent: 'pricing-agent', score: 0.34, status: 'normal' },
            { agent: 'onboard-flow', score: 0.62, status: 'warning' },
            { agent: 'data-pipeline', score: 0.12, status: 'normal' },
          ].map((item) => (
            <div key={item.agent} className="flex items-center gap-3">
              <div className="flex-1">
                <div className="flex justify-between text-xs">
                  <span className="text-slate-300">{item.agent}</span>
                  <span className={item.status === 'critical' ? 'text-red-400' : item.status === 'warning' ? 'text-amber-400' : 'text-emerald-400'}>
                    {item.score.toFixed(2)}
                  </span>
                </div>
                <div className="mt-1 h-1.5 rounded-full bg-white/10">
                  <div
                    className={clsx(
                      'h-1.5 rounded-full',
                      item.status === 'critical' ? 'bg-red-500' : item.status === 'warning' ? 'bg-amber-500' : 'bg-emerald-500',
                    )}
                    style={{ width: `${item.score * 100}%` }}
                  />
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    ),
  },
  {
    title: 'Risk Scoring',
    description:
      'Deterministic 6-dimension risk assessment across data sensitivity, autonomy level, decision impact, regulatory exposure, model complexity, and deployment scope. No LLM hallucination — pure algorithmic scoring.',
    icon: (
      <svg className="h-8 w-8" fill="none" viewBox="0 0 32 32" stroke="currentColor" strokeWidth={1.5}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v4m0 0v4m0-4h4m-4 0H8m13-4v8m0 0l2.5-2.5M21 17l-2.5-2.5M5 20h22M5 20l2-8h18l2 8" />
      </svg>
    ),
    preview: (
      <div className="rounded-xl bg-white/5 p-6 ring-1 ring-white/10">
        <div className="mb-4 flex items-center justify-between">
          <span className="text-sm font-medium text-white">Risk Assessment</span>
          <span className="rounded-full bg-amber-500/20 px-3 py-1 text-xs font-medium text-amber-300">SCORE: 72/100</span>
        </div>
        <div className="space-y-2.5">
          {[
            { dim: 'Data Sensitivity', val: 85 },
            { dim: 'Autonomy Level', val: 70 },
            { dim: 'Decision Impact', val: 90 },
            { dim: 'Regulatory Exposure', val: 65 },
            { dim: 'Model Complexity', val: 55 },
            { dim: 'Deployment Scope', val: 68 },
          ].map((d) => (
            <div key={d.dim} className="flex items-center gap-3">
              <span className="w-36 text-xs text-slate-400">{d.dim}</span>
              <div className="flex-1 h-2 rounded-full bg-white/10">
                <div
                  className={clsx('h-2 rounded-full', d.val > 80 ? 'bg-red-500' : d.val > 60 ? 'bg-amber-500' : 'bg-emerald-500')}
                  style={{ width: `${d.val}%` }}
                />
              </div>
              <span className="w-8 text-right text-xs text-slate-300">{d.val}</span>
            </div>
          ))}
        </div>
      </div>
    ),
  },
  {
    title: 'Compliance Hub',
    description:
      'Full GRC compliance management. Create programs, map controls to 14 frameworks, track evidence, manage policies with workflow approvals. Generate audit-ready reports with one click.',
    icon: (
      <svg className="h-8 w-8" fill="none" viewBox="0 0 32 32" stroke="currentColor" strokeWidth={1.5}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
      </svg>
    ),
    preview: (
      <div className="rounded-xl bg-white/5 p-6 ring-1 ring-white/10">
        <div className="mb-4 flex items-center justify-between">
          <span className="text-sm font-medium text-white">SOC 2 Type II Readiness</span>
          <span className="rounded-full bg-emerald-500/20 px-3 py-1 text-xs font-medium text-emerald-300">78% READY</span>
        </div>
        <div className="space-y-2">
          {[
            { ctrl: 'CC6.1 — Logical Access', status: 'pass' },
            { ctrl: 'CC6.2 — System Operations', status: 'pass' },
            { ctrl: 'CC6.3 — Change Management', status: 'warn' },
            { ctrl: 'CC7.1 — Risk Assessment', status: 'pass' },
            { ctrl: 'CC7.2 — Monitoring', status: 'fail' },
            { ctrl: 'CC8.1 — Incident Response', status: 'pass' },
          ].map((c) => (
            <div key={c.ctrl} className="flex items-center justify-between rounded-lg bg-white/5 px-3 py-2">
              <span className="text-xs text-slate-300">{c.ctrl}</span>
              <span className={clsx(
                'text-xs font-medium',
                c.status === 'pass' ? 'text-emerald-400' : c.status === 'warn' ? 'text-amber-400' : 'text-red-400',
              )}>
                {c.status === 'pass' ? 'IMPLEMENTED' : c.status === 'warn' ? 'IN PROGRESS' : 'GAP'}
              </span>
            </div>
          ))}
        </div>
      </div>
    ),
  },
  {
    title: 'Audit Ledger',
    description:
      'SHA-256 hash-chained immutable audit trail. Every governance decision is cryptographically linked to the previous record. Tamper-proof evidence for regulators, auditors, and legal teams.',
    icon: (
      <svg className="h-8 w-8" fill="none" viewBox="0 0 32 32" stroke="currentColor" strokeWidth={1.5}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M13 10V3L4 14h7v7l9-11h-7z" />
      </svg>
    ),
    preview: (
      <div className="rounded-xl bg-white/5 p-6 ring-1 ring-white/10">
        <div className="mb-4 flex items-center justify-between">
          <span className="text-sm font-medium text-white">Hash-Chained Ledger</span>
          <span className="rounded-full bg-blue-500/20 px-3 py-1 text-xs font-medium text-blue-300">VERIFIED</span>
        </div>
        <div className="space-y-2 font-mono text-xs">
          {[
            { id: '#1847', hash: 'a1b2c3d4...', action: 'ESCALATE', time: '2m ago' },
            { id: '#1846', hash: 'e5f6a7b8...', action: 'APPROVE', time: '4m ago' },
            { id: '#1845', hash: 'c9d0e1f2...', action: 'FLAG', time: '7m ago' },
            { id: '#1844', hash: '3a4b5c6d...', action: 'APPROVE', time: '12m ago' },
          ].map((entry) => (
            <div key={entry.id} className="flex items-center gap-3 rounded-lg bg-white/5 px-3 py-2">
              <span className="text-slate-500">{entry.id}</span>
              <span className="text-emerald-400">{entry.hash}</span>
              <span className={clsx(
                'rounded px-1.5 py-0.5 text-[10px] font-medium',
                entry.action === 'ESCALATE' ? 'bg-red-500/20 text-red-300' :
                entry.action === 'FLAG' ? 'bg-amber-500/20 text-amber-300' :
                'bg-emerald-500/20 text-emerald-300',
              )}>
                {entry.action}
              </span>
              <span className="ml-auto text-slate-500">{entry.time}</span>
            </div>
          ))}
          <div className="mt-2 text-center text-[10px] text-slate-500">
            Chain integrity: VALID | Genesis: SHA256(&quot;GOVERNLAYER_GENESIS&quot;)
          </div>
        </div>
      </div>
    ),
  },
]

export function PrimaryFeatures() {
  let [tabOrientation, setTabOrientation] = useState<'horizontal' | 'vertical'>(
    'horizontal',
  )

  useEffect(() => {
    let lgMediaQuery = window.matchMedia('(min-width: 1024px)')

    function onMediaQueryChange({ matches }: { matches: boolean }) {
      setTabOrientation(matches ? 'vertical' : 'horizontal')
    }

    onMediaQueryChange(lgMediaQuery)
    lgMediaQuery.addEventListener('change', onMediaQueryChange)

    return () => {
      lgMediaQuery.removeEventListener('change', onMediaQueryChange)
    }
  }, [])

  return (
    <section
      id="features"
      aria-label="GovernLayer platform features"
      className="relative overflow-hidden bg-slate-900 pt-20 pb-28 sm:py-32"
    >
      <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_top,_var(--tw-gradient-stops))] from-emerald-900/20 via-slate-900 to-slate-900" />
      <Container className="relative">
        <div className="max-w-2xl md:mx-auto md:text-center xl:max-w-none">
          <h2 className="font-display text-3xl tracking-tight text-white sm:text-4xl md:text-5xl">
            Everything you need to govern AI at scale.
          </h2>
          <p className="mt-6 text-lg tracking-tight text-slate-400">
            From real-time drift detection to immutable audit trails — a complete
            governance stack for autonomous AI systems.
          </p>
        </div>
        <TabGroup
          className="mt-16 grid grid-cols-1 items-center gap-y-2 pt-10 sm:gap-y-6 md:mt-20 lg:grid-cols-12 lg:pt-0"
          vertical={tabOrientation === 'vertical'}
        >
          {({ selectedIndex }) => (
            <>
              <div className="-mx-4 flex overflow-x-auto pb-4 sm:mx-0 sm:overflow-visible sm:pb-0 lg:col-span-5">
                <TabList className="relative z-10 flex gap-x-4 px-4 whitespace-nowrap sm:mx-auto sm:px-0 lg:mx-0 lg:block lg:gap-x-0 lg:gap-y-1 lg:whitespace-normal">
                  {features.map((feature, featureIndex) => (
                    <div
                      key={feature.title}
                      className={clsx(
                        'group relative rounded-full px-4 py-1 lg:rounded-l-xl lg:rounded-r-none lg:p-6',
                        selectedIndex === featureIndex
                          ? 'bg-white/10 lg:bg-white/10 lg:ring-1 lg:ring-white/10 lg:ring-inset'
                          : 'hover:bg-white/5 lg:hover:bg-white/5',
                      )}
                    >
                      <h3>
                        <Tab
                          className={clsx(
                            'font-display text-lg data-selected:not-data-focus:outline-hidden flex items-center gap-3',
                            selectedIndex === featureIndex
                              ? 'text-emerald-400'
                              : 'text-slate-400 hover:text-white',
                          )}
                        >
                          <span className="absolute inset-0 rounded-full lg:rounded-l-xl lg:rounded-r-none" />
                          <span className="hidden lg:inline">{feature.icon}</span>
                          {feature.title}
                        </Tab>
                      </h3>
                      <p
                        className={clsx(
                          'mt-2 hidden text-sm lg:block',
                          selectedIndex === featureIndex
                            ? 'text-slate-300'
                            : 'text-slate-500 group-hover:text-slate-400',
                        )}
                      >
                        {feature.description}
                      </p>
                    </div>
                  ))}
                </TabList>
              </div>
              <TabPanels className="lg:col-span-7">
                {features.map((feature) => (
                  <TabPanel key={feature.title} unmount={false}>
                    <div className="relative sm:px-6 lg:hidden">
                      <div className="absolute -inset-x-4 -top-26 -bottom-17 bg-white/5 ring-1 ring-white/10 ring-inset sm:inset-x-0 sm:rounded-t-xl" />
                      <p className="relative mx-auto max-w-2xl text-base text-slate-300 sm:text-center">
                        {feature.description}
                      </p>
                    </div>
                    <div className="mt-10 overflow-hidden rounded-xl bg-slate-800/50 shadow-xl shadow-emerald-900/10 ring-1 ring-white/10 sm:w-auto lg:mt-0 p-2">
                      {feature.preview}
                    </div>
                  </TabPanel>
                ))}
              </TabPanels>
            </>
          )}
        </TabGroup>
      </Container>
    </section>
  )
}
