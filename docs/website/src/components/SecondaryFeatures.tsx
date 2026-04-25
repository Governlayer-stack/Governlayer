'use client'

import { useId } from 'react'
import { Tab, TabGroup, TabList, TabPanel, TabPanels } from '@headlessui/react'
import clsx from 'clsx'

import { Container } from '@/components/Container'

interface Feature {
  name: React.ReactNode
  summary: string
  description: string
  icon: React.ComponentType
}

const features: Array<Feature> = [
  {
    name: 'Multi-LLM Consensus',
    summary: 'Eliminate hallucination risk with multi-model verification.',
    description:
      'Three hallucination-resistance strategies: Voting (3+ models must agree), Chain-of-Verification (generate, question, verify, synthesize), and Adversarial Debate (claim, critique, judge). Critical decisions never rely on a single model.',
    icon: function ConsensusIcon() {
      let id = useId()
      return (
        <>
          <defs>
            <linearGradient id={id} x1="11.5" y1={18} x2={36} y2="15.5" gradientUnits="userSpaceOnUse">
              <stop offset=".194" stopColor="#fff" />
              <stop offset={1} stopColor="#34D399" />
            </linearGradient>
          </defs>
          <circle cx={12} cy={12} r={3} fill={`url(#${id})`} opacity={0.8} />
          <circle cx={24} cy={12} r={3} fill={`url(#${id})`} opacity={0.8} />
          <circle cx={18} cy={24} r={3} fill={`url(#${id})`} opacity={0.8} />
          <path d="M14 13l3 8M22 13l-3 8M14 12h8" stroke={`url(#${id})`} strokeWidth={1.5} strokeLinecap="round" />
        </>
      )
    },
  },
  {
    name: 'Human-in-the-Loop',
    summary: 'Automatic escalation when AI confidence drops below threshold.',
    description:
      'LangGraph-powered state machine with conditional edges for escalation. When drift scores exceed limits or risk levels hit critical, decisions route to human reviewers. Full context preserved — reviewers see the complete reasoning chain.',
    icon: function HITLIcon() {
      return (
        <>
          <path opacity=".5" d="M8 17a1 1 0 0 1 1-1h18a1 1 0 0 1 1 1v2a1 1 0 0 1-1 1H9a1 1 0 0 1-1-1v-2Z" fill="#fff" />
          <circle cx={18} cy={10} r={5} fill="#fff" opacity={0.9} />
          <path d="M16 10l1.5 1.5L21 8" stroke="#059669" strokeWidth={1.5} strokeLinecap="round" strokeLinejoin="round" />
          <path opacity=".3" d="M8 24a1 1 0 0 1 1-1h18a1 1 0 0 1 1 1v2a1 1 0 0 1-1 1H9a1 1 0 0 1-1-1v-2Z" fill="#fff" />
        </>
      )
    },
  },
  {
    name: 'Framework Library',
    summary: '14 compliance frameworks mapped and ready for assessment.',
    description:
      'SOC 2, GDPR, ISO 27001, EU AI Act, HIPAA, NIST AI RMF, NIST CSF, ISO 42001, PCI DSS, CCPA, NIS2, DORA, DSA, DMA — each with mapped controls, evidence requirements, and automated readiness scoring. New frameworks added quarterly.',
    icon: function FrameworkIcon() {
      return (
        <>
          <path opacity=".5" d="M25.778 25.778c.39.39 1.027.393 1.384-.028A11.952 11.952 0 0 0 30 18c0-6.627-5.373-12-12-12S6 11.373 6 18c0 2.954 1.067 5.659 2.838 7.75.357.421.993.419 1.384.028.39-.39.386-1.02.036-1.448A9.959 9.959 0 0 1 8 18c0-5.523 4.477-10 10-10s10 4.477 10 10a9.959 9.959 0 0 1-2.258 6.33c-.35.427-.354 1.058.036 1.448Z" fill="#fff" />
          <path d="M18 10v8l4 4" stroke="#fff" strokeWidth={2} strokeLinecap="round" fill="none" />
        </>
      )
    },
  },
]

function Feature({
  feature,
  isActive,
  className,
  ...props
}: React.ComponentPropsWithoutRef<'div'> & {
  feature: Feature
  isActive: boolean
}) {
  return (
    <div
      className={clsx(className, !isActive && 'opacity-75 hover:opacity-100')}
      {...props}
    >
      <div
        className={clsx(
          'w-9 rounded-lg',
          isActive ? 'bg-emerald-600' : 'bg-slate-500',
        )}
      >
        <svg aria-hidden="true" className="h-9 w-9" fill="none">
          <feature.icon />
        </svg>
      </div>
      <h3
        className={clsx(
          'mt-6 text-sm font-medium',
          isActive ? 'text-emerald-600' : 'text-slate-600',
        )}
      >
        {feature.name}
      </h3>
      <p className="mt-2 font-display text-xl text-slate-900">
        {feature.summary}
      </p>
      <p className="mt-4 text-sm text-slate-600">{feature.description}</p>
    </div>
  )
}

function FeaturesMobile() {
  return (
    <div className="-mx-4 mt-20 flex flex-col gap-y-10 overflow-hidden px-4 sm:-mx-6 sm:px-6 lg:hidden">
      {features.map((feature) => (
        <div key={feature.summary}>
          <Feature feature={feature} className="mx-auto max-w-2xl" isActive />
        </div>
      ))}
    </div>
  )
}

function FeaturesDesktop() {
  return (
    <TabGroup className="hidden lg:mt-20 lg:block">
      {({ selectedIndex }) => (
        <>
          <TabList className="grid grid-cols-3 gap-x-8">
            {features.map((feature, featureIndex) => (
              <Feature
                key={feature.summary}
                feature={{
                  ...feature,
                  name: (
                    <Tab className="data-selected:not-data-focus:outline-hidden">
                      <span className="absolute inset-0" />
                      {feature.name}
                    </Tab>
                  ),
                }}
                isActive={featureIndex === selectedIndex}
                className="relative"
              />
            ))}
          </TabList>
          <TabPanels className="relative mt-20 overflow-hidden rounded-4xl bg-slate-100 px-14 py-16 xl:px-16">
            <div className="-mx-5 flex">
              {features.map((feature, featureIndex) => (
                <TabPanel
                  static
                  key={feature.summary}
                  className={clsx(
                    'px-5 transition duration-500 ease-in-out data-selected:not-data-focus:outline-hidden',
                    featureIndex !== selectedIndex && 'opacity-60',
                  )}
                  style={{ transform: `translateX(-${selectedIndex * 100}%)` }}
                  aria-hidden={featureIndex !== selectedIndex}
                >
                  <div className="w-full overflow-hidden rounded-xl bg-white p-8 shadow-lg ring-1 shadow-slate-900/5 ring-slate-500/10">
                    {featureIndex === 0 && (
                      <div className="space-y-4">
                        <div className="flex items-center gap-3">
                          <div className="h-3 w-3 rounded-full bg-emerald-500" />
                          <span className="text-sm font-medium text-slate-900">Consensus Engine — Voting Mode</span>
                        </div>
                        <div className="grid grid-cols-3 gap-4">
                          {['Claude Opus', 'GPT-4o', 'Gemini Pro'].map((model) => (
                            <div key={model} className="rounded-lg bg-slate-50 p-4 text-center">
                              <div className="text-xs text-slate-500">{model}</div>
                              <div className="mt-2 text-lg font-bold text-emerald-600">APPROVE</div>
                            </div>
                          ))}
                        </div>
                        <div className="rounded-lg bg-emerald-50 p-3 text-center text-sm font-medium text-emerald-700">
                          Consensus: 3/3 models agree — APPROVED with high confidence
                        </div>
                      </div>
                    )}
                    {featureIndex === 1 && (
                      <div className="space-y-4">
                        <div className="flex items-center gap-3">
                          <div className="h-3 w-3 animate-pulse rounded-full bg-amber-500" />
                          <span className="text-sm font-medium text-slate-900">Escalation Pipeline</span>
                        </div>
                        <div className="flex items-center justify-between gap-2">
                          {['Drift Detected', 'Risk Scored', 'Threshold Exceeded', 'Human Review'].map((step, i) => (
                            <div key={step} className="flex items-center gap-2">
                              <div className={clsx(
                                'flex h-8 w-8 items-center justify-center rounded-full text-xs font-bold text-white',
                                i < 3 ? 'bg-emerald-500' : 'bg-amber-500',
                              )}>
                                {i < 3 ? '\u2713' : '!'}
                              </div>
                              <span className="text-xs text-slate-600">{step}</span>
                              {i < 3 && <span className="text-slate-300">&rarr;</span>}
                            </div>
                          ))}
                        </div>
                        <div className="rounded-lg bg-amber-50 p-3 text-sm text-amber-800">
                          <strong>Awaiting review:</strong> Agent &quot;pricing-bot&quot; offered unauthorized 70% discount. Drift score: 0.91.
                        </div>
                      </div>
                    )}
                    {featureIndex === 2 && (
                      <div className="space-y-3">
                        <div className="text-sm font-medium text-slate-900">Framework Coverage</div>
                        <div className="grid grid-cols-2 gap-2">
                          {[
                            { fw: 'SOC 2 Type II', pct: 92 },
                            { fw: 'GDPR', pct: 88 },
                            { fw: 'ISO 27001', pct: 76 },
                            { fw: 'EU AI Act', pct: 94 },
                            { fw: 'HIPAA', pct: 82 },
                            { fw: 'NIST AI RMF', pct: 71 },
                          ].map((f) => (
                            <div key={f.fw} className="rounded-lg bg-slate-50 p-3">
                              <div className="flex justify-between text-xs">
                                <span className="font-medium text-slate-700">{f.fw}</span>
                                <span className="text-emerald-600">{f.pct}%</span>
                              </div>
                              <div className="mt-2 h-1.5 rounded-full bg-slate-200">
                                <div className="h-1.5 rounded-full bg-emerald-500" style={{ width: `${f.pct}%` }} />
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                </TabPanel>
              ))}
            </div>
            <div className="pointer-events-none absolute inset-0 rounded-4xl ring-1 ring-slate-900/10 ring-inset" />
          </TabPanels>
        </>
      )}
    </TabGroup>
  )
}

export function SecondaryFeatures() {
  return (
    <section
      id="solutions"
      aria-label="Advanced governance capabilities"
      className="pt-20 pb-14 sm:pt-32 sm:pb-20 lg:pb-32"
    >
      <Container>
        <div className="mx-auto max-w-2xl md:text-center">
          <h2 className="font-display text-3xl tracking-tight text-slate-900 sm:text-4xl">
            Advanced capabilities for enterprise AI teams.
          </h2>
          <p className="mt-4 text-lg tracking-tight text-slate-700">
            Multi-LLM consensus, human-in-the-loop escalation, and the
            industry&apos;s most comprehensive framework library.
          </p>
        </div>
        <FeaturesMobile />
        <FeaturesDesktop />
      </Container>
    </section>
  )
}
