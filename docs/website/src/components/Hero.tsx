import { Button } from '@/components/Button'
import { Container } from '@/components/Container'

const frameworks = [
  'SOC 2',
  'GDPR',
  'ISO 27001',
  'EU AI Act',
  'HIPAA',
  'NIST AI RMF',
  'NIST CSF',
  'ISO 42001',
  'PCI DSS',
  'NIS2',
  'DORA',
  'CCPA',
]

export function Hero() {
  return (
    <Container className="pt-20 pb-16 text-center lg:pt-32">
      <div className="mx-auto mb-8 flex justify-center">
        <div className="rounded-full bg-emerald-50 px-4 py-1.5 text-sm font-medium text-emerald-700 ring-1 ring-emerald-600/20">
          Trusted by enterprises governing 10,000+ AI agents
        </div>
      </div>
      <h1 className="mx-auto max-w-5xl font-display text-5xl font-medium tracking-tight text-slate-900 sm:text-7xl">
        The governance layer{' '}
        <span className="relative whitespace-nowrap text-emerald-600">
          <svg
            aria-hidden="true"
            viewBox="0 0 418 42"
            className="absolute top-2/3 left-0 h-[0.58em] w-full fill-emerald-300/70"
            preserveAspectRatio="none"
          >
            <path d="M203.371.916c-26.013-2.078-76.686 1.963-124.73 9.946L67.3 12.749C35.421 18.062 18.2 21.766 6.004 25.934 1.244 27.561.828 27.778.874 28.61c.07 1.214.828 1.121 9.595-1.176 9.072-2.377 17.15-3.92 39.246-7.496C123.565 7.986 157.869 4.492 195.942 5.046c7.461.108 19.25 1.696 19.17 2.582-.107 1.183-7.874 4.31-25.75 10.366-21.992 7.45-35.43 12.534-36.701 13.884-2.173 2.308-.202 4.407 4.442 4.734 2.654.187 3.263.157 15.593-.78 35.401-2.686 57.944-3.488 88.365-3.143 46.327.526 75.721 2.23 130.788 7.584 19.787 1.924 20.814 1.98 24.557 1.332l.066-.011c1.201-.203 1.53-1.825.399-2.335-2.911-1.31-4.893-1.604-22.048-3.261-57.509-5.556-87.871-7.36-132.059-7.842-23.239-.254-33.617-.116-50.627.674-11.629.54-42.371 2.494-46.696 2.967-2.359.259 8.133-3.625 26.504-9.81 23.239-7.825 27.934-10.149 28.304-14.005.417-4.348-3.529-6-16.878-7.066Z" />
          </svg>
          <span className="relative">for agentic AI</span>
        </span>
      </h1>
      <p className="mx-auto mt-6 max-w-2xl text-lg tracking-tight text-slate-700">
        Autonomous compliance auditing, behavioral drift detection, risk scoring,
        and immutable audit ledgers. Ship AI agents with confidence — GovernLayer
        ensures they stay safe, compliant, and accountable.
      </p>
      <div className="mt-10 flex justify-center gap-x-6">
        <Button href="/register">Start free trial</Button>
        <Button href="#features" variant="outline">
          <svg
            aria-hidden="true"
            className="h-3 w-3 flex-none fill-emerald-600 group-active:fill-current"
          >
            <path d="m9.997 6.91-7.583 3.447A1 1 0 0 1 1 9.447V2.553a1 1 0 0 1 1.414-.91L9.997 5.09c.782.355.782 1.465 0 1.82Z" />
          </svg>
          <span className="ml-3">See how it works</span>
        </Button>
      </div>

      {/* Live API Preview */}
      <div className="mx-auto mt-20 max-w-3xl">
        <div className="overflow-hidden rounded-2xl bg-slate-900 shadow-2xl ring-1 ring-white/10">
          <div className="flex items-center gap-2 border-b border-slate-700/50 px-4 py-3">
            <div className="h-3 w-3 rounded-full bg-red-500/80" />
            <div className="h-3 w-3 rounded-full bg-yellow-500/80" />
            <div className="h-3 w-3 rounded-full bg-green-500/80" />
            <span className="ml-2 text-xs text-slate-500">POST /v1/govern</span>
          </div>
          <div className="p-6 text-left">
            <pre className="text-sm leading-relaxed">
              <code>
                <span className="text-slate-500">{'// One API call. Full governance pipeline.'}</span>
                {'\n'}
                <span className="text-emerald-400">{'{'}</span>
                {'\n'}
                <span className="text-slate-300">{'  "system_name"'}</span>
                <span className="text-slate-500">{': '}</span>
                <span className="text-amber-300">{'"customer-support-agent"'}</span>
                <span className="text-slate-500">{','}</span>
                {'\n'}
                <span className="text-slate-300">{'  "behavior"'}</span>
                <span className="text-slate-500">{': '}</span>
                <span className="text-amber-300">{'"Offered 50% discount without authorization"'}</span>
                <span className="text-slate-500">{','}</span>
                {'\n'}
                <span className="text-slate-300">{'  "framework"'}</span>
                <span className="text-slate-500">{': '}</span>
                <span className="text-amber-300">{'"SOC2"'}</span>
                {'\n'}
                <span className="text-emerald-400">{'}'}</span>
                {'\n\n'}
                <span className="text-slate-500">{'// Response: drift detected, risk scored, decision logged'}</span>
                {'\n'}
                <span className="text-emerald-400">{'{'}</span>
                {'\n'}
                <span className="text-slate-300">{'  "drift_score"'}</span>
                <span className="text-slate-500">{': '}</span>
                <span className="text-red-400">{'0.87'}</span>
                <span className="text-slate-500">{','}</span>
                {'\n'}
                <span className="text-slate-300">{'  "risk_level"'}</span>
                <span className="text-slate-500">{': '}</span>
                <span className="text-amber-300">{'"HIGH"'}</span>
                <span className="text-slate-500">{','}</span>
                {'\n'}
                <span className="text-slate-300">{'  "decision"'}</span>
                <span className="text-slate-500">{': '}</span>
                <span className="text-amber-300">{'"ESCALATE — behavioral drift exceeds threshold"'}</span>
                <span className="text-slate-500">{','}</span>
                {'\n'}
                <span className="text-slate-300">{'  "ledger_hash"'}</span>
                <span className="text-slate-500">{': '}</span>
                <span className="text-amber-300">{'"sha256:a1b2c3..."'}</span>
                {'\n'}
                <span className="text-emerald-400">{'}'}</span>
              </code>
            </pre>
          </div>
        </div>
      </div>

      {/* Framework badges */}
      <div className="mt-20 lg:mt-24">
        <p className="font-display text-base text-slate-900">
          14 compliance frameworks. One platform.
        </p>
        <div className="mt-8 flex flex-wrap items-center justify-center gap-3">
          {frameworks.map((fw) => (
            <span
              key={fw}
              className="rounded-full bg-slate-100 px-4 py-1.5 text-sm font-medium text-slate-700 ring-1 ring-slate-200"
            >
              {fw}
            </span>
          ))}
        </div>
      </div>
    </Container>
  )
}
