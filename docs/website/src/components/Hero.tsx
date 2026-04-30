'use client'

import { motion } from 'framer-motion'
import Link from 'next/link'

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
    <section className="relative min-h-screen overflow-hidden bg-[#0A0A0F] pt-32 pb-20 sm:pt-40">
      {/* Grid pattern overlay */}
      <div
        className="pointer-events-none absolute inset-0"
        style={{
          backgroundImage:
            'linear-gradient(rgba(255,255,255,0.03) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,0.03) 1px, transparent 1px)',
          backgroundSize: '64px 64px',
        }}
      />

      {/* Animated gradient orb */}
      <div className="pointer-events-none absolute top-1/4 left-1/2 -translate-x-1/2 -translate-y-1/2">
        <div className="h-[600px] w-[800px] rounded-full bg-gradient-to-r from-emerald-600/20 via-cyan-600/20 to-blue-600/20 blur-3xl" />
      </div>

      {/* Content */}
      <div className="relative mx-auto max-w-7xl px-6 lg:px-8">
        <div className="mx-auto max-w-4xl text-center">
          {/* Badge */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0 }}
            className="mb-8 flex justify-center"
          >
            <div className="rounded-full border border-emerald-500/20 bg-emerald-500/10 px-4 py-1.5 text-sm font-medium text-emerald-400">
              Trusted by enterprises governing 10,000+ AI agents
            </div>
          </motion.div>

          {/* Headline */}
          <motion.h1
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.1 }}
            className="font-display text-6xl font-bold tracking-tighter text-white sm:text-8xl"
          >
            The governance layer{' '}
            <span className="bg-gradient-to-r from-emerald-400 to-cyan-400 bg-clip-text text-transparent">
              for agentic AI
            </span>
          </motion.h1>

          {/* Subheadline */}
          <motion.p
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.2 }}
            className="mx-auto mt-6 max-w-2xl text-lg text-zinc-400"
          >
            Autonomous compliance auditing, behavioral drift detection, risk scoring,
            and immutable audit ledgers. Ship AI agents with confidence — GovernLayer
            ensures they stay safe, compliant, and accountable.
          </motion.p>

          {/* CTAs */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.3 }}
            className="mt-10 flex justify-center gap-x-4"
          >
            <Link
              href="/register"
              className="rounded-full bg-white px-8 py-3 text-sm font-semibold text-black transition-colors hover:bg-zinc-200"
            >
              Start free trial
            </Link>
            <Link
              href="#features"
              className="rounded-full border border-zinc-700 px-8 py-3 text-sm text-zinc-400 transition-colors hover:border-zinc-500 hover:text-zinc-300"
            >
              See how it works
            </Link>
          </motion.div>
        </div>

        {/* Live API Preview */}
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.4 }}
          className="mx-auto mt-20 max-w-3xl"
        >
          <div className="overflow-hidden rounded-2xl bg-gradient-to-b from-zinc-800 to-zinc-900 shadow-2xl shadow-emerald-500/5 ring-1 ring-white/5">
            <div className="flex items-center gap-2 border-b border-white/5 px-4 py-3">
              <div className="h-3 w-3 rounded-full bg-red-500/80" />
              <div className="h-3 w-3 rounded-full bg-yellow-500/80" />
              <div className="h-3 w-3 rounded-full bg-green-500/80" />
              <span className="ml-2 text-xs text-zinc-500">POST /v1/govern</span>
            </div>
            <div className="p-6 text-left">
              <pre className="text-sm leading-relaxed">
                <code>
                  <span className="text-zinc-500">{'// One API call. Full governance pipeline.'}</span>
                  {'\n'}
                  <span className="text-emerald-400">{'{'}</span>
                  {'\n'}
                  <span className="text-zinc-300">{'  "system_name"'}</span>
                  <span className="text-zinc-500">{': '}</span>
                  <span className="text-amber-300">{'"customer-support-agent"'}</span>
                  <span className="text-zinc-500">{','}</span>
                  {'\n'}
                  <span className="text-zinc-300">{'  "behavior"'}</span>
                  <span className="text-zinc-500">{': '}</span>
                  <span className="text-amber-300">{'"Offered 50% discount without authorization"'}</span>
                  <span className="text-zinc-500">{','}</span>
                  {'\n'}
                  <span className="text-zinc-300">{'  "framework"'}</span>
                  <span className="text-zinc-500">{': '}</span>
                  <span className="text-amber-300">{'"SOC2"'}</span>
                  {'\n'}
                  <span className="text-emerald-400">{'}'}</span>
                  {'\n\n'}
                  <span className="text-zinc-500">{'// Response: drift detected, risk scored, decision logged'}</span>
                  {'\n'}
                  <span className="text-emerald-400">{'{'}</span>
                  {'\n'}
                  <span className="text-zinc-300">{'  "drift_score"'}</span>
                  <span className="text-zinc-500">{': '}</span>
                  <span className="text-red-400">{'0.87'}</span>
                  <span className="text-zinc-500">{','}</span>
                  {'\n'}
                  <span className="text-zinc-300">{'  "risk_level"'}</span>
                  <span className="text-zinc-500">{': '}</span>
                  <span className="text-amber-300">{'"HIGH"'}</span>
                  <span className="text-zinc-500">{','}</span>
                  {'\n'}
                  <span className="text-zinc-300">{'  "decision"'}</span>
                  <span className="text-zinc-500">{': '}</span>
                  <span className="text-amber-300">{'"ESCALATE — behavioral drift exceeds threshold"'}</span>
                  <span className="text-zinc-500">{','}</span>
                  {'\n'}
                  <span className="text-zinc-300">{'  "ledger_hash"'}</span>
                  <span className="text-zinc-500">{': '}</span>
                  <span className="text-amber-300">{'"sha256:a1b2c3..."'}</span>
                  {'\n'}
                  <span className="text-emerald-400">{'}'}</span>
                </code>
              </pre>
            </div>
          </div>
        </motion.div>

        {/* Framework badges */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ duration: 0.6, delay: 0.6 }}
          className="mt-20 text-center lg:mt-24"
        >
          <p className="font-display text-base text-zinc-500">
            14 compliance frameworks. One platform.
          </p>
          <div className="mt-8 flex flex-wrap items-center justify-center gap-3">
            {frameworks.map((fw) => (
              <span
                key={fw}
                className="rounded-full border border-white/10 bg-white/5 px-4 py-1.5 text-sm font-medium text-zinc-400"
              >
                {fw}
              </span>
            ))}
          </div>
        </motion.div>
      </div>
    </section>
  )
}
