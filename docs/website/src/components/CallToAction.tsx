'use client'

import { motion } from 'framer-motion'
import { Container } from '@/components/Container'

export function CallToAction() {
  return (
    <section
      id="get-started-today"
      className="relative overflow-hidden bg-[#0A0A0F] py-32"
    >
      {/* Radial gradient orb */}
      <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_center,rgba(16,185,129,0.15),transparent_70%)]" />
      {/* Subtle grid pattern */}
      <div className="absolute inset-0 bg-[linear-gradient(rgba(255,255,255,0.02)_1px,transparent_1px),linear-gradient(90deg,rgba(255,255,255,0.02)_1px,transparent_1px)] bg-[size:64px_64px]" />
      <Container className="relative">
        <motion.div
          className="mx-auto max-w-lg text-center"
          initial={{ opacity: 0, y: 24 }}
          whileInView={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, ease: 'easeOut' }}
          viewport={{ once: true }}
        >
          <h2 className="font-display text-4xl tracking-tight text-white font-bold">
            Your AI agents need governance. Start today.
          </h2>
          <p className="mt-4 text-lg tracking-tight text-zinc-400">
            14-day free trial. No credit card required. Full access to every
            feature. Deploy governance in under 10 minutes.
          </p>
          <a
            href="/register"
            className="mt-10 inline-flex items-center justify-center bg-white text-black font-semibold rounded-full px-10 py-4 text-lg hover:bg-zinc-200 transition"
          >
            Start your free trial
          </a>
        </motion.div>
      </Container>
    </section>
  )
}
