'use client'

import { motion } from 'framer-motion'
import { Container } from '@/components/Container'

const stats = [
  { label: 'AI agents governed', value: '10,000+' },
  { label: 'Governance decisions logged', value: '2.4M+' },
  { label: 'Compliance frameworks', value: '14' },
  { label: 'Uptime SLA', value: '99.99%' },
]

export function Stats() {
  return (
    <section className="border-t border-white/5 bg-[#0A0A0F] py-20 sm:py-24">
      <Container>
        <div className="mx-auto grid max-w-5xl grid-cols-2 gap-12 lg:grid-cols-4">
          {stats.map((stat, index) => (
            <motion.div
              key={stat.label}
              className="relative text-center"
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ duration: 0.5, delay: index * 0.1 }}
            >
              {/* Subtle emerald glow behind the number */}
              <div className="absolute left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 h-16 w-16 rounded-full bg-emerald-500/10 blur-2xl" />
              <div className="relative text-5xl font-bold tracking-tight text-white">
                {stat.value}
              </div>
              <div className="relative mt-3 text-sm uppercase tracking-wider text-zinc-500">
                {stat.label}
              </div>
            </motion.div>
          ))}
        </div>
      </Container>
    </section>
  )
}
