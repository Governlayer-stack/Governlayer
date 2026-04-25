import { Container } from '@/components/Container'

const stats = [
  { label: 'AI agents governed', value: '10,000+' },
  { label: 'Governance decisions logged', value: '2.4M+' },
  { label: 'Compliance frameworks', value: '14' },
  { label: 'Uptime SLA', value: '99.99%' },
]

export function Stats() {
  return (
    <section className="border-y border-slate-200 bg-white py-16">
      <Container>
        <div className="mx-auto grid max-w-5xl grid-cols-2 gap-8 lg:grid-cols-4">
          {stats.map((stat) => (
            <div key={stat.label} className="text-center">
              <div className="font-display text-4xl font-medium tracking-tight text-slate-900">
                {stat.value}
              </div>
              <div className="mt-2 text-sm text-slate-600">{stat.label}</div>
            </div>
          ))}
        </div>
      </Container>
    </section>
  )
}
