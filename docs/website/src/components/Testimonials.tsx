import { Container } from '@/components/Container'

const testimonials = [
  [
    {
      content:
        'Before GovernLayer, we had no visibility into what our AI agents were doing in production. Now we catch behavioral drift in real-time and have a complete audit trail for every decision.',
      author: {
        name: 'Sarah Chen',
        role: 'VP of Engineering at FinTech Corp',
      },
    },
    {
      content:
        'The compliance hub saved us 3 months of SOC 2 preparation. We mapped controls, tracked evidence, and generated audit-ready reports — all from one platform.',
      author: {
        name: 'Marcus Williams',
        role: 'CISO at HealthAI Systems',
      },
    },
  ],
  [
    {
      content:
        'GovernLayer\'s multi-LLM consensus engine is a game-changer. For high-stakes decisions, having 3 models independently verify before taking action gives our board the confidence they need.',
      author: {
        name: 'Dr. Amara Osei',
        role: 'Chief AI Officer at Global Insurance Ltd',
      },
    },
    {
      content:
        'We went from zero governance to full EU AI Act compliance in under 6 weeks. The framework library had every control mapped and ready. Our auditors were impressed.',
      author: {
        name: 'Lukas Hoffmann',
        role: 'Head of Compliance at EuroBank Digital',
      },
    },
  ],
  [
    {
      content:
        'The hash-chained audit ledger is exactly what regulators want to see. Tamper-proof, cryptographically linked records of every governance decision. It\'s the gold standard.',
      author: {
        name: 'Priya Patel',
        role: 'General Counsel at DataDriven Inc',
      },
    },
    {
      content:
        'We deploy 200+ AI agents across our platform. GovernLayer monitors all of them autonomously, escalates when needed, and gives us a single pane of glass for AI risk.',
      author: {
        name: 'James Okonkwo',
        role: 'CTO at Contracts.ai',
      },
    },
  ],
]

function QuoteIcon(props: React.ComponentPropsWithoutRef<'svg'>) {
  return (
    <svg aria-hidden="true" width={105} height={78} {...props}>
      <path d="M25.086 77.292c-4.821 0-9.115-1.205-12.882-3.616-3.767-2.561-6.78-6.102-9.04-10.622C1.054 58.534 0 53.411 0 47.686c0-5.273.904-10.396 2.712-15.368 1.959-4.972 4.746-9.567 8.362-13.786a59.042 59.042 0 0 1 12.43-11.3C28.325 3.917 33.599 1.507 39.324 0l11.074 13.786c-6.479 2.561-11.677 5.951-15.594 10.17-3.767 4.219-5.65 7.835-5.65 10.848 0 1.356.377 2.863 1.13 4.52.904 1.507 2.637 3.089 5.198 4.746 3.767 2.41 6.328 4.972 7.684 7.684 1.507 2.561 2.26 5.5 2.26 8.814 0 5.123-1.959 9.19-5.876 12.204-3.767 3.013-8.588 4.52-14.464 4.52Zm54.24 0c-4.821 0-9.115-1.205-12.882-3.616-3.767-2.561-6.78-6.102-9.04-10.622-2.11-4.52-3.164-9.643-3.164-15.368 0-5.273.904-10.396 2.712-15.368 1.959-4.972 4.746-9.567 8.362-13.786a59.042 59.042 0 0 1 12.43-11.3C82.565 3.917 87.839 1.507 93.564 0l11.074 13.786c-6.479 2.561-11.677 5.951-15.594 10.17-3.767 4.219-5.65 7.835-5.65 10.848 0 1.356.377 2.863 1.13 4.52.904 1.507 2.637 3.089 5.198 4.746 3.767 2.41 6.328 4.972 7.684 7.684 1.507 2.561 2.26 5.5 2.26 8.814 0 5.123-1.959 9.19-5.876 12.204-3.767 3.013-8.588 4.52-14.464 4.52Z" />
    </svg>
  )
}

export function Testimonials() {
  return (
    <section
      id="testimonials"
      aria-label="What our customers are saying"
      className="bg-slate-50 py-20 sm:py-32"
    >
      <Container>
        <div className="mx-auto max-w-2xl md:text-center">
          <h2 className="font-display text-3xl tracking-tight text-slate-900 sm:text-4xl">
            Trusted by enterprise AI teams worldwide.
          </h2>
          <p className="mt-4 text-lg tracking-tight text-slate-700">
            From startups deploying their first agent to enterprises managing
            thousands — GovernLayer provides the governance backbone.
          </p>
        </div>
        <ul
          role="list"
          className="mx-auto mt-16 grid max-w-2xl grid-cols-1 gap-6 sm:gap-8 lg:mt-20 lg:max-w-none lg:grid-cols-3"
        >
          {testimonials.map((column, columnIndex) => (
            <li key={columnIndex}>
              <ul role="list" className="flex flex-col gap-y-6 sm:gap-y-8">
                {column.map((testimonial, testimonialIndex) => (
                  <li key={testimonialIndex}>
                    <figure className="relative rounded-2xl bg-white p-6 shadow-xl shadow-slate-900/10">
                      <QuoteIcon className="absolute top-6 left-6 fill-slate-100" />
                      <blockquote className="relative">
                        <p className="text-lg tracking-tight text-slate-900">
                          {testimonial.content}
                        </p>
                      </blockquote>
                      <figcaption className="relative mt-6 flex items-center justify-between border-t border-slate-100 pt-6">
                        <div>
                          <div className="font-display text-base text-slate-900">
                            {testimonial.author.name}
                          </div>
                          <div className="mt-1 text-sm text-slate-500">
                            {testimonial.author.role}
                          </div>
                        </div>
                        <div className="flex h-14 w-14 items-center justify-center overflow-hidden rounded-full bg-emerald-50">
                          <span className="text-lg font-bold text-emerald-600">
                            {testimonial.author.name.split(' ').map(n => n[0]).join('')}
                          </span>
                        </div>
                      </figcaption>
                    </figure>
                  </li>
                ))}
              </ul>
            </li>
          ))}
        </ul>
      </Container>
    </section>
  )
}
