import clsx from 'clsx'

import { Container } from '@/components/Container'

function CheckIcon({
  className,
  ...props
}: React.ComponentPropsWithoutRef<'svg'>) {
  return (
    <svg
      aria-hidden="true"
      className={clsx(
        'h-6 w-6 flex-none fill-current stroke-current',
        className,
      )}
      {...props}
    >
      <path
        d="M9.307 12.248a.75.75 0 1 0-1.114 1.004l1.114-1.004ZM11 15.25l-.557.502a.75.75 0 0 0 1.15-.043L11 15.25Zm4.844-5.041a.75.75 0 0 0-1.188-.918l1.188.918Zm-7.651 3.043 2.25 2.5 1.114-1.004-2.25-2.5-1.114 1.004Zm3.4 2.457 4.25-5.5-1.187-.918-4.25 5.5 1.188.918Z"
        strokeWidth={0}
      />
      <circle
        cx={12}
        cy={12}
        r={8.25}
        fill="none"
        strokeWidth={1.5}
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  )
}

function Plan({
  name,
  price,
  description,
  href,
  features,
  featured = false,
}: {
  name: string
  price: string
  description: string
  href: string
  features: Array<string>
  featured?: boolean
}) {
  return (
    <section
      className={clsx(
        'relative flex flex-col rounded-2xl p-8',
        featured
          ? 'bg-gradient-to-b from-emerald-500/10 to-transparent border border-emerald-500/30 shadow-lg shadow-emerald-500/10'
          : 'bg-white/[0.03] border border-white/10',
      )}
    >
      {featured && (
        <div className="absolute -top-4 left-1/2 -translate-x-1/2 bg-emerald-500 text-black text-xs font-bold px-4 py-1 rounded-full">
          Most popular
        </div>
      )}
      <h3 className="mt-2 font-display text-lg text-white">{name}</h3>
      <p className="mt-2 text-base text-zinc-500">
        {description}
      </p>
      <p className="order-first font-display text-5xl font-bold tracking-tight text-white">
        {price}
      </p>
      <ul
        role="list"
        className="order-last mt-10 flex flex-col gap-y-3 text-sm"
      >
        {features.map((feature) => (
          <li key={feature} className="flex">
            <CheckIcon className="text-emerald-500" />
            <span className="ml-4 text-zinc-400">{feature}</span>
          </li>
        ))}
      </ul>
      <a
        href={href}
        className={clsx(
          'mt-8 inline-flex items-center justify-center rounded-full px-6 py-3 text-sm font-semibold transition',
          featured
            ? 'bg-emerald-500 text-black hover:bg-emerald-400'
            : 'border border-zinc-700 text-white hover:bg-white/5',
        )}
        aria-label={`Get started with the ${name} plan for ${price}`}
      >
        Get started
      </a>
    </section>
  )
}

export function Pricing() {
  return (
    <section
      id="pricing"
      aria-label="Pricing"
      className="relative bg-[#0A0A0F] py-20 sm:py-32"
    >
      {/* Subtle grid pattern */}
      <div className="absolute inset-0 bg-[linear-gradient(rgba(255,255,255,0.03)_1px,transparent_1px),linear-gradient(90deg,rgba(255,255,255,0.03)_1px,transparent_1px)] bg-[size:64px_64px]" />
      <Container className="relative">
        <div className="md:text-center">
          <h2 className="font-display text-3xl tracking-tight text-white sm:text-4xl font-bold">
            Transparent pricing, built for scale.
          </h2>
          <p className="mt-4 text-lg text-zinc-400">
            Start free. Scale to enterprise. No hidden fees. No per-seat
            licensing games.
          </p>
        </div>
        <div className="mt-16 grid max-w-2xl grid-cols-1 gap-y-10 sm:mx-auto lg:max-w-none lg:grid-cols-3 lg:gap-x-8">
          <Plan
            name="Starter"
            price="$49"
            description="For teams deploying their first AI agents in production."
            href="/register"
            features={[
              'Up to 5 AI agents monitored',
              'Real-time drift detection',
              'Deterministic risk scoring',
              '3 compliance frameworks',
              'Immutable audit ledger',
              '100 API calls / minute',
              'Email support',
            ]}
          />
          <Plan
            featured
            name="Pro"
            price="$199"
            description="For scaling teams with critical AI workloads."
            href="/register"
            features={[
              'Unlimited AI agents',
              'Multi-LLM consensus engine',
              'All 14 compliance frameworks',
              'Human-in-the-loop escalation',
              'Full GRC compliance hub',
              'Webhook integrations',
              '500 API calls / minute',
              'Priority support + SLA',
            ]}
          />
          <Plan
            name="Enterprise"
            price="Custom"
            description="For organizations with advanced security and compliance requirements."
            href="/register"
            features={[
              'Everything in Pro',
              'On-premise / VPC deployment',
              'SSO + SCIM provisioning',
              'Custom framework mapping',
              'Dedicated success manager',
              '2,000+ API calls / minute',
              'SOC 2 Type II report available',
            ]}
          />
        </div>
      </Container>
    </section>
  )
}
