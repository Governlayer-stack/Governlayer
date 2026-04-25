import { Container } from '@/components/Container'

const faqs = [
  [
    {
      question: 'What types of AI systems can GovernLayer monitor?',
      answer:
        'Any AI agent, LLM-powered application, or autonomous system that makes decisions. GovernLayer monitors via API — send us the behavior, we return governance decisions. Works with OpenAI, Anthropic, Gemini, open-source models, and custom systems.',
    },
    {
      question: 'How does the hash-chained audit ledger work?',
      answer:
        'Every governance decision is stored as a record containing the decision, risk score, drift analysis, and a SHA-256 hash of the previous record. This creates a cryptographically linked chain — if any record is tampered with, the chain breaks. Regulators love it.',
    },
    {
      question: 'Can I self-host GovernLayer?',
      answer:
        'Yes. Enterprise plans include on-premise and VPC deployment options. The platform runs on Docker with PostgreSQL and Redis. We provide full deployment guides and dedicated support for self-hosted installations.',
    },
  ],
  [
    {
      question: 'Which compliance frameworks are supported?',
      answer:
        'SOC 2 Type II, GDPR, ISO 27001, EU AI Act, HIPAA, NIST AI RMF, NIST CSF, ISO 42001, PCI DSS, CCPA, NIS2, DORA, DSA, and DMA. Each framework includes mapped controls, evidence requirements, and automated readiness scoring. We add new frameworks quarterly.',
    },
    {
      question: 'What is multi-LLM consensus?',
      answer:
        'For high-stakes governance decisions, GovernLayer queries multiple LLMs independently and requires agreement before acting. Three strategies: Voting (majority rules), Chain-of-Verification (generate-question-verify-synthesize), and Adversarial Debate (claim-critique-judge).',
    },
    {
      question: 'How quickly can we get started?',
      answer:
        'Most teams are monitoring their first AI agent within 10 minutes. Sign up, get your API key, and send your first governance request. The compliance hub takes about a day to configure fully, depending on your framework requirements.',
    },
  ],
  [
    {
      question: 'What happens when drift is detected?',
      answer:
        'GovernLayer calculates a drift score (0-1) using sentence-transformer embeddings compared against safety manifolds. When the score exceeds your configured threshold, actions can include: logging, alerting, escalating to human reviewers, or automatically blocking the agent.',
    },
    {
      question: 'Is GovernLayer SOC 2 certified?',
      answer:
        'We are currently completing our SOC 2 Type II certification. Enterprise customers can request our current security documentation, penetration test results, and compliance posture report. We practice what we preach.',
    },
    {
      question: 'How does pricing work for high-volume usage?',
      answer:
        'Starter and Pro plans include generous API rate limits (100 and 500 calls/min respectively). Enterprise plans are custom-priced based on volume, with dedicated infrastructure and priority routing. Contact us for volume pricing.',
    },
  ],
]

export function Faqs() {
  return (
    <section
      id="faq"
      aria-labelledby="faq-title"
      className="relative overflow-hidden bg-slate-50 py-20 sm:py-32"
    >
      <Container className="relative">
        <div className="mx-auto max-w-2xl lg:mx-0">
          <h2
            id="faq-title"
            className="font-display text-3xl tracking-tight text-slate-900 sm:text-4xl"
          >
            Frequently asked questions
          </h2>
          <p className="mt-4 text-lg tracking-tight text-slate-700">
            Can&apos;t find what you&apos;re looking for? Email us at{' '}
            <a href="mailto:support@governlayer.ai" className="text-emerald-600 underline">
              support@governlayer.ai
            </a>{' '}
            and we&apos;ll get back to you within 24 hours.
          </p>
        </div>
        <ul
          role="list"
          className="mx-auto mt-16 grid max-w-2xl grid-cols-1 gap-8 lg:max-w-none lg:grid-cols-3"
        >
          {faqs.map((column, columnIndex) => (
            <li key={columnIndex}>
              <ul role="list" className="flex flex-col gap-y-8">
                {column.map((faq, faqIndex) => (
                  <li key={faqIndex}>
                    <h3 className="font-display text-lg/7 text-slate-900">
                      {faq.question}
                    </h3>
                    <p className="mt-4 text-sm text-slate-700">{faq.answer}</p>
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
