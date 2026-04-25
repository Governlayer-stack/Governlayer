import { Button } from '@/components/Button'
import { Container } from '@/components/Container'

export function CallToAction() {
  return (
    <section
      id="get-started-today"
      className="relative overflow-hidden bg-emerald-600 py-32"
    >
      <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_center,_var(--tw-gradient-stops))] from-emerald-500 via-emerald-600 to-emerald-800" />
      <Container className="relative">
        <div className="mx-auto max-w-lg text-center">
          <h2 className="font-display text-3xl tracking-tight text-white sm:text-4xl">
            Your AI agents need governance. Start today.
          </h2>
          <p className="mt-4 text-lg tracking-tight text-emerald-100">
            14-day free trial. No credit card required. Full access to every
            feature. Deploy governance in under 10 minutes.
          </p>
          <Button href="/register" color="white" className="mt-10">
            Start your free trial
          </Button>
        </div>
      </Container>
    </section>
  )
}
