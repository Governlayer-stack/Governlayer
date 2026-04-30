'use client'

import Link from 'next/link'
import {
  Popover,
  PopoverButton,
  PopoverBackdrop,
  PopoverPanel,
} from '@headlessui/react'
import clsx from 'clsx'

import { Logo } from '@/components/Logo'

function MobileNavLink({
  href,
  children,
}: {
  href: string
  children: React.ReactNode
}) {
  return (
    <PopoverButton
      as={Link}
      href={href}
      className="block w-full p-2 text-zinc-300 hover:text-white transition-colors"
    >
      {children}
    </PopoverButton>
  )
}

function MobileNavIcon({ open }: { open: boolean }) {
  return (
    <svg
      aria-hidden="true"
      className="h-3.5 w-3.5 overflow-visible stroke-zinc-400"
      fill="none"
      strokeWidth={2}
      strokeLinecap="round"
    >
      <path
        d="M0 1H14M0 7H14M0 13H14"
        className={clsx(
          'origin-center transition',
          open && 'scale-90 opacity-0',
        )}
      />
      <path
        d="M2 2L12 12M12 2L2 12"
        className={clsx(
          'origin-center transition',
          !open && 'scale-90 opacity-0',
        )}
      />
    </svg>
  )
}

function MobileNavigation() {
  return (
    <Popover>
      <PopoverButton
        className="relative z-10 flex h-8 w-8 items-center justify-center focus:not-data-focus:outline-hidden"
        aria-label="Toggle Navigation"
      >
        {({ open }) => <MobileNavIcon open={open} />}
      </PopoverButton>
      <PopoverBackdrop
        transition
        className="fixed inset-0 bg-black/60 backdrop-blur-sm duration-150 data-closed:opacity-0 data-enter:ease-out data-leave:ease-in"
      />
      <PopoverPanel
        transition
        className="absolute inset-x-0 top-full mt-4 flex origin-top flex-col rounded-2xl bg-zinc-900 p-4 text-lg tracking-tight text-zinc-300 ring-1 ring-white/10 data-closed:scale-95 data-closed:opacity-0 data-enter:duration-150 data-enter:ease-out data-leave:duration-100 data-leave:ease-in"
      >
        <MobileNavLink href="#features">Platform</MobileNavLink>
        <MobileNavLink href="#solutions">Solutions</MobileNavLink>
        <MobileNavLink href="#pricing">Pricing</MobileNavLink>
        <MobileNavLink href="#faq">Resources</MobileNavLink>
        <hr className="m-2 border-white/10" />
        <MobileNavLink href="/login">Sign in</MobileNavLink>
      </PopoverPanel>
    </Popover>
  )
}

export function Header() {
  return (
    <header className="fixed top-0 left-0 right-0 z-50">
      <div className="mx-auto max-w-7xl px-6 lg:px-8">
        <nav className="flex items-center justify-between py-4 mt-3 rounded-2xl border border-white/5 bg-white/5 backdrop-blur-xl px-6">
          <div className="flex items-center md:gap-x-12">
            <Link href="#" aria-label="Home">
              <Logo className="h-10 w-auto" />
            </Link>
            <div className="hidden md:flex md:gap-x-8">
              <Link
                href="#features"
                className="text-sm text-zinc-400 transition-colors hover:text-white"
              >
                Platform
              </Link>
              <Link
                href="#solutions"
                className="text-sm text-zinc-400 transition-colors hover:text-white"
              >
                Solutions
              </Link>
              <Link
                href="#pricing"
                className="text-sm text-zinc-400 transition-colors hover:text-white"
              >
                Pricing
              </Link>
              <Link
                href="#faq"
                className="text-sm text-zinc-400 transition-colors hover:text-white"
              >
                Resources
              </Link>
            </div>
          </div>
          <div className="flex items-center gap-x-5 md:gap-x-8">
            <Link
              href="/login"
              className="hidden text-sm text-zinc-400 transition-colors hover:text-white md:block"
            >
              Sign in
            </Link>
            <Link
              href="/register"
              className="rounded-full bg-emerald-500 px-5 py-2 text-sm font-semibold text-black transition-colors hover:bg-emerald-400"
            >
              Start free trial
            </Link>
            <div className="-mr-1 md:hidden">
              <MobileNavigation />
            </div>
          </div>
        </nav>
      </div>
    </header>
  )
}
