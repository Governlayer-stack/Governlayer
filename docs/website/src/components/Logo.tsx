export function Logo(props: React.ComponentPropsWithoutRef<'svg'>) {
  return (
    <svg aria-hidden="true" viewBox="0 0 200 40" {...props}>
      {/* Shield icon */}
      <path
        d="M20 2L4 10v10c0 9.94 6.82 19.24 16 21.5 9.18-2.26 16-11.56 16-21.5V10L20 2z"
        fill="#10B981"
      />
      <path
        d="M20 6L8 12v8c0 7.73 5.3 14.96 12 16.72 6.7-1.76 12-8.99 12-16.72v-8L20 6z"
        fill="#059669"
      />
      <path
        d="M16 18l3 3 6-6"
        stroke="#fff"
        strokeWidth={2.5}
        strokeLinecap="round"
        strokeLinejoin="round"
        fill="none"
      />
      {/* GovernLayer text */}
      <text
        x="44"
        y="27"
        fontFamily="system-ui, -apple-system, sans-serif"
        fontWeight="700"
        fontSize="20"
        fill="#0F172A"
      >
        Govern
        <tspan fill="#10B981">Layer</tspan>
      </text>
    </svg>
  )
}
