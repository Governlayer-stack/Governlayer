export function Logo(props) {
  return (
    <svg viewBox="0 0 140 24" aria-hidden="true" {...props}>
      <path
        d="M12 1L3 5.5v6c0 5.96 4.09 11.54 9 12.87 4.91-1.33 9-6.91 9-12.87v-6L12 1z"
        className="fill-emerald-400"
      />
      <path
        d="M12 4L5 7.5v5c0 4.64 3.18 8.98 7 10.05 3.82-1.07 7-5.41 7-10.05v-5L12 4z"
        className="fill-emerald-500"
      />
      <path
        d="M9.5 11l2 2 3.5-3.5"
        stroke="white"
        strokeWidth={1.8}
        strokeLinecap="round"
        strokeLinejoin="round"
        fill="none"
      />
      <text
        x="26"
        y="17"
        className="fill-zinc-900 dark:fill-white"
        fontFamily="system-ui, -apple-system, sans-serif"
        fontWeight="700"
        fontSize="14"
      >
        Govern
        <tspan className="fill-emerald-500">Layer</tspan>
      </text>
    </svg>
  )
}
