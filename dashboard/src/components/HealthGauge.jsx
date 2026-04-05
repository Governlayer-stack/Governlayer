export default function HealthGauge({ score, size = 160 }) {
  const radius = (size - 20) / 2;
  const circumference = Math.PI * radius; // half circle
  const progress = (score / 100) * circumference;
  const cx = size / 2;
  const cy = size / 2 + 10;

  let color;
  if (score >= 80) color = '#059669';
  else if (score >= 50) color = '#d97706';
  else color = '#dc2626';

  let label;
  if (score >= 90) label = 'Healthy';
  else if (score >= 70) label = 'Warning';
  else if (score >= 50) label = 'Degraded';
  else label = 'Critical';

  return (
    <div className="flex flex-col items-center">
      <svg width={size} height={size * 0.65} viewBox={`0 0 ${size} ${size * 0.65}`}>
        {/* Background arc */}
        <path
          d={describeArc(cx, cy, radius, 180, 360)}
          fill="none"
          stroke="#e5e7eb"
          strokeWidth={10}
          strokeLinecap="round"
        />
        {/* Progress arc */}
        <path
          d={describeArc(cx, cy, radius, 180, 180 + (score / 100) * 180)}
          fill="none"
          stroke={color}
          strokeWidth={10}
          strokeLinecap="round"
        />
        {/* Score text */}
        <text
          x={cx}
          y={cy - 10}
          textAnchor="middle"
          className="text-3xl font-bold"
          fill={color}
          style={{ fontSize: '2rem', fontWeight: 700 }}
        >
          {score}
        </text>
        <text
          x={cx}
          y={cy + 10}
          textAnchor="middle"
          fill="#6b7280"
          style={{ fontSize: '0.75rem' }}
        >
          / 100
        </text>
      </svg>
      <span
        className="text-sm font-semibold mt-1"
        style={{ color }}
      >
        {label}
      </span>
    </div>
  );
}

function polarToCartesian(cx, cy, r, angleDeg) {
  const rad = ((angleDeg - 90) * Math.PI) / 180;
  return {
    x: cx + r * Math.cos(rad),
    y: cy + r * Math.sin(rad),
  };
}

function describeArc(cx, cy, r, startAngle, endAngle) {
  const start = polarToCartesian(cx, cy, r, endAngle);
  const end = polarToCartesian(cx, cy, r, startAngle);
  const largeArc = endAngle - startAngle <= 180 ? '0' : '1';
  return `M ${start.x} ${start.y} A ${r} ${r} 0 ${largeArc} 0 ${end.x} ${end.y}`;
}
