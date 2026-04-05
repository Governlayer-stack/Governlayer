export default function ErrorBanner({ message, onRetry }) {
  return (
    <div className="bg-red-50 border border-red-200 rounded-lg p-4 flex items-center gap-3">
      <svg className="w-5 h-5 text-red-500 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
          d="M12 9v2m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
      </svg>
      <span className="text-sm text-red-700 flex-1">{message}</span>
      {onRetry && (
        <button onClick={onRetry} className="text-sm font-medium text-red-600 hover:text-red-800">
          Retry
        </button>
      )}
    </div>
  );
}
