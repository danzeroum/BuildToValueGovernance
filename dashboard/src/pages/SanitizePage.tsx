import { useState } from 'react';
import { useSanitize } from '../hooks/useDecide';
import MetricCard from '../components/MetricCard';

export default function SanitizePage() {
  const [text, setText] = useState('');
  const sanitize = useSanitize();

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (text.trim()) sanitize.mutate({ text });
  }

  const d = sanitize.data;

  return (
    <div>
      <h1 className="text-xl font-bold mb-1">PII Sanitizer</h1>
      <p className="text-sm text-gray-500 mb-4">Mask sensitive data in LLM output</p>

      <form onSubmit={handleSubmit} className="mb-6">
        <textarea
          value={text}
          onChange={(e) => setText(e.target.value)}
          placeholder="Paste LLM output containing PII..."
          className="w-full px-3 py-2 border rounded-lg h-24 resize-none dark:bg-gray-800 dark:border-gray-700 mb-3"
        />
        <button
          type="submit"
          disabled={sanitize.isPending}
          className="px-4 py-2 bg-btv-600 text-white rounded-lg font-medium hover:bg-btv-700 disabled:opacity-50"
        >
          {sanitize.isPending ? 'Sanitizing...' : 'Sanitize'}
        </button>
      </form>

      {sanitize.isError && (
        <div className="p-3 bg-red-50 text-red-700 rounded-lg mb-4">Error: {sanitize.error?.message}</div>
      )}

      {d && (
        <div>
          <h3 className="font-semibold mb-2">Result</h3>
          <pre className="p-3 bg-gray-50 dark:bg-gray-800 rounded-lg border text-sm mb-4 whitespace-pre-wrap">
            {d.sanitized_text ?? d.sanitized ?? ''}
          </pre>
          <div className="grid grid-cols-3 gap-4">
            <MetricCard label="Masked" value={d.masked_count ?? d.redactions ?? 0} />
            <MetricCard label="Types" value={(d.masked_types ?? []).join(', ') || 'None'} />
            <MetricCard label="Latency" value={`${(d.latency_ms ?? 0).toFixed(1)}ms`} />
          </div>
        </div>
      )}
    </div>
  );
}
