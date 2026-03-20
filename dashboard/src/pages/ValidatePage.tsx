import { useState } from 'react';
import { useValidate } from '../hooks/useDecide';
import ActionBadge from '../components/ActionBadge';
import MetricCard from '../components/MetricCard';
import JsonViewer from '../components/JsonViewer';
import PipelineViz, { buildStages } from '../components/PipelineViz';

export default function ValidatePage() {
  const [input, setInput] = useState('');
  const [sessionId, setSessionId] = useState('dashboard-user');
  const validate = useValidate();

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (input.trim()) validate.mutate({ input, session_id: sessionId });
  }

  const d = validate.data;

  return (
    <div>
      <h1 className="text-xl font-bold mb-1">Validate Input</h1>
      <p className="text-sm text-gray-500 mb-4">Scan + Policy + Governance (Republica Algoritmica)</p>

      <form onSubmit={handleSubmit} className="flex gap-4 mb-6">
        <div className="flex-1">
          <textarea
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Type or paste text to validate..."
            className="w-full px-3 py-2 border rounded-lg h-24 resize-none dark:bg-gray-800 dark:border-gray-700"
          />
        </div>
        <div className="w-48 flex flex-col gap-2">
          <input
            value={sessionId}
            onChange={(e) => setSessionId(e.target.value)}
            placeholder="Session ID"
            className="px-3 py-2 border rounded-lg text-sm dark:bg-gray-800 dark:border-gray-700"
          />
          <button
            type="submit"
            disabled={validate.isPending}
            className="px-4 py-2 bg-btv-600 text-white rounded-lg font-medium hover:bg-btv-700 disabled:opacity-50"
          >
            {validate.isPending ? 'Scanning...' : 'Validate'}
          </button>
        </div>
      </form>

      {validate.isError && (
        <div className="p-3 bg-red-50 text-red-700 rounded-lg mb-4">
          {validate.error?.message || 'Validation failed'}
        </div>
      )}

      {d && (
        <div>
          <div className="mb-4">
            <ActionBadge action={d.action} />
          </div>

          <div className="grid grid-cols-4 gap-4 mb-4">
            <MetricCard label="Findings" value={d.finding_count ?? 0} />
            <MetricCard label="Critical" value={d.critical_count ?? 0} />
            <MetricCard label="Risk" value={`${((d.composite_risk ?? 0) * 100).toFixed(0)}%`} />
            <MetricCard label="Latency" value={`${(d.latency_ms ?? 0).toFixed(1)}ms`} />
          </div>

          {d.mercy_applied && (
            <div className="p-3 bg-green-50 text-green-700 rounded-lg mb-4 dark:bg-green-900/20 dark:text-green-300">
              Mercy applied: {d.original_action} &rarr; {d.action}
            </div>
          )}

          {d.hard_blocked && (
            <div className="p-3 bg-red-50 text-red-700 rounded-lg mb-4 font-semibold">
              HARD BLOCK: Dangerous content detected
            </div>
          )}

          <PipelineViz
            stages={buildStages(d.explain)}
            latencyMs={d.latency_ms}
            mercyApplied={d.mercy_applied}
          />

          <JsonViewer data={d} />
        </div>
      )}
    </div>
  );
}
