import { useState } from 'react';
import { useTrustScore } from '../hooks/useDecide';
import MetricCard from '../components/MetricCard';
import clsx from 'clsx';

export default function TrustScorePage() {
  const [sessionId, setSessionId] = useState('dashboard-user');
  const trust = useTrustScore();

  function handleLookup(e: React.FormEvent) {
    e.preventDefault();
    trust.mutate(sessionId);
  }

  const d = trust.data;
  const score = d?.trust_score ?? 0.5;
  const color = score > 0.6 ? 'text-green-600' : score > 0.3 ? 'text-amber-500' : 'text-red-600';

  return (
    <div>
      <h1 className="text-xl font-bold mb-4">Trust Score Lookup</h1>

      <form onSubmit={handleLookup} className="flex gap-3 mb-6">
        <input
          value={sessionId}
          onChange={(e) => setSessionId(e.target.value)}
          placeholder="Session ID"
          className="px-3 py-2 border rounded-lg w-64 dark:bg-gray-800 dark:border-gray-700"
        />
        <button
          type="submit"
          disabled={trust.isPending}
          className="px-4 py-2 bg-btv-600 text-white rounded-lg font-medium hover:bg-btv-700 disabled:opacity-50"
        >
          Lookup
        </button>
      </form>

      {trust.isError && (
        <div className="p-3 bg-red-50 text-red-700 rounded-lg mb-4">Error: {trust.error?.message}</div>
      )}

      {d && (
        <div>
          <p className={clsx('text-3xl font-bold mb-4', color)}>Trust: {score.toFixed(2)}</p>
          <div className="grid grid-cols-3 gap-4 mb-4">
            <MetricCard label="Trust Score" value={score.toFixed(2)} />
            <MetricCard label="Offenses" value={d.offenses ?? 0} />
            <MetricCard label="Total Requests" value={d.total_requests ?? 0} />
          </div>
          <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-3">
            <div
              className={clsx('h-3 rounded-full transition-all', score > 0.6 ? 'bg-green-500' : score > 0.3 ? 'bg-amber-500' : 'bg-red-500')}
              style={{ width: `${Math.min(score, 1) * 100}%` }}
            />
          </div>
        </div>
      )}
    </div>
  );
}
