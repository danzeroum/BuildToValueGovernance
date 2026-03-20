import { useEffect } from 'react';
import { useHealthChecks } from '../hooks/useDecide';
import JsonViewer from '../components/JsonViewer';

export default function MetricsPage() {
  const health = useHealthChecks();

  useEffect(() => { health.mutate(); }, []);

  const d = health.data;

  return (
    <div>
      <h1 className="text-xl font-bold mb-4">System Metrics</h1>

      <button onClick={() => health.mutate()} disabled={health.isPending}
        className="px-4 py-2 bg-btv-600 text-white rounded-lg font-medium hover:bg-btv-700 disabled:opacity-50 mb-6"
      >
        Refresh
      </button>

      {d && (
        <div className="grid grid-cols-2 gap-6">
          <div>
            <h2 className="text-lg font-semibold mb-2">Rust Gateway</h2>
            <div className="bg-white dark:bg-gray-800 border rounded-lg p-4">
              <JsonViewer data={d.gateway} label="Health" />
            </div>
          </div>
          <div>
            <h2 className="text-lg font-semibold mb-2">Python Governance</h2>
            <div className="bg-white dark:bg-gray-800 border rounded-lg p-4">
              <JsonViewer data={d.governance} label="Health" />
            </div>
          </div>
          <div className="col-span-2">
            <h2 className="text-lg font-semibold mb-2">Prometheus Metrics</h2>
            <pre className="p-4 bg-gray-50 dark:bg-gray-900 border rounded-lg text-xs overflow-x-auto max-h-96 overflow-y-auto">
              {d.metricsText || 'No metrics data'}
            </pre>
          </div>
        </div>
      )}
    </div>
  );
}
