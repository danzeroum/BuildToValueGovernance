import { useEffect } from 'react';
import { useWebhooksStatus } from '../hooks/useDecide';
import MetricCard from '../components/MetricCard';
import JsonViewer from '../components/JsonViewer';
import { governance } from '../api/client';
import clsx from 'clsx';

export default function WebhooksPage() {
  const status = useWebhooksStatus();

  useEffect(() => { status.mutate(); }, []);

  const d = status.data;

  async function handleReload() {
    try {
      await governance.post('/v1/webhooks/reload');
      status.mutate();
    } catch {
      // ignore
    }
  }

  async function handleTest() {
    try {
      await governance.post('/v1/webhooks/test');
      alert('Test webhook sent');
    } catch {
      alert('Failed to send test webhook');
    }
  }

  return (
    <div>
      <h1 className="text-xl font-bold mb-1">Webhook Status</h1>
      <p className="text-sm text-gray-500 mb-4">Real-time notifications for critical decisions (Jonas)</p>

      {d && (
        <div>
          <p className={clsx('text-lg font-bold mb-4', d.status === 'ok' ? 'text-green-600' : 'text-red-600')}>
            Status: {d.status ?? '?'}
          </p>
          <div className="grid grid-cols-3 gap-4 mb-6">
            <MetricCard label="Targets" value={d.targets ?? 0} />
            <MetricCard label="Dispatched" value={d.dispatched ?? 0} />
            <MetricCard label="Failed" value={d.failed ?? 0} />
          </div>
          <JsonViewer data={d} label="Full Status" />
        </div>
      )}

      <div className="flex gap-3 mt-6">
        <button onClick={handleReload} className="px-4 py-2 border rounded-lg font-medium hover:bg-gray-50 dark:hover:bg-gray-700">
          Reload Config
        </button>
        <button onClick={handleTest} className="px-4 py-2 border rounded-lg font-medium hover:bg-gray-50 dark:hover:bg-gray-700">
          Send Test Webhook
        </button>
      </div>
    </div>
  );
}
