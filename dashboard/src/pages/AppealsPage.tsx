import { useState } from 'react';
import { useSubmitAppeal, useListAppeals, useAppealsMetrics } from '../hooks/useDecide';
import MetricCard from '../components/MetricCard';
import JsonViewer from '../components/JsonViewer';
import clsx from 'clsx';

export default function AppealsPage() {
  const [tab, setTab] = useState<'submit' | 'view' | 'metrics'>('submit');

  // Submit form
  const [auditId, setAuditId] = useState(1);
  const [userId, setUserId] = useState('');
  const [reason, setReason] = useState('');
  const [evidence, setEvidence] = useState('');
  const submitAppeal = useSubmitAppeal();

  // View
  const [statusFilter, setStatusFilter] = useState('');
  const listAppeals = useListAppeals();

  // Metrics
  const metrics = useAppealsMetrics();

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    submitAppeal.mutate({ audit_trail_id: auditId, user_id: userId, reason, evidence: evidence || undefined });
  }

  const TABS = [
    { id: 'submit' as const, label: 'Submit Appeal' },
    { id: 'view' as const, label: 'View Appeals' },
    { id: 'metrics' as const, label: 'Metrics' },
  ];

  return (
    <div>
      <h1 className="text-xl font-bold mb-1">Contestability — Appeals</h1>
      <p className="text-sm text-gray-500 mb-4">Human-in-the-loop (Levinas, LGPD Art. 20)</p>

      <div className="flex gap-2 mb-6">
        {TABS.map(t => (
          <button key={t.id} onClick={() => setTab(t.id)}
            className={clsx('px-4 py-2 rounded-lg text-sm font-medium', tab === t.id ? 'bg-btv-600 text-white' : 'bg-gray-100 dark:bg-gray-700')}
          >{t.label}</button>
        ))}
      </div>

      {tab === 'submit' && (
        <form onSubmit={handleSubmit} className="max-w-lg space-y-3">
          <label className="block text-sm">Audit Trail ID
            <input type="number" min={1} value={auditId} onChange={e => setAuditId(Number(e.target.value))} className="w-full mt-1 px-3 py-2 border rounded-lg dark:bg-gray-800 dark:border-gray-700" />
          </label>
          <input placeholder="Your User ID" value={userId} onChange={e => setUserId(e.target.value)} className="w-full px-3 py-2 border rounded-lg dark:bg-gray-800 dark:border-gray-700" required />
          <textarea placeholder="Reason for appeal..." value={reason} onChange={e => setReason(e.target.value)} className="w-full px-3 py-2 border rounded-lg h-20 dark:bg-gray-800 dark:border-gray-700" required />
          <textarea placeholder="Supporting evidence (optional)..." value={evidence} onChange={e => setEvidence(e.target.value)} className="w-full px-3 py-2 border rounded-lg h-16 dark:bg-gray-800 dark:border-gray-700" />
          <button type="submit" disabled={submitAppeal.isPending} className="px-4 py-2 bg-btv-600 text-white rounded-lg font-medium hover:bg-btv-700 disabled:opacity-50">
            Submit Appeal
          </button>
          {submitAppeal.isSuccess && <p className="text-green-600 text-sm">Appeal submitted: {submitAppeal.data?.appeal_id}</p>}
          {submitAppeal.isError && <p className="text-red-600 text-sm">Error: {submitAppeal.error?.message}</p>}
        </form>
      )}

      {tab === 'view' && (
        <div>
          <div className="flex gap-3 mb-4">
            <select value={statusFilter} onChange={e => setStatusFilter(e.target.value)} className="px-3 py-2 border rounded-lg dark:bg-gray-800 dark:border-gray-700">
              <option value="">All statuses</option>
              {['pending', 'accepted', 'rejected', 'expired'].map(s => <option key={s} value={s}>{s}</option>)}
            </select>
            <button onClick={() => listAppeals.mutate({ status: statusFilter || undefined })}
              className="px-4 py-2 bg-btv-600 text-white rounded-lg font-medium hover:bg-btv-700"
            >Load Appeals</button>
          </div>
          {listAppeals.data && (
            <div>
              <p className="text-sm text-gray-500 mb-3"><strong>{listAppeals.data.total ?? 0}</strong> appeals</p>
              <div className="space-y-2">
                {(listAppeals.data.appeals ?? []).map((a: Record<string, unknown>) => {
                  const status = String(a.status ?? '?');
                  const icon = { pending: 'bg-amber-100', accepted: 'bg-green-100', rejected: 'bg-red-100', expired: 'bg-gray-100' }[status] ?? 'bg-gray-100';
                  return (
                    <details key={String(a.appeal_id)} className="border rounded-lg">
                      <summary className="px-4 py-3 cursor-pointer hover:bg-gray-50 dark:hover:bg-gray-800 flex items-center gap-2">
                        <span className={clsx('px-2 py-0.5 rounded text-xs font-medium', icon)}>{status}</span>
                        {String(a.appeal_id)}
                      </summary>
                      <div className="px-4 pb-3 text-sm space-y-1">
                        <p><strong>User:</strong> {String(a.user_id)}</p>
                        <p><strong>Reason:</strong> {String(a.reason)}</p>
                        <p><strong>SLA Deadline:</strong> {String(a.sla_deadline)}</p>
                        {a.reviewer_notes ? <p className="text-blue-600">Reviewer: {String(a.reviewer_notes)}</p> : null}
                        <JsonViewer data={a} />
                      </div>
                    </details>
                  );
                })}
              </div>
            </div>
          )}
        </div>
      )}

      {tab === 'metrics' && (
        <div>
          <button onClick={() => metrics.mutate()} className="px-4 py-2 bg-btv-600 text-white rounded-lg font-medium hover:bg-btv-700 mb-4">
            Load Metrics
          </button>
          {metrics.data && (
            <div className="grid grid-cols-4 gap-4">
              <MetricCard label="Total" value={metrics.data.total ?? metrics.data.appeals_submitted ?? 0} />
              <MetricCard label="Pending" value={metrics.data.pending ?? metrics.data.pending_appeals ?? 0} />
              <MetricCard label="Accepted" value={metrics.data.accepted ?? metrics.data.appeals_accepted ?? 0} />
              <MetricCard label="Rejected" value={metrics.data.rejected ?? metrics.data.appeals_rejected ?? 0} />
            </div>
          )}
        </div>
      )}
    </div>
  );
}
