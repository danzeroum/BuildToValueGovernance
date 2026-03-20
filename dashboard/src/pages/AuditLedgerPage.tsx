import { useState } from 'react';
import { useLedgerQuery, useLedgerStats } from '../hooks/useDecide';
import ActionBadge from '../components/ActionBadge';
import MetricCard from '../components/MetricCard';
import JsonViewer from '../components/JsonViewer';

export default function AuditLedgerPage() {
  const [sessionFilter, setSessionFilter] = useState('');
  const [verdictFilter, setVerdictFilter] = useState('');
  const [actionFilter, setActionFilter] = useState('');
  const [pageSize, setPageSize] = useState(50);
  const ledger = useLedgerQuery();
  const stats = useLedgerStats();

  function handleQuery() {
    const params: Record<string, unknown> = { page_size: pageSize };
    if (sessionFilter) params.session_id = sessionFilter;
    if (verdictFilter) params.verdict_id = verdictFilter;
    if (actionFilter) params.action = actionFilter;
    ledger.mutate(params);
    stats.mutate();
  }

  const d = ledger.data;
  const pagination = d?.pagination ?? {};

  return (
    <div>
      <h1 className="text-xl font-bold mb-1">Audit Ledger Query</h1>
      <p className="text-sm text-gray-500 mb-4">Query immutable decision log (ADR-024, Jonas)</p>

      <div className="grid grid-cols-4 gap-3 mb-4">
        <input value={sessionFilter} onChange={e => setSessionFilter(e.target.value)} placeholder="Session ID" className="px-3 py-2 border rounded-lg dark:bg-gray-800 dark:border-gray-700" />
        <select value={actionFilter} onChange={e => setActionFilter(e.target.value)} className="px-3 py-2 border rounded-lg dark:bg-gray-800 dark:border-gray-700">
          <option value="">All actions</option>
          {['ALLOW', 'LOG', 'EDUCATE', 'REDACT', 'BLOCK'].map(a => <option key={a} value={a}>{a}</option>)}
        </select>
        <input value={verdictFilter} onChange={e => setVerdictFilter(e.target.value)} placeholder="Verdict ID" className="px-3 py-2 border rounded-lg dark:bg-gray-800 dark:border-gray-700" />
        <div className="flex items-center gap-2">
          <label className="text-xs text-gray-500 whitespace-nowrap">Per page:</label>
          <input type="range" min={10} max={200} value={pageSize} onChange={e => setPageSize(Number(e.target.value))} className="flex-1" />
          <span className="text-xs w-8">{pageSize}</span>
        </div>
      </div>
      <button onClick={handleQuery} disabled={ledger.isPending}
        className="px-4 py-2 bg-btv-600 text-white rounded-lg font-medium hover:bg-btv-700 disabled:opacity-50 mb-4"
      >
        Query Ledger
      </button>

      {d && (
        <div>
          <p className="text-sm text-gray-500 mb-3">
            <strong>{pagination.total_matched ?? 0}</strong> decisions (page {pagination.page ?? 1}/{pagination.total_pages ?? 1})
          </p>
          <div className="space-y-2">
            {(d.entries ?? []).map((entry: Record<string, unknown>, i: number) => {
              const ts = entry.ts ? new Date(Number(entry.ts)).toISOString().replace('T', ' ').slice(0, 19) : '?';
              return (
                <details key={i} className="border rounded-lg">
                  <summary className="px-4 py-3 cursor-pointer hover:bg-gray-50 dark:hover:bg-gray-800 flex items-center gap-3">
                    <ActionBadge action={String(entry.final_action ?? '?')} />
                    <span className="text-sm text-gray-500">{ts}</span>
                    <span className="text-xs text-gray-400">{String(entry.verdict_id ?? '')}</span>
                  </summary>
                  <div className="px-4 pb-3">
                    <div className="grid grid-cols-4 gap-3 mb-2">
                      <MetricCard label="Risk" value={`${((Number(entry.risk) || 0) * 100).toFixed(0)}%`} />
                      <MetricCard label="Findings" value={Number(entry.findings) || 0} />
                      <MetricCard label="Critical" value={Number(entry.critical) || 0} />
                      <MetricCard label="Latency" value={`${(Number(entry.latency_ms) || 0).toFixed(1)}ms`} />
                    </div>
                    {entry.mercy ? <p className="text-green-600 text-sm mb-2">Mercy applied</p> : null}
                    <JsonViewer data={entry} />
                  </div>
                </details>
              );
            })}
          </div>
        </div>
      )}

      {stats.data && (
        <div className="mt-6 border-t pt-4">
          <h3 className="text-sm font-semibold mb-2">Ledger Stats</h3>
          <div className="grid grid-cols-2 gap-4">
            <MetricCard label="Total Entries" value={stats.data.entry_count ?? 0} />
            <MetricCard label="File" value={stats.data.ledger_file ?? '?'} />
          </div>
        </div>
      )}
    </div>
  );
}
