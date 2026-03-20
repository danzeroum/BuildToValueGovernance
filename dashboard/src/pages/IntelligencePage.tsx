import { useState } from 'react';
import { useIntelligenceQuery, useIntelligenceIngest, useIntelligenceStats } from '../hooks/useDecide';
import MetricCard from '../components/MetricCard';
import clsx from 'clsx';

export default function IntelligencePage() {
  const [tab, setTab] = useState<'browse' | 'ingest'>('browse');
  const [filterType, setFilterType] = useState('');
  const [minSev, setMinSev] = useState(0);
  const query = useIntelligenceQuery();
  const stats = useIntelligenceStats();
  const ingest = useIntelligenceIngest();

  // Ingest form state
  const [form, setForm] = useState({ id: '', threat_type: 'prompt_injection', severity: 5, source: 'OWASP', indicators: '', description: '', mitre_id: '' });

  function handleSearch() {
    query.mutate({ threat_type: filterType || undefined, min_severity: minSev });
    stats.mutate();
  }

  function handleIngest(e: React.FormEvent) {
    e.preventDefault();
    ingest.mutate({
      ...form,
      severity: Number(form.severity),
      indicators: form.indicators.split(',').map(s => s.trim()).filter(Boolean),
    });
  }

  return (
    <div>
      <h1 className="text-xl font-bold mb-4">Threat Intelligence Hub</h1>

      <div className="flex gap-2 mb-6">
        <button onClick={() => setTab('browse')} className={clsx('px-4 py-2 rounded-lg text-sm font-medium', tab === 'browse' ? 'bg-btv-600 text-white' : 'bg-gray-100 dark:bg-gray-700')}>
          Browse
        </button>
        <button onClick={() => setTab('ingest')} className={clsx('px-4 py-2 rounded-lg text-sm font-medium', tab === 'ingest' ? 'bg-btv-600 text-white' : 'bg-gray-100 dark:bg-gray-700')}>
          Ingest
        </button>
      </div>

      {tab === 'browse' && (
        <div>
          <div className="flex gap-3 mb-4">
            <input value={filterType} onChange={e => setFilterType(e.target.value)} placeholder="Filter by type" className="px-3 py-2 border rounded-lg dark:bg-gray-800 dark:border-gray-700" />
            <label className="flex items-center gap-2 text-sm">
              Min severity:
              <input type="range" min={0} max={10} value={minSev} onChange={e => setMinSev(Number(e.target.value))} className="w-32" />
              <span>{minSev}</span>
            </label>
            <button onClick={handleSearch} className="px-4 py-2 bg-btv-600 text-white rounded-lg font-medium hover:bg-btv-700">Search</button>
          </div>

          {query.data && (
            <div>
              <MetricCard label="Results" value={query.data.count ?? 0} className="mb-4 inline-block" />
              <div className="space-y-2">
                {(query.data.threats ?? []).map((t: Record<string, unknown>) => {
                  const sev = Number(t.severity ?? 0);
                  const color = sev >= 8 ? 'text-red-600' : sev >= 5 ? 'text-amber-500' : 'text-blue-600';
                  return (
                    <details key={String(t.id)} className="border rounded-lg">
                      <summary className="px-4 py-3 cursor-pointer hover:bg-gray-50 dark:hover:bg-gray-800">
                        <span className={clsx('font-medium', color)}>[{String(t.source)}]</span>{' '}
                        {String(t.threat_type)} (severity {sev})
                      </summary>
                      <div className="px-4 pb-3 text-sm space-y-1">
                        <p><strong>ID:</strong> {String(t.id)}</p>
                        <p><strong>Description:</strong> {String(t.description ?? 'N/A')}</p>
                        <p><strong>MITRE:</strong> {String(t.mitre_id ?? 'N/A')}</p>
                        <p><strong>Indicators:</strong> {(t.indicators as string[] ?? []).join(', ')}</p>
                        <p><strong>Hash:</strong> <code>{String(t.hash ?? '')}</code></p>
                      </div>
                    </details>
                  );
                })}
              </div>
            </div>
          )}

          {stats.data && (
            <div className="mt-6 grid grid-cols-3 gap-4">
              <MetricCard label="Total Threats" value={stats.data.total_threats ?? 0} />
              <MetricCard label="Avg Severity" value={stats.data.avg_severity ?? 0} />
              <MetricCard label="Sources" value={Object.keys(stats.data.by_source ?? {}).length} />
            </div>
          )}
        </div>
      )}

      {tab === 'ingest' && (
        <form onSubmit={handleIngest} className="max-w-lg space-y-3">
          <input placeholder="Threat ID" value={form.id} onChange={e => setForm({ ...form, id: e.target.value })} className="w-full px-3 py-2 border rounded-lg dark:bg-gray-800 dark:border-gray-700" required />
          <select value={form.threat_type} onChange={e => setForm({ ...form, threat_type: e.target.value })} className="w-full px-3 py-2 border rounded-lg dark:bg-gray-800 dark:border-gray-700">
            {['prompt_injection', 'pii_leakage', 'data_exfiltration', 'social_engineering', 'other'].map(t => <option key={t} value={t}>{t}</option>)}
          </select>
          <label className="flex items-center gap-2 text-sm">Severity: <input type="range" min={1} max={10} value={form.severity} onChange={e => setForm({ ...form, severity: Number(e.target.value) })} className="w-48" /> {form.severity}</label>
          <select value={form.source} onChange={e => setForm({ ...form, source: e.target.value })} className="w-full px-3 py-2 border rounded-lg dark:bg-gray-800 dark:border-gray-700">
            {['OWASP', 'MISP', 'STIX', 'manual'].map(s => <option key={s} value={s}>{s}</option>)}
          </select>
          <input placeholder="Indicators (comma-separated)" value={form.indicators} onChange={e => setForm({ ...form, indicators: e.target.value })} className="w-full px-3 py-2 border rounded-lg dark:bg-gray-800 dark:border-gray-700" />
          <input placeholder="Description" value={form.description} onChange={e => setForm({ ...form, description: e.target.value })} className="w-full px-3 py-2 border rounded-lg dark:bg-gray-800 dark:border-gray-700" />
          <input placeholder="MITRE ATT&CK ID" value={form.mitre_id} onChange={e => setForm({ ...form, mitre_id: e.target.value })} className="w-full px-3 py-2 border rounded-lg dark:bg-gray-800 dark:border-gray-700" />
          <button type="submit" disabled={ingest.isPending} className="px-4 py-2 bg-btv-600 text-white rounded-lg font-medium hover:bg-btv-700 disabled:opacity-50">Ingest</button>
          {ingest.isSuccess && <p className="text-green-600 text-sm">Ingested successfully</p>}
          {ingest.isError && <p className="text-red-600 text-sm">Error: {ingest.error?.message}</p>}
        </form>
      )}
    </div>
  );
}
