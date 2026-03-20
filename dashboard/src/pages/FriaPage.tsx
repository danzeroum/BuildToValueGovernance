import { useState } from 'react';
import { useGenerateFria } from '../hooks/useDecide';
import MetricCard from '../components/MetricCard';
import clsx from 'clsx';

const SECTORS = [
  'healthcare', 'employment', 'education', 'banking', 'insurance',
  'law_enforcement', 'justice', 'migration', 'biometric',
  'critical_infrastructure', 'essential_services', 'democratic_processes',
  'marketing', 'general_commercial', 'general',
];

const CAPABILITIES = [
  'chatbot', 'deepfake_generation', 'synthetic_content', 'emotion_detection',
  'biometric_categorization', 'subliminal_manipulation', 'social_scoring_public',
  'real_time_biometric_public', 'predictive_policing_profiling',
];

export default function FriaPage() {
  const [agentId, setAgentId] = useState('my-agent');
  const [sector, setSector] = useState('general');
  const [caps, setCaps] = useState<string[]>([]);
  const [safety, setSafety] = useState(false);
  const [rights, setRights] = useState(false);
  const fria = useGenerateFria();

  function toggleCap(cap: string) {
    setCaps(prev => prev.includes(cap) ? prev.filter(c => c !== cap) : [...prev, cap]);
  }

  function handleGenerate(e: React.FormEvent) {
    e.preventDefault();
    fria.mutate({ agent_id: agentId, sector, capabilities: caps, deployment_context: { safety_component: safety, affects_fundamental_rights: rights } });
  }

  const d = fria.data;
  const riskColors: Record<string, string> = {
    PROHIBITED: 'text-red-700', HIGH_RISK: 'text-orange-600',
    LIMITED_RISK: 'text-blue-600', MINIMAL_RISK: 'text-green-600',
  };

  return (
    <div>
      <h1 className="text-xl font-bold mb-1">Fundamental Rights Impact Assessment</h1>
      <p className="text-sm text-gray-500 mb-4">EU AI Act Art. 27 — auto-generated with manual review sections</p>

      <form onSubmit={handleGenerate} className="grid grid-cols-2 gap-4 mb-6">
        <div className="space-y-3">
          <input value={agentId} onChange={e => setAgentId(e.target.value)} placeholder="Agent ID" className="w-full px-3 py-2 border rounded-lg dark:bg-gray-800 dark:border-gray-700" />
          <select value={sector} onChange={e => setSector(e.target.value)} className="w-full px-3 py-2 border rounded-lg dark:bg-gray-800 dark:border-gray-700">
            {SECTORS.map(s => <option key={s} value={s}>{s}</option>)}
          </select>
        </div>
        <div className="space-y-2">
          <p className="text-sm font-medium">Capabilities</p>
          <div className="flex flex-wrap gap-2">
            {CAPABILITIES.map(c => (
              <button key={c} type="button" onClick={() => toggleCap(c)}
                className={clsx('text-xs px-2 py-1 rounded border', caps.includes(c) ? 'bg-btv-100 border-btv-400 text-btv-700' : 'bg-gray-50 dark:bg-gray-800')}
              >{c}</button>
            ))}
          </div>
          <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={safety} onChange={e => setSafety(e.target.checked)} /> Safety component</label>
          <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={rights} onChange={e => setRights(e.target.checked)} /> Affects fundamental rights</label>
        </div>
        <button type="submit" disabled={fria.isPending} className="col-span-2 px-4 py-2 bg-btv-600 text-white rounded-lg font-medium hover:bg-btv-700 disabled:opacity-50">
          Generate FRIA
        </button>
      </form>

      {fria.isError && <div className="p-3 bg-red-50 text-red-700 rounded-lg mb-4">Error: {fria.error?.message}</div>}

      {d && (
        <div>
          <p className={clsx('text-lg font-bold mb-4', riskColors[d.risk_level] ?? 'text-gray-600')}>
            Risk: {d.risk_level}
          </p>
          <div className="grid grid-cols-3 gap-4 mb-4">
            <MetricCard label="Sections" value={d.total_sections ?? 0} />
            <MetricCard label="Auto-filled" value={d.auto_filled ?? 0} />
            <MetricCard label="Manual Pending" value={d.manual_pending ?? 0} />
          </div>
          <p className="text-sm mb-2"><strong>Overall risk:</strong> {d.overall_risk ?? '?'}</p>
          <p className="text-sm bg-blue-50 dark:bg-blue-900/20 p-3 rounded-lg mb-4">{d.summary}</p>

          <div className="space-y-2">
            {(d.sections ?? []).map((s: Record<string, unknown>) => {
              const risk = String(s.risk_indicator ?? '?');
              const secColor: Record<string, string> = { LOW: 'text-green-600', MEDIUM: 'text-amber-500', HIGH: 'text-red-600', CRITICAL: 'text-red-700' };
              return (
                <details key={String(s.section_id)} className="border rounded-lg">
                  <summary className="px-4 py-3 cursor-pointer hover:bg-gray-50 dark:hover:bg-gray-800">
                    {s.manual_required ? '(manual)' : '(auto)'}{' '}
                    {String(s.section_id)} — {String(s.title)}{' '}
                    <span className={secColor[risk] ?? ''}>[{risk}]</span>
                  </summary>
                  <div className="px-4 pb-3 text-sm space-y-1">
                    <p><strong>Question:</strong> {String(s.question)}</p>
                    <p><strong>Auto-answer:</strong> {String(s.auto_answer)}</p>
                    <p className="text-xs text-gray-400">Article: {String(s.article_ref)}</p>
                    {s.manual_required ? <p className="text-amber-600 font-medium">Manual review required</p> : null}
                  </div>
                </details>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}
