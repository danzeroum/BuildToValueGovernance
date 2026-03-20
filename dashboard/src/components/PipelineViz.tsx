import clsx from 'clsx';

interface Stage {
  name: string;
  rationale: string;
  status: 'pending' | 'active' | 'done';
}

interface Props {
  stages: Stage[];
  latencyMs?: number;
  mercyApplied?: boolean;
}

const STAGE_COLORS = {
  pending: 'border-gray-300 bg-gray-50 dark:bg-gray-800',
  active: 'border-btv-400 bg-btv-50 dark:bg-btv-900/30 animate-pulse',
  done: 'border-green-400 bg-green-50 dark:bg-green-900/20',
};

export function buildStages(explain: Record<string, unknown> | undefined): Stage[] {
  if (!explain) return [];
  return [
    { name: 'Rawls', rationale: String(explain.rawls_rationale ?? ''), status: 'done' as const },
    { name: 'Levinas', rationale: String(explain.levinas_rationale ?? ''), status: 'done' as const },
    { name: 'Jonas', rationale: String(explain.jonas_rationale ?? ''), status: 'done' as const },
    { name: 'Gilligan', rationale: String(explain.gilligan_rationale ?? ''), status: 'done' as const },
  ];
}

export default function PipelineViz({ stages, latencyMs, mercyApplied }: Props) {
  if (stages.length === 0) return null;

  return (
    <div className="mt-4">
      <div className="flex items-center gap-1 mb-2">
        <h3 className="text-sm font-semibold">Philosophical Pipeline</h3>
        {latencyMs != null && (
          <span className="text-xs text-gray-400 ml-2">{latencyMs.toFixed(1)}ms</span>
        )}
        {mercyApplied && (
          <span className="ml-2 px-2 py-0.5 text-xs rounded-full bg-green-100 text-green-700">
            Mercy Applied
          </span>
        )}
      </div>
      <div className="flex gap-2 overflow-x-auto">
        {stages.map((stage, i) => (
          <div key={stage.name} className="flex items-center gap-2">
            <div className={clsx('border-2 rounded-lg p-3 min-w-[150px]', STAGE_COLORS[stage.status])}>
              <p className="font-medium text-sm">{stage.name}</p>
              <p className="text-xs text-gray-500 mt-1 line-clamp-3">{stage.rationale || 'Awaiting...'}</p>
            </div>
            {i < stages.length - 1 && (
              <span className="text-gray-300 text-lg shrink-0">&rarr;</span>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
