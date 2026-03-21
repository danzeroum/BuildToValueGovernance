interface Props {
  label: string;
  value: string | number;
  className?: string;
}

export default function MetricCard({ label, value, className }: Props) {
  return (
    <div className={`bg-white dark:bg-gray-800 rounded-lg border p-4 ${className ?? ''}`}>
      <p className="text-xs text-gray-500 uppercase tracking-wide">{label}</p>
      <p className="text-2xl font-bold mt-1">{value}</p>
    </div>
  );
}
