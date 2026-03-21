import clsx from 'clsx';

const COLORS: Record<string, string> = {
  ALLOW: 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200',
  LOG: 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200',
  EDUCATE: 'bg-amber-100 text-amber-800 dark:bg-amber-900 dark:text-amber-200',
  REDACT: 'bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-200',
  BLOCK: 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200',
  INSPECT: 'bg-purple-100 text-purple-800 dark:bg-purple-900 dark:text-purple-200',
};

export default function ActionBadge({ action }: { action: string }) {
  return (
    <span className={clsx('px-3 py-1 rounded-full text-sm font-semibold', COLORS[action] ?? 'bg-gray-100 text-gray-800')}>
      {action}
    </span>
  );
}
