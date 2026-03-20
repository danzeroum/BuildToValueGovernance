interface Props {
  data: unknown;
  label?: string;
}

export default function JsonViewer({ data, label }: Props) {
  return (
    <details className="mt-2">
      <summary className="text-sm text-gray-500 cursor-pointer hover:text-gray-700">
        {label ?? 'Full Response'}
      </summary>
      <pre className="mt-2 p-3 bg-gray-50 dark:bg-gray-900 rounded-lg text-xs overflow-x-auto border">
        {JSON.stringify(data, null, 2)}
      </pre>
    </details>
  );
}
