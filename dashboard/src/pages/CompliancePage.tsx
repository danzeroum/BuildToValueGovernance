import { useState } from 'react';
import { useComplianceReport } from '../hooks/useDecide';
import MetricCard from '../components/MetricCard';
import clsx from 'clsx';

export default function CompliancePage() {
  const [framework, setFramework] = useState('LGPD');
  const report = useComplianceReport();

  function handleGenerate(e: React.FormEvent) {
    e.preventDefault();
    report.mutate(framework);
  }

  async function handleExportPdf() {
    if (!report.data) return;
    const { default: jsPDF } = await import('jspdf');
    const doc = new jsPDF();
    doc.setFontSize(18);
    doc.text(`${framework} Compliance Report`, 20, 20);
    doc.setFontSize(12);
    doc.text(`Compliance Rate: ${((report.data.compliance_rate ?? 0) * 100).toFixed(0)}%`, 20, 35);
    doc.text(`Generated: ${new Date().toISOString()}`, 20, 45);

    let y = 60;
    for (const a of report.data.artifacts ?? []) {
      if (y > 270) { doc.addPage(); y = 20; }
      doc.setFontSize(10);
      doc.text(`${a.article} - ${a.requirement}`, 20, y);
      y += 6;
      doc.text(`Status: ${a.status}`, 25, y);
      y += 10;
    }
    doc.save(`btv-compliance-${framework}-${Date.now()}.pdf`);
  }

  const d = report.data;
  const rate = d?.compliance_rate ?? 0;

  return (
    <div>
      <h1 className="text-xl font-bold mb-4">Compliance Reports</h1>

      <form onSubmit={handleGenerate} className="flex gap-3 mb-6">
        <select
          value={framework}
          onChange={(e) => setFramework(e.target.value)}
          className="px-3 py-2 border rounded-lg dark:bg-gray-800 dark:border-gray-700"
        >
          <option value="LGPD">LGPD</option>
          <option value="EU_AI_ACT">EU AI Act</option>
        </select>
        <button type="submit" disabled={report.isPending}
          className="px-4 py-2 bg-btv-600 text-white rounded-lg font-medium hover:bg-btv-700 disabled:opacity-50"
        >
          Generate Report
        </button>
        {d && (
          <button type="button" onClick={handleExportPdf}
            className="px-4 py-2 border rounded-lg font-medium hover:bg-gray-50 dark:hover:bg-gray-700"
          >
            Export PDF
          </button>
        )}
      </form>

      {report.isError && (
        <div className="p-3 bg-red-50 text-red-700 rounded-lg mb-4">Error: {report.error?.message}</div>
      )}

      {d && (
        <div>
          <p className={clsx('text-lg font-bold mb-4', rate === 1.0 ? 'text-green-600' : 'text-amber-500')}>
            {framework} — {(rate * 100).toFixed(0)}% Compliant
          </p>

          <div className="grid grid-cols-3 gap-4 mb-6">
            <MetricCard label="Compliant" value={d.compliant ?? 0} />
            <MetricCard label="Partial" value={d.partial ?? 0} />
            <MetricCard label="Non-Compliant" value={d.non_compliant ?? 0} />
          </div>

          <div className="space-y-2" id="compliance-report">
            {(d.artifacts ?? []).map((a: Record<string, string>, i: number) => {
              const icon = a.status === 'COMPLIANT' ? 'text-green-600' : a.status === 'PARTIAL' ? 'text-amber-500' : 'text-red-600';
              return (
                <details key={i} className="border rounded-lg">
                  <summary className="px-4 py-3 cursor-pointer hover:bg-gray-50 dark:hover:bg-gray-800 flex items-center gap-2">
                    <span className={clsx('font-medium', icon)}>{a.status}</span>
                    <span className="text-sm">{a.article} — {a.requirement}</span>
                  </summary>
                  <div className="px-4 pb-3 text-sm space-y-1">
                    <p><strong>Evidence:</strong> {a.evidence || 'N/A'}</p>
                    <p><strong>Recommendation:</strong> {a.recommendation || 'N/A'}</p>
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
