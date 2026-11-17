import type { ConfusionMatrixData } from '../types';

interface ConfusionMatrixTableProps {
  data: ConfusionMatrixData;
  title?: string;
}

export function ConfusionMatrixTable({ data, title }: ConfusionMatrixTableProps) {
  const { labels, matrix } = data;
  const maxVal = Math.max(1, ...matrix.flat());

  return (
    <div className="space-y-3">
      {title && <h4 className="text-sm font-semibold text-slate-900 dark:text-slate-100">{title}</h4>}
      <div className="overflow-x-auto border border-slate-200 dark:border-slate-800 rounded-lg">
        <table className="w-full text-xs border-collapse">
          <thead>
            <tr className="bg-slate-100 dark:bg-slate-800/70 text-slate-600 dark:text-slate-300">
              <th className="px-3 py-2 text-left font-medium border-b border-r border-slate-200 dark:border-slate-800">
                True \ Pred
              </th>
              {labels.map((lbl) => (
                <th
                  key={lbl}
                  className="px-3 py-2 text-right font-medium border-b border-slate-200 dark:border-slate-800 whitespace-nowrap"
                >
                  {lbl}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {labels.map((rowLabel, rIdx) => (
              <tr key={rowLabel} className="border-b last:border-b-0 border-slate-200 dark:border-slate-800">
                <td className="px-3 py-2 font-medium text-slate-800 dark:text-slate-200 border-r border-slate-200 dark:border-slate-800 whitespace-nowrap bg-slate-50 dark:bg-slate-900/60">
                  {rowLabel}
                </td>
                {matrix[rIdx].map((val, cIdx) => {
                  const isDiag = rIdx === cIdx;
                  const intensity = val / maxVal;
                  const cellBg = isDiag
                    ? intensity > 0.5
                      ? 'bg-emerald-600/20 dark:bg-emerald-500/25 text-emerald-800 dark:text-emerald-200 font-semibold'
                      : 'bg-emerald-500/10 text-emerald-700 dark:text-emerald-300'
                    : val > 0
                      ? 'bg-rose-500/15 text-rose-700 dark:text-rose-300'
                      : 'text-slate-400 dark:text-slate-600';
                  return (
                    <td
                      key={`${rowLabel}-${cIdx}`}
                      className={`px-3 py-2 text-right font-mono tabular-nums ${cellBg}`}
                    >
                      {val}
                    </td>
                  );
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
