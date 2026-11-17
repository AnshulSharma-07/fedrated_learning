import type {
  AttackCategory,
  ClassificationMode,
  DatasetCleanReport,
  FlowRecord,
  PreparedSplit,
  ScalerParams,
} from './types';

export const CORE_FEATURES: Array<keyof Omit<FlowRecord, 'label' | 'source_ip' | 'destination_ip' | 'timestamp'>> = [
  'flow_duration',
  'total_fwd_packets',
  'total_bwd_packets',
  'fwd_packet_length_mean',
  'bwd_packet_length_mean',
  'flow_bytes_per_sec',
  'flow_packets_per_sec',
  'syn_flag_count',
  'ack_flag_count',
  'rst_flag_count',
  'psh_flag_count',
  'iat_mean',
  'init_win_bytes_fwd',
  'subflow_fwd_bytes',
];

export const ATTACK_CATEGORIES: AttackCategory[] = [
  'Benign',
  'DoS/DDoS',
  'PortScan',
  'BruteForce',
  'Botnet',
  'WebAttack',
];

const LEAKAGE_COLUMN_PATTERNS = [
  'flow id',
  'flow_id',
  'source ip',
  'src ip',
  'source_ip',
  'src_ip',
  'srcip',
  'destination ip',
  'dst ip',
  'destination_ip',
  'dst_ip',
  'dstip',
  'timestamp',
  'source port',
  'src port',
  'src_port',
  'sport',
  'id',
];

const COLUMN_ALIASES: Record<string, string> = {
  'flow duration': 'flow_duration',
  'dur': 'flow_duration',
  'total fwd packets': 'total_fwd_packets',
  'tot fwd pkts': 'total_fwd_packets',
  'spkts': 'total_fwd_packets',
  'total backward packets': 'total_bwd_packets',
  'tot bwd pkts': 'total_bwd_packets',
  'dpkts': 'total_bwd_packets',
  'fwd packet length mean': 'fwd_packet_length_mean',
  'fwd pkt len mean': 'fwd_packet_length_mean',
  'smean': 'fwd_packet_length_mean',
  'bwd packet length mean': 'bwd_packet_length_mean',
  'bwd pkt len mean': 'bwd_packet_length_mean',
  'dmean': 'bwd_packet_length_mean',
  'flow bytes/s': 'flow_bytes_per_sec',
  'flow byts/s': 'flow_bytes_per_sec',
  'rate': 'flow_bytes_per_sec',
  'flow packets/s': 'flow_packets_per_sec',
  'flow pkts/s': 'flow_packets_per_sec',
  'syn flag count': 'syn_flag_count',
  'syn flag cnt': 'syn_flag_count',
  'ack flag count': 'ack_flag_count',
  'ack flag cnt': 'ack_flag_count',
  'rst flag count': 'rst_flag_count',
  'rst flag cnt': 'rst_flag_count',
  'psh flag count': 'psh_flag_count',
  'psh flag cnt': 'psh_flag_count',
  'flow iat mean': 'iat_mean',
  'iat_mean': 'iat_mean',
  'sinpkt': 'iat_mean',
  'init_win_bytes_forward': 'init_win_bytes_fwd',
  'init fwd win byts': 'init_win_bytes_fwd',
  'swin': 'init_win_bytes_fwd',
  'subflow fwd bytes': 'subflow_fwd_bytes',
  'sbytes': 'subflow_fwd_bytes',
  'label': 'label',
  'attack_cat': 'label',
  'class': 'label',
};

export function createSeededRng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function gaussian(rng: () => number, mean: number, std: number): number {
  const u1 = Math.max(1e-7, rng());
  const u2 = rng();
  const z = Math.sqrt(-2.0 * Math.log(u1)) * Math.cos(2.0 * Math.PI * u2);
  return mean + z * std;
}

export function normalizeAttackLabel(raw: string | undefined): AttackCategory {
  if (!raw) return 'Benign';
  const s = raw.trim().toLowerCase();
  if (s === 'benign' || s === 'normal' || s === '0') return 'Benign';
  if (s.includes('dos') || s.includes('ddos') || s.includes('hulk') || s.includes('goldeneye') || s.includes('slowloris')) {
    return 'DoS/DDoS';
  }
  if (s.includes('port') || s.includes('scan') || s.includes('recon')) return 'PortScan';
  if (s.includes('brute') || s.includes('patator') || s.includes('ssh') || s.includes('ftp')) return 'BruteForce';
  if (s.includes('bot') || s.includes('backdoor') || s.includes('c2')) return 'Botnet';
  if (s.includes('web') || s.includes('xss') || s.includes('sql')) return 'WebAttack';
  if (s === '1' || s === 'malicious' || s === 'attack') return 'DoS/DDoS';
  return 'Botnet';
}

export function generateSyntheticCicIdsDataset(totalRows = 1200, seed = 42): FlowRecord[] {
  const rng = createSeededRng(seed);
  // Realistic imbalanced distribution (~62% Benign, 38% attacks across 5 categories)
  const categoryWeights: Array<{ category: AttackCategory; share: number }> = [
    { category: 'Benign', share: 0.62 },
    { category: 'DoS/DDoS', share: 0.14 },
    { category: 'PortScan', share: 0.09 },
    { category: 'BruteForce', share: 0.06 },
    { category: 'Botnet', share: 0.05 },
    { category: 'WebAttack', share: 0.04 },
  ];

  const records: FlowRecord[] = [];
  const baseTime = Date.UTC(2026, 10, 17, 8, 0, 0);

  for (let i = 0; i < totalRows; i++) {
    const pick = rng();
    let acc = 0;
    let category: AttackCategory = 'Benign';
    for (const item of categoryWeights) {
      acc += item.share;
      if (pick <= acc) {
        category = item.category;
        break;
      }
    }

    const pos = (v: number, min = 0) => Math.max(min, Math.round(v * 100) / 100);
    // Occasional borderline/noisy traffic profiles mimic real CIC-IDS2017 overlap
    const jitter = rng() < 0.14 ? 2.1 : 1.0;
    let rec: FlowRecord;

    if (category === 'Benign') {
      const dur = pos(gaussian(rng, 245000, 155000 * jitter), 900);
      const fwd = Math.max(1, Math.round(gaussian(rng, 10, 6 * jitter)));
      const bwd = Math.max(1, Math.round(gaussian(rng, 8, 5 * jitter)));
      const fLen = pos(gaussian(rng, 175, 95 * jitter), 28);
      const bLen = pos(gaussian(rng, 390, 180 * jitter), 20);
      rec = {
        flow_duration: dur,
        total_fwd_packets: fwd,
        total_bwd_packets: bwd,
        fwd_packet_length_mean: fLen,
        bwd_packet_length_mean: bLen,
        flow_bytes_per_sec: pos(((fwd * fLen + bwd * bLen) / (dur / 1e6)) + gaussian(rng, 0, 2400), 100),
        flow_packets_per_sec: pos(((fwd + bwd) / (dur / 1e6)) + gaussian(rng, 0, 35), 2),
        syn_flag_count: rng() < 0.82 ? 1 : 2,
        ack_flag_count: Math.max(1, Math.round(gaussian(rng, 7, 4))),
        rst_flag_count: rng() < 0.12 ? 1 : 0,
        psh_flag_count: Math.max(0, Math.round(gaussian(rng, 3, 2))),
        iat_mean: pos(dur / Math.max(1, fwd + bwd) + gaussian(rng, 3500, 2800), 200),
        init_win_bytes_fwd: rng() < 0.55 ? 29200 : rng() < 0.8 ? 8192 : 64240,
        subflow_fwd_bytes: pos(fwd * fLen + gaussian(rng, 40, 80), 40),
        label: 'Benign',
      };
    } else if (category === 'DoS/DDoS') {
      const dur = pos(gaussian(rng, 28000, 22000 * jitter), 250);
      const fwd = Math.max(6, Math.round(gaussian(rng, 52, 26 * jitter)));
      const bwd = Math.max(0, Math.round(gaussian(rng, 3, 3 * jitter)));
      const fLen = pos(gaussian(rng, 68, 38 * jitter), 20);
      const bLen = pos(gaussian(rng, 35, 35 * jitter), 0);
      rec = {
        flow_duration: dur,
        total_fwd_packets: fwd,
        total_bwd_packets: bwd,
        fwd_packet_length_mean: fLen,
        bwd_packet_length_mean: bLen,
        flow_bytes_per_sec: pos(gaussian(rng, 155000, 68000 * jitter), 8000),
        flow_packets_per_sec: pos(gaussian(rng, 3100, 1450 * jitter), 180),
        syn_flag_count: Math.max(1, Math.round(gaussian(rng, 5, 3))),
        ack_flag_count: Math.max(0, Math.round(gaussian(rng, 2, 2))),
        rst_flag_count: Math.max(0, Math.round(gaussian(rng, 2, 1.4))),
        psh_flag_count: rng() < 0.25 ? 1 : 0,
        iat_mean: pos(gaussian(rng, 680, 520 * jitter), 20),
        init_win_bytes_fwd: rng() < 0.7 ? 512 : 8192,
        subflow_fwd_bytes: pos(fwd * fLen, 160),
        label: 'DoS/DDoS',
      };
    } else if (category === 'PortScan') {
      const dur = pos(gaussian(rng, 4500, 3800 * jitter), 80);
      const fwd = Math.max(1, Math.round(gaussian(rng, 3, 2)));
      const bwd = Math.max(0, Math.round(gaussian(rng, 1, 1.2)));
      const fLen = pos(gaussian(rng, 56, 26 * jitter), 20);
      rec = {
        flow_duration: dur,
        total_fwd_packets: fwd,
        total_bwd_packets: bwd,
        fwd_packet_length_mean: fLen,
        bwd_packet_length_mean: pos(gaussian(rng, 45, 35 * jitter), 0),
        flow_bytes_per_sec: pos(gaussian(rng, 42000, 24000 * jitter), 1800),
        flow_packets_per_sec: pos(gaussian(rng, 1150, 620 * jitter), 60),
        syn_flag_count: 1,
        ack_flag_count: rng() < 0.35 ? 1 : 0,
        rst_flag_count: Math.max(0, Math.round(gaussian(rng, 1.2, 0.7))),
        psh_flag_count: 0,
        iat_mean: pos(gaussian(rng, 980, 650 * jitter), 40),
        init_win_bytes_fwd: rng() < 0.75 ? 1024 : 8192,
        subflow_fwd_bytes: pos(fwd * fLen, 28),
        label: 'PortScan',
      };
    } else if (category === 'BruteForce') {
      const dur = pos(gaussian(rng, 360000, 140000 * jitter), 40000);
      const fwd = Math.max(6, Math.round(gaussian(rng, 19, 8 * jitter)));
      const bwd = Math.max(4, Math.round(gaussian(rng, 16, 7 * jitter)));
      const fLen = pos(gaussian(rng, 132, 45 * jitter), 50);
      const bLen = pos(gaussian(rng, 185, 75 * jitter), 50);
      rec = {
        flow_duration: dur,
        total_fwd_packets: fwd,
        total_bwd_packets: bwd,
        fwd_packet_length_mean: fLen,
        bwd_packet_length_mean: bLen,
        flow_bytes_per_sec: pos(gaussian(rng, 16500, 8200 * jitter), 1800),
        flow_packets_per_sec: pos(gaussian(rng, 105, 52 * jitter), 15),
        syn_flag_count: 1,
        ack_flag_count: Math.max(4, Math.round(gaussian(rng, 15, 6))),
        rst_flag_count: rng() < 0.5 ? 1 : 0,
        psh_flag_count: Math.max(2, Math.round(gaussian(rng, 9, 4))),
        iat_mean: pos(gaussian(rng, 9200, 4600 * jitter), 900),
        init_win_bytes_fwd: rng() < 0.8 ? 29200 : 64240,
        subflow_fwd_bytes: pos(fwd * fLen, 500),
        label: 'BruteForce',
      };
    } else if (category === 'Botnet') {
      const dur = pos(gaussian(rng, 680000, 290000 * jitter), 90000);
      const fwd = Math.max(4, Math.round(gaussian(rng, 12, 5 * jitter)));
      const bwd = Math.max(4, Math.round(gaussian(rng, 12, 5 * jitter)));
      const fLen = pos(gaussian(rng, 110, 48 * jitter), 36);
      const bLen = pos(gaussian(rng, 145, 75 * jitter), 36);
      rec = {
        flow_duration: dur,
        total_fwd_packets: fwd,
        total_bwd_packets: bwd,
        fwd_packet_length_mean: fLen,
        bwd_packet_length_mean: bLen,
        flow_bytes_per_sec: pos(gaussian(rng, 5200, 3800 * jitter), 300),
        flow_packets_per_sec: pos(gaussian(rng, 42, 22 * jitter), 6),
        syn_flag_count: 1,
        ack_flag_count: Math.max(3, Math.round(gaussian(rng, 11, 4))),
        rst_flag_count: rng() < 0.15 ? 1 : 0,
        psh_flag_count: Math.max(2, Math.round(gaussian(rng, 7, 3))),
        iat_mean: pos(gaussian(rng, 26000, 12500 * jitter), 3000),
        init_win_bytes_fwd: rng() < 0.65 ? 65535 : 29200,
        subflow_fwd_bytes: pos(fwd * fLen, 240),
        label: 'Botnet',
      };
    } else {
      // WebAttack (SQLi / XSS)
      const dur = pos(gaussian(rng, 295000, 125000 * jitter), 25000);
      const fwd = Math.max(5, Math.round(gaussian(rng, 15, 6 * jitter)));
      const bwd = Math.max(4, Math.round(gaussian(rng, 12, 5 * jitter)));
      const fLen = pos(gaussian(rng, 410, 165 * jitter), 120);
      const bLen = pos(gaussian(rng, 540, 210 * jitter), 120);
      rec = {
        flow_duration: dur,
        total_fwd_packets: fwd,
        total_bwd_packets: bwd,
        fwd_packet_length_mean: fLen,
        bwd_packet_length_mean: bLen,
        flow_bytes_per_sec: pos(gaussian(rng, 52000, 24000 * jitter), 8000),
        flow_packets_per_sec: pos(gaussian(rng, 98, 45 * jitter), 18),
        syn_flag_count: 1,
        ack_flag_count: Math.max(4, Math.round(gaussian(rng, 13, 5))),
        rst_flag_count: rng() < 0.1 ? 1 : 0,
        psh_flag_count: Math.max(2, Math.round(gaussian(rng, 6, 3))),
        iat_mean: pos(gaussian(rng, 9800, 4500 * jitter), 1200),
        init_win_bytes_fwd: rng() < 0.7 ? 64240 : 29200,
        subflow_fwd_bytes: pos(fwd * fLen, 1200),
        label: 'WebAttack',
      };
    }

    rec.timestamp = new Date(baseTime + i * 1200).toISOString();
    records.push(rec);
  }
  return records;
}

export function parseCsvLine(line: string): string[] {
  const result: string[] = [];
  let cur = '';
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === '"') {
      if (inQuotes && line[i + 1] === '"') {
        cur += '"';
        i++;
      } else {
        inQuotes = !inQuotes;
      }
    } else if (ch === ',' && !inQuotes) {
      result.push(cur.trim());
      cur = '';
    } else {
      cur += ch;
    }
  }
  result.push(cur.trim());
  return result;
}

export function parseAndCleanCsv(
  csvText: string,
  columnMapping?: Record<string, string>,
  isSynthetic = false,
): { records: FlowRecord[]; report: DatasetCleanReport } {
  const lines = csvText
    .replace(/\r\n/g, '\n')
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l.length > 0);

  if (lines.length < 2) {
    throw new Error('CSV must include a header row and at least one data row');
  }

  const rawHeaders = parseCsvLine(lines[0]);
  const removedLeakageColumns: string[] = [];
  const headerToCanonical: Array<string | null> = rawHeaders.map((h) => {
    const norm = h.trim().toLowerCase();
    if (columnMapping && columnMapping[h]) {
      return columnMapping[h];
    }
    if (LEAKAGE_COLUMN_PATTERNS.includes(norm)) {
      removedLeakageColumns.push(h.trim());
      return null;
    }
    if (CORE_FEATURES.includes(norm as typeof CORE_FEATURES[number])) {
      return norm;
    }
    if (COLUMN_ALIASES[norm]) {
      return COLUMN_ALIASES[norm];
    }
    return null;
  });

  const seenRows = new Set<string>();
  let droppedMissing = 0;
  let droppedInfinite = 0;
  let droppedDuplicates = 0;
  const records: FlowRecord[] = [];
  const classDistribution: Record<string, number> = {};

  for (let i = 1; i < lines.length; i++) {
    const cells = parseCsvLine(lines[i]);
    if (cells.length !== rawHeaders.length) {
      droppedMissing++;
      continue;
    }
    const rowObj: Record<string, number | string> = {};
    let hasMissing = false;
    let hasInf = false;

    for (let c = 0; c < rawHeaders.length; c++) {
      const target = headerToCanonical[c];
      if (!target) continue;
      const val = cells[c];
      if (target === 'label') {
        rowObj.label = val;
        continue;
      }
      if (val === '' || val.toLowerCase() === 'nan' || val.toLowerCase() === 'null') {
        hasMissing = true;
        break;
      }
      const num = Number(val);
      if (Number.isNaN(num)) {
        hasMissing = true;
        break;
      }
      if (!Number.isFinite(num)) {
        hasInf = true;
        break;
      }
      rowObj[target] = num;
    }

    if (hasMissing) {
      droppedMissing++;
      continue;
    }
    if (hasInf) {
      droppedInfinite++;
      continue;
    }

    const record: FlowRecord = {
      flow_duration: Number(rowObj.flow_duration ?? 0),
      total_fwd_packets: Number(rowObj.total_fwd_packets ?? 0),
      total_bwd_packets: Number(rowObj.total_bwd_packets ?? 0),
      fwd_packet_length_mean: Number(rowObj.fwd_packet_length_mean ?? 0),
      bwd_packet_length_mean: Number(rowObj.bwd_packet_length_mean ?? 0),
      flow_bytes_per_sec: Number(rowObj.flow_bytes_per_sec ?? 0),
      flow_packets_per_sec: Number(rowObj.flow_packets_per_sec ?? 0),
      syn_flag_count: Number(rowObj.syn_flag_count ?? 0),
      ack_flag_count: Number(rowObj.ack_flag_count ?? 0),
      rst_flag_count: Number(rowObj.rst_flag_count ?? 0),
      psh_flag_count: Number(rowObj.psh_flag_count ?? 0),
      iat_mean: Number(rowObj.iat_mean ?? 0),
      init_win_bytes_fwd: Number(rowObj.init_win_bytes_fwd ?? 0),
      subflow_fwd_bytes: Number(rowObj.subflow_fwd_bytes ?? 0),
      label: rowObj.label !== undefined ? normalizeAttackLabel(String(rowObj.label)) : undefined,
    };

    const sig = CORE_FEATURES.map((f) => record[f]).join('|') + '|' + (record.label ?? '');
    if (seenRows.has(sig)) {
      droppedDuplicates++;
      continue;
    }
    seenRows.add(sig);

    const lbl = record.label ?? 'Unlabeled';
    classDistribution[lbl] = (classDistribution[lbl] || 0) + 1;
    records.push(record);
  }

  return {
    records,
    report: {
      rawRows: lines.length - 1,
      cleanRows: records.length,
      droppedMissing,
      droppedInfinite,
      droppedDuplicates,
      removedLeakageColumns,
      classDistribution,
      featureColumns: [...CORE_FEATURES],
      isSynthetic,
    },
  };
}

export function recordsToCsv(records: FlowRecord[]): string {
  const headers = [...CORE_FEATURES, 'label'];
  const rows = records.map((r) =>
    [...CORE_FEATURES.map((f) => String(r[f])), r.label ?? 'Benign'].join(','),
  );
  return [headers.join(','), ...rows].join('\n');
}

export function extractFeatureVector(record: FlowRecord): number[] {
  return CORE_FEATURES.map((f) => Number(record[f] ?? 0));
}

export function fitScaler(XTrain: number[][]): ScalerParams {
  const d = CORE_FEATURES.length;
  const n = Math.max(1, XTrain.length);
  const means = new Array(d).fill(0);
  const stds = new Array(d).fill(0);

  for (const row of XTrain) {
    for (let j = 0; j < d; j++) means[j] += row[j];
  }
  for (let j = 0; j < d; j++) means[j] /= n;

  for (const row of XTrain) {
    for (let j = 0; j < d; j++) {
      const diff = row[j] - means[j];
      stds[j] += diff * diff;
    }
  }
  for (let j = 0; j < d; j++) {
    stds[j] = Math.sqrt(stds[j] / n);
    if (stds[j] < 1e-6) stds[j] = 1;
  }

  return { featureNames: [...CORE_FEATURES], means, stds };
}

export function transformWithScaler(X: number[][], scaler: ScalerParams): number[][] {
  return X.map((row) => row.map((v, j) => (v - scaler.means[j]) / scaler.stds[j]));
}

export function prepareStratifiedSplit(
  records: FlowRecord[],
  mode: ClassificationMode,
  seed = 42,
): PreparedSplit {
  const labeled = records.filter((r) => r.label !== undefined);
  if (labeled.length < 30) {
    throw new Error('At least 30 labeled records are required for stratified splitting');
  }

  const classes =
    mode === 'binary'
      ? ['Benign', 'Malicious']
      : ATTACK_CATEGORIES.filter((cat) => labeled.some((r) => r.label === cat));

  const classToIndex = new Map<string, number>();
  classes.forEach((c, idx) => classToIndex.set(c, idx));

  const buckets = new Map<number, FlowRecord[]>();
  for (const rec of labeled) {
    const labelStr = mode === 'binary' ? (rec.label === 'Benign' ? 'Benign' : 'Malicious') : (rec.label as string);
    const idx = classToIndex.get(labelStr);
    if (idx === undefined) continue;
    if (!buckets.has(idx)) buckets.set(idx, []);
    buckets.get(idx)!.push(rec);
  }

  const rng = createSeededRng(seed);
  const trainRecs: Array<{ x: number[]; y: number }> = [];
  const valRecs: Array<{ x: number[]; y: number }> = [];
  const testRecs: Array<{ x: number[]; y: number }> = [];

  for (const [clsIdx, list] of buckets.entries()) {
    const shuffled = [...list];
    for (let i = shuffled.length - 1; i > 0; i--) {
      const j = Math.floor(rng() * (i + 1));
      [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
    }
    const nTrain = Math.max(1, Math.floor(shuffled.length * 0.7));
    const nVal = Math.max(1, Math.floor(shuffled.length * 0.15));
    for (let i = 0; i < shuffled.length; i++) {
      const item = { x: extractFeatureVector(shuffled[i]), y: clsIdx };
      if (i < nTrain) trainRecs.push(item);
      else if (i < nTrain + nVal) valRecs.push(item);
      else testRecs.push(item);
    }
  }

  const shufflePairs = (arr: Array<{ x: number[]; y: number }>) => {
    for (let i = arr.length - 1; i > 0; i--) {
      const j = Math.floor(rng() * (i + 1));
      [arr[i], arr[j]] = [arr[j], arr[i]];
    }
  };
  shufflePairs(trainRecs);
  shufflePairs(valRecs);
  shufflePairs(testRecs);

  const rawXTrain = trainRecs.map((r) => r.x);
  // Fit scaler strictly on training split to prevent preprocessing leakage
  const scaler = fitScaler(rawXTrain);

  const yTrain = trainRecs.map((r) => r.y);
  const counts: Record<number, number> = {};
  for (const y of yTrain) counts[y] = (counts[y] || 0) + 1;
  const maxCount = Math.max(...Object.values(counts));
  const minCount = Math.max(1, Math.min(...Object.values(counts)));
  const classWeights: Record<number, number> = {};
  for (let c = 0; c < classes.length; c++) {
    const cnt = Math.max(1, counts[c] || 1);
    classWeights[c] = Math.min(4.0, yTrain.length / (classes.length * cnt));
  }

  return {
    XTrain: transformWithScaler(rawXTrain, scaler),
    yTrain,
    XVal: transformWithScaler(valRecs.map((r) => r.x), scaler),
    yVal: valRecs.map((r) => r.y),
    XTest: transformWithScaler(testRecs.map((r) => r.x), scaler),
    yTest: testRecs.map((r) => r.y),
    classes,
    scaler,
    classWeights,
    imbalanceRatio: Number((maxCount / minCount).toFixed(2)),
  };
}

export interface ClientPartition {
  clientId: string;
  X: number[][];
  y: number[];
  classCounts: Record<string, number>;
}

/**
 * Partition training data into non-IID organization subsets.
 * Each client receives a skewed distribution over attack categories using
 * Dirichlet-style allocation controlled by alpha (smaller alpha = stronger non-IID skew).
 */
export function partitionNonIid(
  XTrain: number[][],
  yTrain: number[],
  classes: string[],
  clientIds: string[],
  alpha = 0.5,
  seed = 42,
): ClientPartition[] {
  const rng = createSeededRng(seed);
  const numClients = clientIds.length;
  const partitions: ClientPartition[] = clientIds.map((clientId) => ({
    clientId,
    X: [],
    y: [],
    classCounts: {},
  }));

  // Group sample indices by class
  const byClass: number[][] = classes.map(() => []);
  for (let i = 0; i < yTrain.length; i++) {
    byClass[yTrain[i]].push(i);
  }

  // Approximate Gamma sampling for Dirichlet(alpha)
  const sampleGamma = (shape: number): number => {
    const s = Math.max(0.15, shape);
    let sum = 0;
    const k = Math.max(1, Math.round(s * 2));
    for (let i = 0; i < k; i++) {
      sum -= Math.log(Math.max(1e-7, rng()));
    }
    return sum * (s / k);
  };

  for (let c = 0; c < classes.length; c++) {
    const indices = [...byClass[c]];
    for (let i = indices.length - 1; i > 0; i--) {
      const j = Math.floor(rng() * (i + 1));
      [indices[i], indices[j]] = [indices[j], indices[i]];
    }

    // Generate skewed client proportions for class c
    const rawProps = clientIds.map((_, idx) => {
      // Give different organizations natural affinity to different attack types
      const affinityBoost = (c + idx) % numClients === 0 ? 2.5 : 1.0;
      return Math.pow(sampleGamma(alpha), 1 / Math.max(0.2, alpha)) * affinityBoost;
    });
    const propSum = rawProps.reduce((a, b) => a + b, 0) || 1;
    const normalized = rawProps.map((p) => p / propSum);

    let cursor = 0;
    for (let k = 0; k < numClients; k++) {
      const count =
        k === numClients - 1
          ? indices.length - cursor
          : Math.max(1, Math.floor(indices.length * normalized[k]));
      const slice = indices.slice(cursor, Math.min(indices.length, cursor + count));
      cursor += slice.length;
      const clsName = classes[c];
      for (const idx of slice) {
        partitions[k].X.push(XTrain[idx]);
        partitions[k].y.push(yTrain[idx]);
        partitions[k].classCounts[clsName] = (partitions[k].classCounts[clsName] || 0) + 1;
      }
    }
  }

  return partitions;
}
