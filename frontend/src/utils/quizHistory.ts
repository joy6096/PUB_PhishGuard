
export type QuizHistoryEntry = {
  id: string;
  completedAt: string;
  score: number;
  total: number;
  percentage: number;
  correctAnswers: number;
};

const STORAGE_KEY = 'pub-phishguard-awareness-quiz-history-v1';
const MAX_HISTORY_ITEMS = 50;

export function readQuizHistory(): QuizHistoryEntry[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];

    const parsed: unknown = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];

    return parsed.filter((item): item is QuizHistoryEntry => {
      return (
        typeof item?.id === 'string' &&
        typeof item?.completedAt === 'string' &&
        typeof item?.score === 'number' &&
        typeof item?.total === 'number' &&
        typeof item?.percentage === 'number' &&
        typeof item?.correctAnswers === 'number'
      );
    });
  } catch {
    return [];
  }
}

export function saveQuizResult(
  correctAnswers: number,
  total: number,
): QuizHistoryEntry {
  const safeTotal = Math.max(1, total);
  const safeCorrect = Math.max(0, Math.min(safeTotal, correctAnswers));

  const entry: QuizHistoryEntry = {
    id: `${Date.now()}-${Math.random().toString(36).slice(2, 9)}`,
    completedAt: new Date().toISOString(),
    score: safeCorrect,
    total: safeTotal,
    percentage: Math.round((safeCorrect / safeTotal) * 100),
    correctAnswers: safeCorrect,
  };

  const history = readQuizHistory();
  const updated = [entry, ...history].slice(0, MAX_HISTORY_ITEMS);

  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(updated));
  } catch {
    // Quiz results still display if browser storage is unavailable.
  }

  return entry;
}

export function clearQuizHistory(): void {
  try {
    localStorage.removeItem(STORAGE_KEY);
  } catch {
    // Ignore unavailable browser storage.
  }
}
