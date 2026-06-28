// Entropy-based password strength — no rule lists, no false positives
export interface StrengthResult {
  score: 0 | 1 | 2 | 3 | 4   // 0=very weak … 4=very strong
  label: string
  color: string
  entropy: number
  feedback: string
}

export function measureStrength(pw: string): StrengthResult {
  if (!pw) return { score: 0, label: '', color: 'transparent', entropy: 0, feedback: '' }

  // Character set size
  let pool = 0
  if (/[a-z]/.test(pw)) pool += 26
  if (/[A-Z]/.test(pw)) pool += 26
  if (/[0-9]/.test(pw)) pool += 10
  if (/[^a-zA-Z0-9]/.test(pw)) pool += 32

  const entropy = pw.length * Math.log2(pool || 1)

  // Penalty for repetition
  const uniqueRatio = new Set(pw).size / pw.length
  const adjusted = entropy * (0.5 + 0.5 * uniqueRatio)

  let score: 0 | 1 | 2 | 3 | 4
  let label: string
  let color: string
  let feedback: string

  if (adjusted < 28) {
    score = 0; label = 'Very weak'; color = '#ef4444'
    feedback = 'Too short or too simple — easily cracked.'
  } else if (adjusted < 40) {
    score = 1; label = 'Weak'; color = '#f97316'
    feedback = 'Add more characters or mix uppercase, numbers, and symbols.'
  } else if (adjusted < 55) {
    score = 2; label = 'Fair'; color = '#f59e0b'
    feedback = 'Decent, but a longer password would be stronger.'
  } else if (adjusted < 70) {
    score = 3; label = 'Strong'; color = '#84cc16'
    feedback = 'Good password. A symbol or two would make it excellent.'
  } else {
    score = 4; label = 'Very strong'; color = '#22c55e'
    feedback = 'Excellent password strength.'
  }

  return { score, label, color, entropy: Math.round(adjusted), feedback }
}
