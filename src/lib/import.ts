import type { Credential } from './vault'

type ImportResult = Omit<Credential, 'id' | 'createdAt' | 'updatedAt'>

// ─── Generic CSV parser ───────────────────────────────────────────────────
function parseCsv(text: string): Record<string, string>[] {
  const lines = text.replace(/\r\n/g, '\n').split('\n').filter(l => l.trim())
  if (lines.length < 2) return []
  const headers = splitCsvLine(lines[0]).map(h => h.toLowerCase().trim())
  return lines.slice(1).map(line => {
    const vals = splitCsvLine(line)
    const row: Record<string, string> = {}
    headers.forEach((h, i) => { row[h] = (vals[i] ?? '').trim() })
    return row
  })
}

function splitCsvLine(line: string): string[] {
  const out: string[] = []
  let cur = ''
  let inQ = false
  for (let i = 0; i < line.length; i++) {
    const ch = line[i]
    if (ch === '"') {
      if (inQ && line[i + 1] === '"') { cur += '"'; i++ }
      else { inQ = !inQ }
    } else if (ch === ',' && !inQ) {
      out.push(cur); cur = ''
    } else {
      cur += ch
    }
  }
  out.push(cur)
  return out
}

// ─── Bitwarden CSV ─────────────────────────────────────────────────────────
// columns: folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp
function fromBitwarden(text: string): ImportResult[] {
  const rows = parseCsv(text)
  return rows
    .filter(r => r['type'] === 'login' || !r['type'])
    .map(r => ({
      type: 'login' as const,
      site: r['name'] || r['login_uri'] || 'Unknown',
      username: r['login_username'] || '',
      password: r['login_password'] || '',
      notes: r['notes'] || '',
    }))
    .filter(r => r.password)
}

// ─── 1Password CSV ─────────────────────────────────────────────────────────
// columns: Title,Username,Password,URL,Notes,OTPAuth
function from1Password(text: string): ImportResult[] {
  const rows = parseCsv(text)
  return rows
    .map(r => ({
      type: 'login' as const,
      site: r['title'] || r['url'] || 'Unknown',
      username: r['username'] || '',
      password: r['password'] || '',
      notes: r['notes'] || '',
    }))
    .filter(r => r.password)
}

// ─── LastPass CSV ──────────────────────────────────────────────────────────
// columns: url,username,password,totp,extra,name,grouping,fav
function fromLastPass(text: string): ImportResult[] {
  const rows = parseCsv(text)
  return rows
    .map(r => ({
      type: 'login' as const,
      site: r['name'] || r['url'] || 'Unknown',
      username: r['username'] || '',
      password: r['password'] || '',
      notes: r['extra'] || '',
    }))
    .filter(r => r.password)
}

// ─── Generic fallback ──────────────────────────────────────────────────────
// Tries to map common column name variants
function fromGeneric(text: string): ImportResult[] {
  const rows = parseCsv(text)
  return rows
    .map(r => {
      const site = r['name'] || r['title'] || r['site'] || r['url'] || r['website'] || 'Unknown'
      const username = r['username'] || r['email'] || r['user'] || r['login'] || ''
      const password = r['password'] || r['pass'] || r['pwd'] || ''
      const notes = r['notes'] || r['note'] || r['comment'] || r['extra'] || ''
      return { type: 'login' as const, site, username, password, notes }
    })
    .filter(r => r.password)
}

export type ImportFormat = 'auto' | 'bitwarden' | '1password' | 'lastpass' | 'generic'

export function detectFormat(text: string): ImportFormat {
  const firstLine = text.split('\n')[0].toLowerCase()
  if (firstLine.includes('login_uri') || firstLine.includes('login_username')) return 'bitwarden'
  if (firstLine.includes('otpauth') || firstLine.includes('title,username,password,url')) return '1password'
  if (firstLine.includes('grouping') || firstLine.includes('fav') && firstLine.includes('totp')) return 'lastpass'
  return 'generic'
}

export function importCredentials(text: string, format: ImportFormat = 'auto'): ImportResult[] {
  const fmt = format === 'auto' ? detectFormat(text) : format
  switch (fmt) {
    case 'bitwarden': return fromBitwarden(text)
    case '1password': return from1Password(text)
    case 'lastpass': return fromLastPass(text)
    default: return fromGeneric(text)
  }
}
