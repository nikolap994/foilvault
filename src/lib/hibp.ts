// HaveIBeenPwned k-anonymity breach check
// Sends only the first 5 chars of the SHA-1 hash — password never leaves the device
import { logAuditEvent } from './audit'

export interface BreachResult {
  breached: boolean
  count: number
}

export async function checkPasswordBreach(password: string): Promise<BreachResult> {
  const msgBuf = new TextEncoder().encode(password)
  const hashBuf = await crypto.subtle.digest('SHA-1', msgBuf)
  const hex = Array.from(new Uint8Array(hashBuf), b => b.toString(16).padStart(2, '0')).join('').toUpperCase()
  const prefix = hex.slice(0, 5)
  const suffix = hex.slice(5)

  const res = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
    headers: { 'Add-Padding': 'true' },
  })
  if (!res.ok) throw new Error(`HIBP API error: ${res.status}`)

  const text = await res.text()
  await logAuditEvent('hibp_check')
  for (const line of text.split('\r\n')) {
    const [s, countStr] = line.split(':')
    if (s === suffix) {
      const count = parseInt(countStr, 10)
      return { breached: true, count }
    }
  }
  return { breached: false, count: 0 }
}
