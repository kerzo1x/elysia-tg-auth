import type { TelegramInitData, TelegramUser, ValidationResult } from './types'

const WEB_APP_DATA_KEY = 'WebAppData'
const DEFAULT_MAX_AGE_SECONDS = 86_400

export type ValidateInitDataOptions = {
  /** Reject initData older than this many seconds (default: 86400). Set 0 to disable. */
  maxAgeSeconds?: number
}

function normalizeInitData(initData: string): string {
  const trimmed = initData.trim()
  return trimmed.startsWith('?') ? trimmed.slice(1) : trimmed
}

export function buildDataCheckString(params: URLSearchParams): string {
  const pairs: [string, string][] = []
  for (const [key, value] of Array.from(params.entries())) {
    if (key === 'hash' || key === 'signature') continue
    pairs.push([key, value])
  }
  return pairs
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([key, value]) => `${key}=${value}`)
    .join('\n')
}

export async function computeInitDataHash(
  dataCheckString: string,
  botToken: string
): Promise<string> {
  const encoder = new TextEncoder()

  const webAppDataKey = await crypto.subtle.importKey(
    'raw',
    encoder.encode(WEB_APP_DATA_KEY),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  )

  const secretKey = await crypto.subtle.sign(
    'HMAC',
    webAppDataKey,
    encoder.encode(botToken)
  )

  const dataHmacKey = await crypto.subtle.importKey(
    'raw',
    secretKey,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  )

  const signature = await crypto.subtle.sign(
    'HMAC',
    dataHmacKey,
    encoder.encode(dataCheckString)
  )

  return Array.from(new Uint8Array(signature))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
}

function timingSafeEqualHex(a: string, b: string): boolean {
  if (a.length !== b.length) return false
  const left = Buffer.from(a, 'utf8')
  const right = Buffer.from(b, 'utf8')
  if (left.length !== right.length) return false
  return crypto.timingSafeEqual(left, right)
}

function parseUser(raw: string | null): TelegramUser | undefined {
  if (!raw) return undefined
  try {
    const parsed: unknown = JSON.parse(raw)
    if (
      typeof parsed === 'object' &&
      parsed !== null &&
      typeof (parsed as TelegramUser).id === 'number' &&
      typeof (parsed as TelegramUser).first_name === 'string'
    ) {
      return parsed as TelegramUser
    }
  } catch {
    return undefined
  }
  return undefined
}

export async function validateInitData(
  initData: string,
  botToken: string,
  options: ValidateInitDataOptions = {}
): Promise<ValidationResult> {
  const raw = normalizeInitData(initData)
  const params = new URLSearchParams(raw)
  const hash = params.get('hash')
  const authDateRaw = params.get('auth_date')

  if (!hash) return { ok: false, error: 'MISSING_HASH' }
  if (!authDateRaw) return { ok: false, error: 'MISSING_AUTH_DATE' }

  const authDate = Number(authDateRaw)
  if (!Number.isFinite(authDate)) {
    return { ok: false, error: 'INVALID_AUTH_DATE' }
  }

  const maxAgeSeconds = options.maxAgeSeconds ?? DEFAULT_MAX_AGE_SECONDS
  if (maxAgeSeconds > 0) {
    const now = Math.floor(Date.now() / 1000)
    if (authDate > now + 60) {
      return { ok: false, error: 'AUTH_DATE_IN_FUTURE' }
    }
    if (now - authDate > maxAgeSeconds) {
      return { ok: false, error: 'AUTH_DATE_EXPIRED' }
    }
  }

  const dataCheckString = buildDataCheckString(params)
  const calculatedHash = await computeInitDataHash(dataCheckString, botToken)

  if (!timingSafeEqualHex(calculatedHash, hash)) {
    return { ok: false, error: 'INVALID_HASH' }
  }

  const user = parseUser(params.get('user'))

  return {
    ok: true,
    data: {
      user,
      auth_date: authDate,
      hash,
      raw,
    },
  }
}
