export interface TelegramUser {
    id: number
    first_name: string
    last_name?: string
    username?: string
    language_code?: string
    is_premium?: boolean
    photo_url?: string
    allows_write_to_pm?: boolean
  }

  export interface TelegramInitData {
    user?: TelegramUser
    auth_date: number
    hash: string
    raw: string
  }
  
  export type ValidationResult =
    | { ok: true; data: TelegramInitData }
    | { ok: false; error: string }