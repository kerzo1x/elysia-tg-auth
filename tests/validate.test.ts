import { test, expect } from 'bun:test'
import {
  buildDataCheckString,
  computeInitDataHash,
  validateInitData,
} from '../src/validate'

const botToken = '5768337691:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw'
const user = JSON.stringify({
  id: 279753388,
  first_name: 'Andrew',
  last_name: 'Rozhkov',
  username: 'andrewrozhkov',
  language_code: 'ru',
  is_premium: true,
})
const authDate = '1679130118'
const expectedHash =
  '57684865b54483fffde9c38109c3371949c08fc0cd69fe961094198d823b51be'

test('buildDataCheckString sorts keys and excludes hash', () => {
  const params = new URLSearchParams(
    `user=${encodeURIComponent(user)}&auth_date=${authDate}&hash=${expectedHash}`
  )
  expect(buildDataCheckString(params)).toBe(
    `auth_date=${authDate}\nuser=${user}`
  )
})

test('buildDataCheckString excludes signature', () => {
  const params = new URLSearchParams(
    `auth_date=${authDate}&signature=fake&hash=${expectedHash}`
  )
  expect(buildDataCheckString(params)).toBe(`auth_date=${authDate}`)
})

test('computeInitDataHash matches official algorithm', async () => {
  const dataCheckString = `auth_date=${authDate}\nuser=${user}`
  const hash = await computeInitDataHash(dataCheckString, botToken)
  expect(hash).toBe(expectedHash)
})

test('validateInitData accepts valid initData', async () => {
  const initData = `auth_date=${authDate}&user=${encodeURIComponent(user)}&hash=${expectedHash}`
  const result = await validateInitData(initData, botToken, {
    maxAgeSeconds: 0,
  })
  expect(result.ok).toBe(true)
  if (result.ok) {
    expect(result.data.auth_date).toBe(1679130118)
    expect(result.data.user?.id).toBe(279753388)
    expect(result.data.user?.first_name).toBe('Andrew')
  }
})

test('validateInitData rejects tampered user', async () => {
  const tamperedUser = JSON.stringify({ id: 1, first_name: 'Hacker' })
  const initData = `auth_date=${authDate}&user=${encodeURIComponent(tamperedUser)}&hash=${expectedHash}`
  const result = await validateInitData(initData, botToken, {
    maxAgeSeconds: 0,
  })
  expect(result).toEqual({ ok: false, error: 'INVALID_HASH' })
})

test('validateInitData rejects missing hash', async () => {
  const result = await validateInitData(`auth_date=${authDate}`, botToken)
  expect(result).toEqual({ ok: false, error: 'MISSING_HASH' })
})

test('validateInitData strips leading ?', async () => {
  const initData = `?auth_date=${authDate}&user=${encodeURIComponent(user)}&hash=${expectedHash}`
  const result = await validateInitData(initData, botToken, {
    maxAgeSeconds: 0,
  })
  expect(result.ok).toBe(true)
})
