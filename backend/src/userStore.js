import { scrypt, randomBytes, timingSafeEqual } from 'node:crypto'
import { promisify } from 'node:util'
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const scryptAsync = promisify(scrypt)
const __dirname = dirname(fileURLToPath(import.meta.url))
const DATA_DIR = join(__dirname, '..', 'data')
const USERS_FILE = join(DATA_DIR, 'users.json')

// scrypt params
const N = 16384
const r = 8
const p = 1
const KEY_LEN = 32

function ensureDataDir() {
  if (!existsSync(DATA_DIR)) mkdirSync(DATA_DIR, { recursive: true })
}

export function loadUsers() {
  ensureDataDir()
  if (!existsSync(USERS_FILE)) return []
  try {
    return JSON.parse(readFileSync(USERS_FILE, 'utf8'))
  } catch {
    return []
  }
}

export function saveUsers(users) {
  ensureDataDir()
  writeFileSync(USERS_FILE, JSON.stringify(users, null, 2), 'utf8')
}

// Returns "saltHex.hashHex"
export async function hashPassword(password) {
  const salt = randomBytes(16)
  const hash = await scryptAsync(password, salt, KEY_LEN, { N, r, p })
  return `${salt.toString('hex')}.${Buffer.from(hash).toString('hex')}`
}

export async function verifyPassword(password, stored) {
  const [saltHex, hashHex] = (stored || '').split('.')
  if (!saltHex || !hashHex) return false
  const salt = Buffer.from(saltHex, 'hex')
  const storedHash = Buffer.from(hashHex, 'hex')
  const derived = Buffer.from(await scryptAsync(password, salt, KEY_LEN, { N, r, p }))
  if (derived.length !== storedHash.length) return false
  return timingSafeEqual(derived, storedHash)
}

export function findUser(email) {
  const users = loadUsers()
  return users.find((u) => u.email.toLowerCase() === email.toLowerCase()) ?? null
}

export async function addUser(email, password, role = 'user') {
  const users = loadUsers()
  if (users.some((u) => u.email.toLowerCase() === email.toLowerCase())) {
    throw new Error(`User already exists: ${email}`)
  }
  const passwordHash = await hashPassword(password)
  users.push({ email: email.toLowerCase(), passwordHash, role })
  saveUsers(users)
}

export function removeUser(email) {
  const users = loadUsers()
  const idx = users.findIndex((u) => u.email.toLowerCase() === email.toLowerCase())
  if (idx === -1) throw new Error(`User not found: ${email}`)
  users.splice(idx, 1)
  saveUsers(users)
}

export async function setPassword(email, password) {
  const users = loadUsers()
  const user = users.find((u) => u.email.toLowerCase() === email.toLowerCase())
  if (!user) throw new Error(`User not found: ${email}`)
  user.passwordHash = await hashPassword(password)
  saveUsers(users)
}

export function listUsers() {
  return loadUsers().map(({ email, role }) => ({ email, role }))
}
