#!/usr/bin/env node
/**
 * User management CLI
 *
 * Usage:
 *   node backend/scripts/manage-users.js add <email> <password> [admin|user]
 *   node backend/scripts/manage-users.js list
 *   node backend/scripts/manage-users.js remove <email>
 *   node backend/scripts/manage-users.js set-password <email> <newpassword>
 */

import { addUser, removeUser, setPassword, listUsers } from '../src/userStore.js'

const [, , cmd, ...args] = process.argv

async function main() {
  switch (cmd) {
    case 'add': {
      const [email, password, role = 'user'] = args
      if (!email || !password) {
        console.error('Usage: manage-users add <email> <password> [admin|user]')
        process.exit(1)
      }
      if (role !== 'admin' && role !== 'user') {
        console.error('Role must be "admin" or "user"')
        process.exit(1)
      }
      await addUser(email, password, role)
      console.log(`✓ Added ${role}: ${email}`)
      break
    }

    case 'list': {
      const users = listUsers()
      if (users.length === 0) {
        console.log('No users. Add one with: manage-users add <email> <password> [admin|user]')
      } else {
        console.log(`${'EMAIL'.padEnd(42)} ROLE`)
        console.log('─'.repeat(52))
        for (const u of users) {
          console.log(`${u.email.padEnd(42)} ${u.role}`)
        }
      }
      break
    }

    case 'remove': {
      const [email] = args
      if (!email) {
        console.error('Usage: manage-users remove <email>')
        process.exit(1)
      }
      removeUser(email)
      console.log(`✓ Removed: ${email}`)
      break
    }

    case 'set-password': {
      const [email, password] = args
      if (!email || !password) {
        console.error('Usage: manage-users set-password <email> <newpassword>')
        process.exit(1)
      }
      await setPassword(email, password)
      console.log(`✓ Password updated for: ${email}`)
      break
    }

    default: {
      console.log(`
API Scanner — User Management

Commands:
  add <email> <password> [admin|user]   Add a new user (default role: user)
  list                                  List all users
  remove <email>                        Delete a user
  set-password <email> <newpassword>    Change a user's password

Examples:
  node backend/scripts/manage-users.js add alice@example.com secret123 admin
  node backend/scripts/manage-users.js add bob@example.com hunter2
  node backend/scripts/manage-users.js list
  node backend/scripts/manage-users.js set-password alice@example.com newpass
  node backend/scripts/manage-users.js remove bob@example.com
      `.trim())
    }
  }
}

main().catch((err) => {
  console.error('Error:', err.message)
  process.exit(1)
})
