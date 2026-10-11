import makeWASocket, { useMultiFileAuthState, DisconnectReason } from '@whiskeysockets/baileys'
import express from 'express'
import pino from 'pino'
import readline from 'readline'
import path from 'path'
import { fileURLToPath } from 'url'
import settings from './settings.js'
import { PORT, SESSION_PATH, BROWSER } from './config.js'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

const app = express()
app.use(express.json())
app.use(express.static(__dirname))
app.get('/', (req,res) => res.sendFile(path.join(__dirname, 'index.html')))

let globalSock = null
let lastCode = null

app.get('/code', (req,res) => res.json({ code: lastCode, connected:!!globalSock?.user }))
app.post('/pair', async (req,res) => {
  const { number } = req.body
  if (!globalSock) return res.json({ error: "Bot not started" })
  try {
    const code = await globalSock.requestPairingCode(number.trim())
    lastCode = code
    res.json({ code })
  } catch(e) { res.json({ error: e.message }) }
})

app.listen(PORT, () => console.log(`Dashboard: http://localhost:${PORT} | Owner: ${settings.ownerName}`))

const rl = readline.createInterface({ input: process.stdin, output: process.stdout })
const ask = (q) => new Promise(r => rl.question(q, r))

async function startBot() {
  const { state, saveCreds } = await useMultiFileAuthState(SESSION_PATH)
  const sock = makeWASocket({
    auth: state,
    logger: pino({ level: 'silent' }),
    printQRInTerminal: false,
    browser: BROWSER
  })
  globalSock = sock

  if (!sock.authState.creds.registered) {
    console.log('=== PAIRING CODE MODE - NO QR | Simon tech inc ===')
    if (process.env.PHONE_NUMBER) {
      await new Promise(r => setTimeout(r, 3000))
      const code = await sock.requestPairingCode(process.env.PHONE_NUMBER.trim())
      lastCode = code
      console.log(`PAIRING CODE FOR ${process.env.PHONE_NUMBER}: ${code}`)
    } else {
      const num = await ask('Enter number (2349166265317): ')
      const finalNum = num.trim() || "2349166265317"
      const code = await sock.requestPairingCode(finalNum)
      lastCode = code
      console.log(`\n>>> CODE: ${code} <<<\nOpen dashboard / or WhatsApp > Linked Devices > Link with phone number`)
    }
  }

  sock.ev.on('creds.update', saveCreds)
  sock.ev.on('connection.update', ({ connection, lastDisconnect }) => {
    if (connection === 'open') { console.log(`✅ CONNECTED - ${settings.botName} Online`); rl.close() }
    if (connection === 'close' && lastDisconnect?.error?.output?.statusCode!== DisconnectReason.loggedOut) startBot()
  })

  const { default: handler } = await import('./handler.js')
  sock.ev.on('messages.upsert', async ({ messages }) => handler(sock, messages))
}
startBot()
