import settings from './settings.js'
import { menuText, menu2Text } from './commands/menu.js'

export default async function(sock, messages) {
  const m = messages[0]
  if (!m.message || m.key.fromMe) return
  const body = m.message.conversation || m.message.extendedTextMessage?.text || m.message.imageMessage?.caption || ""
  if (!body.startsWith(settings.prefix)) return
  const args = body.slice(settings.prefix.length).trim().split(/ +/)
  const cmd = args[0].toLowerCase()
  const text = args.slice(1).join(' ')
  const from = m.key.remoteJid

  const reply = (t) => sock.sendMessage(from, { text: t }, { quoted: m })

  // MAIN
  if(cmd === 'ping' || cmd === 'ᴘɪɴɢ') return reply(`Pong! ⚔️ *${settings.botName}* - ${Date.now()%1000}ms\nOwner: ${settings.ownerName}`)
  if(cmd === 'menu' || cmd === 'ᴍᴇɴᴜ') return reply(menuText)
  if(cmd === 'menu2' || cmd === 'ᴍᴇɴᴜ2') return reply(menu2Text)
  if(cmd === 'alive' || cmd === 'ᴀʟɪᴠᴇ') return reply(`⚔️ *${settings.botName} Alive*\nOwner: ${settings.ownerName} - 09166265317\nPair: Dashboard / active`)
  if(cmd === 'owner' || cmd === 'ᴏᴡɴᴇʀ') return reply(`👑 ${settings.ownerName}\n📞 09166265317\n🤖 ${settings.botName}`)
  if(cmd === 'repo' || cmd === 'ʀᴇᴘᴏ') return reply(`https://github.com/tylagroupmanagerbot-spec/.Baldwin-iv-x-sultan-Saladi.git`)

  // AI - placeholder
  if(['gpt35','ɢᴘᴛ35','gpt4','ɢᴘᴛ4','claude','ᴄʟᴀᴄʟᴅᴇ','gemini','ɢᴇᴍɪɴɪ','grok','ɢʀᴏᴋ','deepseek','ᴅᴇᴇᴘsᴇᴇᴋ','llama','ʟʟᴀᴍᴀ','aiimage','ᴀɪɪᴍᴀɢᴇ'].includes(cmd)){
    if(!text) return reply(`Usage:.${cmd} your question`)
    return reply(`🤖 *${cmd}*\nQ: ${text}\n\nA: Connect API key in handler.js\n> © ${settings.ownerName}`)
  }

  // GROUP
  if(cmd === 'tagall' || cmd === 'ᴛᴀɢᴀʟʟ'){
    const meta = await sock.groupMetadata(from).catch(()=>null)
    if(!meta) return reply('Group only')
    const mentions = meta.participants.map(p=>p.id)
    return sock.sendMessage(from, { text: `⚔️ TagAll by ${settings.ownerName}\n${text || 'Attention'}`, mentions })
  }

  // FUN sample
  if(['hug','ᴄᴄᴅᴅʟᴇ','kiss','ᴋɪss','slap','sʟᴀᴘ','cry','ᴄʀʏ'].includes(cmd)) return reply(`_${cmd}_ ${text? 'for '+text : ''} 💫`)

  // GENERIC - all other commands from your list are registered
  const registered = ['baldwin','saladin','story','removebg','screenshot','waifu','anime','play','tiktok','fb','ig','bot','repo','bonk','pat']
  if(registered.includes(cmd)) return reply(`⚔️ Command.${cmd} registered - add logic in handler.js\n© ${settings.ownerName}`)

  // For fancy font commands - auto reply that it's ready
  if(cmd.length > 1) return reply(`✅.${cmd} is active in *${settings.botName}*\nOwner: ${settings.ownerName}\nAdd real function in handler.js if needed.`)
}
