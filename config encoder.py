#!/usr/bin/env python3
"""
Protected SSC Bot
কোনো .ssc ফাইল পাঠালেই → protected.ssc ফেরত দেয়
সাথে সাথে inline buttons দিয়ে encrypt/decrypt
"""
import os
import hmac
import hashlib
import gzip
import base64
import secrets
import struct
import tempfile

from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.fernet import Fernet
from Crypto.Cipher import ChaCha20, ChaCha20_Poly1305
import telebot
from telebot import types

# ================= CONFIG =================
BOT_TOKEN = "9108484299:AAG5WRbl2v6D7y6oRATqfg9KS1LgzxK-kIw"
YOUR_ID = 8221245087        # 0 = সবাই; নিজের ID দিলে শুধু আপনি
# =========================================

bot = telebot.TeleBot(BOT_TOKEN)
user_state = {}   # chat_id -> {"mode": ..., "password": ..., "ready": bool}

MAGIC = b"PSC"    # Protected SSC
VERSION = 1
PAD_BLOCK = 4096
JUNK_MIN, JUNK_MAX = 8, 48

ARGON_MEM = 128 * 1024
ARGON_TIME = 4
ARGON_PAR = 2

# ================= CRYPTO =================
def derive_keys(password: str, salt: bytes):
    master = hash_secret_raw(
        secret=password.encode(), salt=salt,
        time_cost=ARGON_TIME, memory_cost=ARGON_MEM,
        parallelism=ARGON_PAR, hash_len=96, type=Type.ID,
    )
    return {
        "xor":    hashlib.scrypt(master[:32],  salt=salt+b"1", n=16384, r=8, p=1, dklen=32),
        "aes":    hashlib.scrypt(master[32:64], salt=salt+b"2", n=16384, r=8, p=1, dklen=32),
        "fer":    hashlib.scrypt(master[64:96], salt=salt+b"3", n=16384, r=8, p=1, dklen=32),
        "hmac":   hashlib.sha512(master + b"h").digest(),
        "chacha": hashlib.sha256(master + b"c").digest(),
    }

def xor_stream(data: bytes, key: bytes) -> bytes:
    c = ChaCha20.new(key=key[:32], nonce=b"\x00"*8)
    ks = c.encrypt(b"\x00" * len(data))
    return bytes(a ^ b for a, b in zip(data, ks))

def pad(data: bytes) -> bytes:
    n = PAD_BLOCK - (len(data) % PAD_BLOCK)
    if n < 32: n += PAD_BLOCK
    return struct.pack(">I", len(data)) + data + secrets.token_bytes(n - 4)

def unpad(data: bytes) -> bytes:
    ln = struct.unpack(">I", data[:4])[0]
    return data[4:4 + ln]

def encrypt_data(text: str, password: str) -> str:
    salt = secrets.token_bytes(32)
    k = derive_keys(password, salt)
    d = text.encode()

    d = xor_stream(d, k["xor"])                                # L1
    n = secrets.token_bytes(12)
    d = n + AESGCM(k["aes"]).encrypt(n, d, None)               # L2
    n = secrets.token_bytes(24)
    c = ChaCha20_Poly1305.new(key=k["chacha"], nonce=n)
    ct, tag = c.encrypt_and_digest(d)
    d = n + tag + ct                                            # L3
    d = Fernet(base64.urlsafe_b64encode(k["fer"])).encrypt(d)  # L4
    d = gzip.compress(d, compresslevel=9)                       # L5
    d = pad(d)                                                  # L6
    h = hmac.new(k["hmac"], d, hashlib.sha512).digest()         # L7

    blob = MAGIC + bytes([VERSION]) + salt + h + d
    junk_len = secrets.randbelow(JUNK_MAX - JUNK_MIN + 1) + JUNK_MIN
    blob = secrets.token_bytes(junk_len) + bytes([junk_len]) + blob
    return blob.hex()

def decrypt_data(hex_str: str, password: str) -> str:
    blob = bytes.fromhex(hex_str.strip())
    jl = blob[0]
    blob = blob[1 + jl:]

    if blob[:3] != MAGIC:
        raise ValueError("এই bot-এর ফাইল না")
    if blob[3] != VERSION:
        raise ValueError("ভার্সন mismatch")

    salt = blob[4:36]
    h = blob[36:100]
    d = blob[100:]

    k = derive_keys(password, salt)
    calc = hmac.new(k["hmac"], d, hashlib.sha512).digest()
    if not hmac.compare_digest(calc, h):
        raise ValueError("পাসওয়ার্ড ভুল বা ফাইল corrupt")

    d = unpad(d)                                                # L6
    d = gzip.decompress(d)                                      # L5
    d = Fernet(base64.urlsafe_b64encode(k["fer"])).decrypt(d)  # L4
    n, tag, ct = d[:24], d[24:40], d[40:]
    c = ChaCha20_Poly1305.new(key=k["chacha"], nonce=n)
    d = c.decrypt_and_verify(ct, tag)                           # L3
    n, ct = d[:12], d[12:]
    d = AESGCM(k["aes"]).decrypt(n, ct, None)                   # L2
    d = xor_stream(d, k["xor"])                                 # L1
    return d.decode()

# ================= AUTH =================
def ok(msg) -> bool:
    return YOUR_ID == 0 or msg.from_user.id == YOUR_ID

# ================= KEYBOARDS =================
def main_kb():
    kb = types.InlineKeyboardMarkup(row_width=2)
    kb.add(
        types.InlineKeyboardButton("🔒 Protect .ssc", callback_data="protect"),
        types.InlineKeyboardButton("🔓 Unlock .enc", callback_data="unlock"),
    )
    kb.add(types.InlineKeyboardButton("❓ Help", callback_data="help"))
    return kb

def cancel_kb():
    kb = types.InlineKeyboardMarkup()
    kb.add(types.InlineKeyboardButton("❌ Cancel", callback_data="cancel"))
    return kb

# ================= HANDLERS =================
@bot.message_handler(commands=["start"])
def cmd_start(msg):
    if not ok(msg):
        bot.reply_to(msg, "🔒 Private bot"); return
    user_state.pop(msg.chat.id, None)
    bot.send_message(
        msg.chat.id,
        "👋 **Protected SSC Bot**\n\n"
        "📁 `.ssc` ফাইল পাঠান → সাথে সাথে **protected.ssc** ফেরত পাবেন।\n\n"
        "নিচের বাটন চাপুন অথবা সরাসরি ফাইল পাঠান:",
        reply_markup=main_kb(), parse_mode="Markdown"
    )

@bot.callback_query_handler(func=lambda c: True)
def on_cb(call):
    cid = call.message.chat.id
    if YOUR_ID and call.from_user.id != YOUR_ID:
        bot.answer_callback_query(call.id, "❌ Access denied"); return

    if call.data == "help":
        bot.answer_callback_query(call.id)
        bot.send_message(
            cid,
            "**📖 কীভাবে ব্যবহার করবেন:**\n\n"
            "**🔒 Protect:**\n"
            "1. 🔒 Protect চাপুন\n"
            "2. পাসওয়ার্ড দিন (মনে রাখুন!)\n"
            "3. `.ssc` ফাইল পাঠান\n"
            "4. `protected.ssc` ফেরত পাবেন ✅\n\n"
            "**🔓 Unlock:**\n"
            "1. 🔓 Unlock চাপুন\n"
            "2. একই পাসওয়ার্ড দিন\n"
            "3. protected ফাইল পাঠান\n"
            "4. আসল `.ssc` ফেরত পাবেন ✅\n\n"
            "⚠️ পাসওয়ার্ড হারালে ফাইল চিরতরে লক!",
            parse_mode="Markdown", reply_markup=main_kb())
        return

    if call.data == "cancel":
        user_state.pop(cid, None)
        bot.answer_callback_query(call.id, "Cancelled")
        bot.send_message(cid, "❌ বাতিল।", reply_markup=main_kb())
        return

    if call.data in ("protect", "unlock"):
        mode = "enc" if call.data == "protect" else "dec"
        user_state[cid] = {"mode": mode, "step": "pw"}
        bot.answer_callback_query(call.id)
        txt = ("🔒 **Protect মোড**\n\n🔑 পাসওয়ার্ড পাঠান:"
               if mode == "enc"
               else "🔓 **Unlock মোড**\n\n🔑 পাসওয়ার্ড পাঠান:")
        bot.send_message(cid, txt, parse_mode="Markdown", reply_markup=cancel_kb())
        return

@bot.message_handler(content_types=["text"])
def on_text(msg):
    if not ok(msg): return
    cid = msg.chat.id
    st = user_state.get(cid)

    if not st or st.get("step") != "pw":
        bot.send_message(cid, "আগে 🔒 বা 🔓 চাপুন।", reply_markup=main_kb())
        return

    pw = msg.text.strip()
    if len(pw) < 6:
        bot.reply_to(msg, "⚠️ কমপক্ষে ৬ অক্ষর দিন।"); return

    st["password"] = pw
    st["step"] = "file"
    try: bot.delete_message(cid, msg.message_id)
    except: pass

    if st["mode"] == "enc":
        bot.send_message(cid, "✅ পাসওয়ার্ড গ্রহণ।\n\n📁 এখন `.ssc` ফাইল পাঠান।",
                         reply_markup=main_kb())
    else:
        bot.send_message(cid, "✅ পাসওয়ার্ড গ্রহণ।\n\n📁 এখন protected ফাইল পাঠান।",
                         reply_markup=main_kb())

@bot.message_handler(content_types=["document"])
def on_doc(msg):
    if not ok(msg): return
    cid = msg.chat.id
    st = user_state.get(cid)

    # Auto-mode: পাসওয়ার্ড না দিলেও কাজ করবে — Telegram ID থেকে auto password
    if not st or st.get("step") != "file":
        # Auto protect mode
        auto_pw = f"tgid_{msg.from_user.id}_autopw"
        st = {"mode": "enc", "password": auto_pw, "step": "file"}
        user_state[cid] = st

    fname = msg.document.file_name or "file"
    pw = st["password"]
    mode = st["mode"]

    if msg.document.file_size > 20 * 1024 * 1024:
        bot.reply_to(msg, "❌ ফাইল ২০MB এর কম হতে হবে।"); return

    status = bot.reply_to(msg, "⏳ প্রসেস হচ্ছে...")

    try:
        fi = bot.get_file(msg.document.file_id)
        raw = bot.download_file(fi.file_path)
        text = raw.decode("utf-8", errors="ignore")

        if mode == "enc":
            result = encrypt_data(text, pw)
            out_name = "protected.ssc"           # ← সবসময় এই নাম
            caption = "✅ **Protected!**\n\n`protected.ssc`\n⚠️ পাসওয়ার্ড সংরক্ষণ করুন!"
        else:
            result = decrypt_data(text, pw)
            base = fname[:-4] if fname.endswith(".enc") else fname
            if not base.endswith(".ssc"):
                base += ".ssc"
            out_name = base
            caption = f"✅ **Unlocked!**\n\n`{out_name}`"
    except Exception as e:
        bot.edit_message_text(f"❌ ব্যর্থ: `{e}`", cid, status.message_id,
                              parse_mode="Markdown")
        user_state.pop(cid, None)
        return

    tmp = os.path.join(tempfile.gettempdir(), f"{cid}_{out_name}")
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(result)
        with open(tmp, "rb") as f:
            bot.send_document(cid, f, caption=caption,
                              parse_mode="Markdown",
                              visible_file_name=out_name)
        bot.delete_message(cid, status.message_id)
    finally:
        if os.path.exists(tmp): os.remove(tmp)

    user_state.pop(cid, None)
    bot.send_message(cid, "🏠 মূল মেনু:", reply_markup=main_kb())

# ================= RUN =================
if __name__ == "__main__":
    print("🤖 Protected SSC Bot চালু...")
    bot.infinity_polling(timeout=60, long_polling_timeout=60)