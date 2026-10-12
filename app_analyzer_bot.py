#!/usr/bin/env python3
"""
App Static Analyzer Bot — GitHub Actions Edition
Analyzes APK/ZIP for secrets, API endpoints, security issues
"""

import os
import re
import json
import asyncio
import zipfile
import shutil
import signal
import sys
from datetime import datetime
from urllib.parse import urlparse
from collections import defaultdict

import aiohttp

# ==================== CONFIG ====================
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "8636614665:AAEiOHIh-4cYkpq1uIl3DczFx6XQqWC9Q58")
TELEGRAM_API = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}"
WORK_DIR = "app_analysis"
os.makedirs(WORK_DIR, exist_ok=True)

last_update_id = 0
running = True

# ==================== PATTERNS ====================
PATTERNS = {
    "http_url": re.compile(r'https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]{5,300}'),
    "api_path": re.compile(r'["\'](/api/[a-zA-Z0-9/_\-.{}]{2,100})["\']'),
    "ws_url": re.compile(r'wss?://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]{5,300}'),
    "graphql": re.compile(r'["\'](/graphql|/gql)["\']'),

    "jwt": re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'),
    "aws_access": re.compile(r'AKIA[0-9A-Z]{16}'),
    "aws_secret": re.compile(r'aws_secret[_a-z]*["\']?\s*[:=]\s*["\']([A-Za-z0-9/+=]{40})["\']'),
    "google_api": re.compile(r'AIza[0-9A-Za-z_-]{35}'),
    "firebase_url": re.compile(r'[a-z0-9-]+\.firebaseio\.com'),
    "firebase_key": re.compile(r'firebase[_a-z]*["\']?\s*[:=]\s*["\']([A-Za-z0-9_-]{20,})["\']'),
    "stripe": re.compile(r'sk_live_[0-9a-zA-Z]{24,}'),
    "private_key": re.compile(r'-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----'),
    "bearer": re.compile(r'["\']Bearer\s+[a-zA-Z0-9_\-.]+["\']'),
    "basic_auth": re.compile(r'["\']Basic\s+[A-Za-z0-9+/=]{20,}["\']'),

    "api_key_assign": re.compile(
        r'(api[_-]?key|apikey|secret|token|password|passwd|pwd)\s*[:=]\s*["\']([^"\']{6,100})["\']',
        re.IGNORECASE
    ),
    "android_permission": re.compile(r'android\.permission\.[A-Z_]+'),
    "android_package": re.compile(r'["\']([a-z][a-z0-9_]*(\.[a-z0-9_]+){2,})["\']'),
    "http_insecure": re.compile(r'http://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]{5,200}'),
    "localhost": re.compile(r'(localhost|127\.0\.0\.1|0\.0\.0\.0)(:\d+)?'),
    "debug_flag": re.compile(r'(debug|DEBUG)\s*[:=]\s*(true|True|1)'),
}

WHITELIST_DOMAINS = {
    "schemas.android.com", "w3.org", "apache.org", "xmlpull.org",
    "json-schema.org", "github.com", "github.io", "googleapis.com",
    "gstatic.com", "google.com", "android.com", "kotlinlang.org",
    "oracle.com", "mozilla.org", "creativecommons.org", "purl.org",
    "facebook.com", "fbcdn.net", "apple.com", "microsoft.com",
    "squareup.com", "crashlytics.com",
}

DANGEROUS_FILES = {
    "gradle-wrapper.jar", "debug.keystore", ".env", ".git/config",
    "local.properties", "keystore.jks", "secrets.xml", "secrets.properties",
}

TEXT_EXTS = {
    ".json", ".xml", ".txt", ".js", ".jsx", ".ts", ".tsx",
    ".py", ".php", ".html", ".htm", ".css", ".yml", ".yaml",
    ".ini", ".cfg", ".properties", ".env", ".md", ".gradle",
    ".kt", ".java", ".swift", ".m", ".h", ".c", ".cpp",
    ".dart", ".go", ".rs", ".rb", ".sh", ".bash", ".sql",
    ".smali", ".pro", ".toml", ".lock", "",
}


# ==================== TELEGRAM ====================
async def tg_send(chat_id, text):
    try:
        async with aiohttp.ClientSession() as s:
            async with s.post(
                f"{TELEGRAM_API}/sendMessage",
                json={"chat_id": chat_id, "text": text[:4000], "parse_mode": "Markdown"},
                timeout=15
            ) as r:
                return r.status == 200
    except Exception as e:
        print(f"tg_send err: {e}")
        return False


async def tg_send_doc(chat_id, path, caption=""):
    try:
        async with aiohttp.ClientSession() as s:
            with open(path, "rb") as f:
                form = aiohttp.FormData()
                form.add_field("chat_id", str(chat_id))
                form.add_field("document", f, filename=os.path.basename(path))
                if caption:
                    form.add_field("caption", caption)
                async with s.post(f"{TELEGRAM_API}/sendDocument", data=form, timeout=300) as r:
                    return r.status == 200
    except Exception as e:
        print(f"tg_send_doc err: {e}")
        return False


async def tg_get_updates(offset=0):
    try:
        async with aiohttp.ClientSession() as s:
            async with s.get(
                f"{TELEGRAM_API}/getUpdates",
                params={"timeout": 30, "offset": offset},
                timeout=35
            ) as r:
                data = await r.json()
                if data.get("ok"):
                    return data.get("result", [])
    except:
        pass
    return []


async def tg_download(file_id, dest):
    try:
        async with aiohttp.ClientSession() as s:
            async with s.post(
                f"{TELEGRAM_API}/getFile",
                json={"file_id": file_id},
                timeout=15
            ) as r:
                data = await r.json()
                if not data.get("ok"):
                    return False
                fp = data["result"]["file_path"]

            dl = f"https://api.telegram.org/file/bot{TELEGRAM_BOT_TOKEN}/{fp}"
            async with s.get(dl, timeout=600) as r:
                if r.status != 200:
                    return False
                with open(dest, "wb") as f:
                    async for chunk in r.content.iter_chunked(1024 * 1024):
                        f.write(chunk)
            return True
    except Exception as e:
        print(f"tg_download err: {e}")
        return False


# ==================== ANALYSIS ====================
def is_whitelisted(url):
    try:
        host = urlparse(url).hostname or ""
        return any(w in host for w in WHITELIST_DOMAINS)
    except:
        return False


def analyze_text(content, result):
    for name, pat in PATTERNS.items():
        try:
            matches = pat.findall(content)
        except:
            continue

        if name == "http_url":
            for m in matches[:100]:
                if is_whitelisted(m):
                    continue
                result["urls"].add(m[:300])

        elif name == "http_insecure":
            for m in matches[:50]:
                if is_whitelisted(m):
                    continue
                result["insecure_urls"].add(m[:200])

        elif name == "api_path":
            for m in matches[:100]:
                result["api_paths"].add(m)

        elif name == "ws_url":
            for m in matches[:50]:
                if is_whitelisted(m):
                    continue
                result["ws_urls"].add(m[:200])

        elif name in ["jwt", "aws_access", "google_api", "firebase_key",
                      "stripe", "bearer", "basic_auth", "private_key"]:
            for m in matches[:20]:
                if isinstance(m, tuple):
                    m = m[0]
                result["secrets"].add(f"{name}: {m[:120]}")

        elif name == "firebase_url":
            for m in matches[:20]:
                result["firebase"].add(m)

        elif name == "api_key_assign":
            for k, v in matches[:30]:
                if v.lower() in ["null", "none", "true", "false", "your_key",
                                 "change_me", "xxx", "test"]:
                    continue
                if len(v) < 8:
                    continue
                result["config_secrets"].add(f"{k} = {v[:60]}")

        elif name == "android_permission":
            for m in matches[:50]:
                result["permissions"].add(m)

        elif name == "android_package":
            for m in matches[:30]:
                if m.count(".") >= 2 and len(m) < 80:
                    result["packages"].add(m)

        elif name == "localhost":
            for m in matches[:20]:
                result["localhost_refs"].add(str(m))

        elif name == "debug_flag":
            for m in matches[:10]:
                result["debug_flags"].add(str(m))


def analyze_zip(zip_path, extract_dir):
    result = {
        "file_count": 0, "total_size": 0, "uncompressed_size": 0,
        "file_types": defaultdict(int),
        "urls": set(), "insecure_urls": set(), "ws_urls": set(),
        "api_paths": set(), "secrets": set(), "config_secrets": set(),
        "firebase": set(), "permissions": set(), "packages": set(),
        "localhost_refs": set(), "debug_flags": set(),
        "dangerous_files": [], "interesting_files": [],
        "tech_hints": set(), "big_files": [],
    }

    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            result["file_count"] = len(zf.namelist())
            result["uncompressed_size"] = sum(i.file_size for i in zf.infolist())
            zf.extractall(extract_dir)
    except Exception as e:
        return {"error": f"Extract failed: {e}"}

    for root, dirs, files in os.walk(extract_dir):
        for fname in files:
            fpath = os.path.join(root, fname)
            try:
                size = os.path.getsize(fpath)
            except:
                continue
            result["total_size"] += size

            ext = os.path.splitext(fname)[1].lower()
            result["file_types"][ext] += 1

            if ext == ".dex":
                result["tech_hints"].add("Android (DEX)")
            elif ext == ".apk":
                result["tech_hints"].add("Android (APK nested)")
            elif ext == ".so":
                result["tech_hints"].add("Native (C/C++)")
            elif ext == ".jar":
                result["tech_hints"].add("Java (JAR)")
            elif ext in [".js", ".jsx"]:
                result["tech_hints"].add("JavaScript")
            elif ext in [".ts", ".tsx"]:
                result["tech_hints"].add("TypeScript")
            elif ext == ".py":
                result["tech_hints"].add("Python")
            elif ext == ".php":
                result["tech_hints"].add("PHP")
            elif ext == ".dll":
                result["tech_hints"].add("Windows DLL")
            elif ext == ".exe":
                result["tech_hints"].add("Windows EXE")
            elif ext == ".dart":
                result["tech_hints"].add("Flutter/Dart")
            elif ext == ".kt":
                result["tech_hints"].add("Kotlin")
            elif ext == ".swift":
                result["tech_hints"].add("Swift (iOS)")
            elif ext == ".dylib":
                result["tech_hints"].add("iOS Native")

            if size > 5 * 1024 * 1024:
                result["big_files"].append((os.path.relpath(fpath, extract_dir), size))

            if fname.lower() in [d.lower() for d in DANGEROUS_FILES]:
                result["dangerous_files"].append(os.path.relpath(fpath, extract_dir))

            low = fname.lower()
            for kw in ["config", "secret", "token", "manifest", "strings",
                       "build.gradle", "package.json", "info.plist",
                       ".env", "credentials", "firebase"]:
                if kw in low:
                    result["interesting_files"].append(os.path.relpath(fpath, extract_dir))
                    break

            if ext in TEXT_EXTS and size < 2 * 1024 * 1024:
                try:
                    with open(fpath, "r", errors="ignore") as f:
                        content = f.read(1000000)
                    analyze_text(content, result)
                except:
                    pass

    for k in ["urls", "insecure_urls", "ws_urls", "api_paths", "secrets",
              "config_secrets", "firebase", "permissions", "packages",
              "localhost_refs", "debug_flags", "tech_hints"]:
        result[k] = sorted(list(result[k]))

    result["file_types"] = dict(sorted(result["file_types"].items(), key=lambda x: -x[1]))
    return result


def find_issues(r):
    critical, warning, info = [], [], []

    if r["secrets"]:
        critical.append(f"🔴 *{len(r['secrets'])} hardcoded secrets* — JWT/API keys in source")
    if r["config_secrets"]:
        critical.append(f"🔴 *{len(r['config_secrets'])} config secrets* — plain text keys")
    pk = [s for s in r["secrets"] if "private_key" in s]
    if pk:
        critical.append(f"🔴 *{len(pk)} private key(s)* leaked")
    if r["insecure_urls"]:
        critical.append(f"🔴 *{len(r['insecure_urls'])} HTTP (not HTTPS)* URLs")

    if r["localhost_refs"]:
        warning.append(f"🟡 *{len(r['localhost_refs'])} localhost refs* — dev URLs")
    if r["debug_flags"]:
        warning.append(f"🟡 *{len(r['debug_flags'])} debug flags* enabled")
    for df in r["dangerous_files"]:
        warning.append(f"🟡 *Dangerous file:* `{df}`")
    if r["firebase"]:
        warning.append(f"🟡 *Firebase URL exposed*")

    big = sorted(r.get("big_files", []), key=lambda x: -x[1])[:5]
    for name, size in big:
        if size > 20 * 1024 * 1024:
            warning.append(f"🟡 *Large file:* `{name}` ({size/1024/1024:.1f} MB)")

    if not r["api_paths"] and not r["urls"]:
        info.append("ℹ️ No API endpoints found")
    elif r["api_paths"]:
        info.append(f"ℹ️ {len(r['api_paths'])} API endpoints detected")

    return critical, warning, info


def format_report(r, filename):
    if "error" in r:
        return f"❌ *Analysis Failed*\n\n`{r['error']}`"

    critical, warning, info = find_issues(r)
    lines = [f"📦 *App Analysis: `{filename}`*", ""]

    lines.append("📊 *Overview*")
    lines.append(f"• Files: {r['file_count']:,}")
    lines.append(f"• Size: {r['total_size']/1024/1024:.2f} MB")
    lines.append(f"• Uncompressed: {r['uncompressed_size']/1024/1024:.2f} MB")
    lines.append(f"• Tech: {', '.join(r['tech_hints']) or 'unknown'}")
    lines.append("")

    if critical:
        lines.append("🚨 *CRITICAL ISSUES*")
        lines.extend(critical[:10])
        lines.append("")
    if warning:
        lines.append("⚠️ *WARNINGS*")
        lines.extend(warning[:15])
        lines.append("")
    if info:
        lines.append("ℹ️ *INFO*")
        lines.extend(info[:10])
        lines.append("")

    if r["api_paths"]:
        lines.append(f"🔌 *API Endpoints ({len(r['api_paths'])})*")
        for p in r["api_paths"][:25]:
            lines.append(f"• `{p}`")
        if len(r["api_paths"]) > 25:
            lines.append(f"  ... +{len(r['api_paths'])-25} more")
        lines.append("")

    if r["urls"]:
        lines.append(f"🌐 *URLs ({len(r['urls'])})*")
        for u in r["urls"][:15]:
            lines.append(f"• `{u[:100]}`")
        if len(r["urls"]) > 15:
            lines.append(f"  ... +{len(r['urls'])-15} more")
        lines.append("")

    if r["ws_urls"]:
        lines.append("🔌 *WebSocket URLs*")
        for u in r["ws_urls"][:10]:
            lines.append(f"• `{u[:100]}`")
        lines.append("")

    if r["secrets"] or r["config_secrets"]:
        lines.append("🔑 *Secrets Found (CRITICAL!)*")
        for s in r["secrets"][:5]:
            lines.append(f"• `{s[:100]}`")
        for s in r["config_secrets"][:5]:
            lines.append(f"• `{s[:100]}`")
        lines.append("")

    lines.append("📁 *File Types*")
    for ext, cnt in list(r["file_types"].items())[:12]:
        lines.append(f"• `{ext or 'no ext'}`: {cnt}")
    lines.append("")

    if r["permissions"]:
        lines.append(f"🔐 *Permissions ({len(r['permissions'])})*")
        for p in r["permissions"][:15]:
            lines.append(f"• `{p}`")
        if len(r["permissions"]) > 15:
            lines.append(f"  ... +{len(r['permissions'])-15} more")
        lines.append("")

    return "\n".join(lines)[:4000]


# ==================== HANDLER ====================
async def handle_message(update):
    msg = update.get("message")
    if not msg:
        return
    chat_id = msg["chat"]["id"]
    text = (msg.get("text") or "").strip()

    if text.startswith("/start"):
        await tg_send(chat_id,
            "🔍 *App Analyzer Bot*\n\n"
            "📤 ZIP file ပို့ပါ (APK, JAR, Electron, etc.)\n\n"
            "📋 *ရရှိမည့်အချက်:*\n"
            "• ✅ API endpoints\n"
            "• 🔴 Secrets/Keys leak\n"
            "• ⚠️ HTTP URLs\n"
            "• 🐞 Debug flags\n"
            "• 📁 Tech stack\n"
            "• 🔐 Permissions\n\n"
            "⚠️ Max 100 MB. မင်းပိုင် app ပဲ ပို့ပါ။"
        )
        return

    if text == "/help":
        await tg_send(chat_id,
            "📚 *Help*\n\n"
            "1. `.zip` file ပို့\n"
            "2. Analysis စောင့်\n"
            "3. Report ရ\n\n"
            "⚠️ Static analysis ပဲ"
        )
        return

    doc = msg.get("document")
    if not doc:
        if text:
            await tg_send(chat_id, "📤 ZIP file ပို့ပါ။ /help")
        return

    fname = doc.get("file_name", "app.zip")
    if not fname.lower().endswith(".zip"):
        await tg_send(chat_id, "❌ `.zip` file ပဲ လက်ခံတယ်။")
        return

    fsize = doc.get("file_size", 0)
    if fsize > 100 * 1024 * 1024:
        await tg_send(chat_id, f"❌ File ကြီးလွန်း ({fsize/1024/1024:.1f} MB). Max 100 MB.")
        return

    await tg_send(chat_id, f"📥 Downloading `{fname}` ({fsize/1024/1024:.1f} MB)...")

    ts = int(datetime.now().timestamp())
    zip_path = os.path.join(WORK_DIR, f"{chat_id}_{ts}.zip")
    extract_dir = os.path.join(WORK_DIR, f"{chat_id}_{ts}_extracted")

    ok = await tg_download(doc["file_id"], zip_path)
    if not ok:
        await tg_send(chat_id, "❌ Download failed.")
        return

    await tg_send(chat_id, "🔍 Analyzing...")

    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(None, analyze_zip, zip_path, extract_dir)

    json_path = zip_path.replace(".zip", "_report.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, default=str, ensure_ascii=False)

    if "error" in result:
        await tg_send(chat_id, format_report(result, fname))
    else:
        formatted = format_report(result, fname)
        await tg_send(chat_id, formatted)
        await tg_send_doc(chat_id, json_path, caption="📄 Full JSON report")

        critical, warning, info = find_issues(result)
        await tg_send(chat_id,
            f"✅ *Analysis Complete*\n\n"
            f"🚨 Critical: {len(critical)}\n"
            f"⚠️ Warnings: {len(warning)}\n"
            f"ℹ️ Info: {len(info)}"
        )

    try:
        shutil.rmtree(extract_dir, ignore_errors=True)
        os.remove(zip_path)
        os.remove(json_path)
    except:
        pass


# ==================== MAIN ====================
async def main():
    global last_update_id, running
    print("=" * 50)
    print(f"🔍 App Analyzer Bot started at {datetime.now()}")
    print(f"Token: {TELEGRAM_BOT_TOKEN[:15]}...")
    print("=" * 50)

    # Graceful shutdown for GitHub Actions
    def shutdown(sig, frame):
        global running
        print("Shutdown signal received")
        running = False
    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    while running:
        try:
            updates = await tg_get_updates(last_update_id + 1)
            for u in updates:
                if u.get("update_id", 0) > last_update_id:
                    last_update_id = u["update_id"]
                try:
                    await handle_message(u)
                except Exception as e:
                    print(f"Handler error: {e}")
            await asyncio.sleep(1)
        except Exception as e:
            print(f"Main error: {e}")
            await asyncio.sleep(5)

    print("Bot stopped")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Interrupted")
        sys.exit(0)
