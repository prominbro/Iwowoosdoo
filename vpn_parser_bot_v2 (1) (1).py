#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VPN Subscription Parser Bot v2
Multi-client: Happ -> Incy -> V2RayTun
Supports: vless://, trojan://, ss://, vmess://, hy2://, hysteria2://
Decrypts: happ://crypt/, incy://crypt/, v2raytun:// via api.sayori.cc
"""

import base64
import json
import re
import requests
import os
import random
import string
import tempfile
from urllib.parse import unquote, parse_qs, quote
from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, ContextTypes, filters

# ========== КОНФИГ ==========
BOT_TOKEN = "8726794201:AAGx5grsZi3kg5FHPeQBP_iXFj0GPFl6M9E"

HWID_HAPP = "f8d28f22c504f601"
HWID_INCY = "04425DD1-5B7A-5E99-0298-153229CFC26E"

UA_HAPP = "Happ/3.18.0"
UA_INCY = "Incy/2.7.1"
UA_V2RAYTUN = "v2raytun/5.23.72"

DECRYPT_API = "https://api.sayori.cc/v1/decrypt"

# ========== ГЕНЕРАТОР HWID ==========
def generate_hwid_v2raytun():
    parts = [
        ''.join(random.choices('0123456789abcdef', k=8)),
        ''.join(random.choices('0123456789abcdef', k=4)),
        ''.join(random.choices('0123456789abcdef', k=4)),
        ''.join(random.choices('0123456789abcdef', k=4)),
        ''.join(random.choices('0123456789abcdef', k=12)),
    ]
    return '-'.join(parts)

# ========== КЛИЕНТЫ ==========
CLIENTS = {
    "happ": {
        "name": "Happ",
        "ua": UA_HAPP,
        "hwid": HWID_HAPP,
        "headers": {
            "User-Agent": UA_HAPP,
            "X-HWID": HWID_HAPP,
            "Accept": "*/*",
            "Accept-Encoding": "gzip",
            "Connection": "keep-alive",
        }
    },
    "incy": {
        "name": "Incy",
        "ua": UA_INCY,
        "hwid": HWID_INCY,
        "headers": {
            "User-Agent": UA_INCY,
            "X-HWID": HWID_INCY,
            "Accept": "*/*",
            "Accept-Encoding": "gzip",
            "Connection": "keep-alive",
        }
    },
    "v2raytun": {
        "name": "V2RayTun",
        "ua": UA_V2RAYTUN,
        "hwid": None,
        "headers": {
            "User-Agent": UA_V2RAYTUN,
            "Accept": "*/*",
            "Accept-Encoding": "gzip",
            "Connection": "keep-alive",
        }
    }
}

# ========== ЗАПРОС ПОДПИСКИ ==========
def fetch_subscription(url, client_key="happ", custom_hwid=None):
    client = CLIENTS[client_key]
    headers = client["headers"].copy()

    if client_key == "v2raytun":
        hwid = custom_hwid or generate_hwid_v2raytun()
    else:
        hwid = custom_hwid or client["hwid"]
    headers["X-HWID"] = hwid

    try:
        resp = requests.get(url, headers=headers, timeout=30, allow_redirects=True)
        resp.raise_for_status()
        return {"text": resp.text, "hwid": hwid, "client": client_key, "status": resp.status_code}
    except Exception as e:
        return {"text": f"ERROR: {e}", "hwid": hwid, "client": client_key, "status": 0, "error": str(e)}

# ========== BASE64 ДЕКОДЕР ==========
def try_base64_decode(text):
    try:
        clean = text.strip().replace("\n", "").replace(" ", "")
        padding = 4 - len(clean) % 4
        if padding != 4:
            clean += "=" * padding
        decoded = base64.b64decode(clean).decode("utf-8", errors="ignore")
        return decoded, True
    except Exception:
        return text, False

# ========== API РАСШИФРОВКИ ==========
def decrypt_link(link):
    try:
        resp = requests.post(
            DECRYPT_API,
            headers={"Content-Type": "application/json"},
            json={"link": link},
            timeout=30
        )
        resp.raise_for_status()
        data = resp.json()
        if data.get("success"):
            return data.get("result", ""), True
        return data.get("result", "API error"), False
    except Exception as e:
        return f"ERROR: {e}", False

# ========== ИЗВЛЕЧЕНИЕ КЛЮЧЕЙ ==========
def extract_all_keys(text):
    pattern = r'(vless://|trojan://|ss://|vmess://|hy2://|hysteria2://)[^\s\n]+'
    matches = re.finditer(pattern, text)
    return [m.group(0) for m in matches]

# ========== VMESS ДЕКОДЕР ==========
def decode_vmess(vmess_url):
    try:
        b64 = vmess_url.replace("vmess://", "")
        padding = 4 - len(b64) % 4
        if padding != 4:
            b64 += "=" * padding
        decoded = base64.b64decode(b64).decode("utf-8")
        return json.loads(decoded)
    except Exception as e:
        return {"error": str(e), "raw": vmess_url}

# ========== HYSTERIA2/HY2 ПАРСЕР ==========
def parse_hy2(uri):
    try:
        scheme = uri.split("://")[0]
        rest = uri.split("://", 1)[1]
        result = {"scheme": scheme, "raw": uri}

        if "@" in rest:
            auth_part, server_part = rest.split("@", 1)
            result["password"] = auth_part

            if "?" in server_part:
                addr_port, query = server_part.split("?", 1)
            else:
                addr_port = server_part
                query = ""

            if ":" in addr_port:
                result["address"] = addr_port.rsplit(":", 1)[0]
                result["port"] = int(addr_port.rsplit(":", 1)[1].replace("/", ""))

            if query:
                if "#" in query:
                    query, fragment = query.split("#", 1)
                    result["name"] = unquote(fragment)
                params = parse_qs(query)
                for k, v in params.items():
                    result[k] = v[0]

        return result
    except Exception as e:
        return {"error": str(e), "raw": uri}

# ========== VLESS/TROJAN/SS/HY2 ПАРСЕР ==========
def parse_proxy_uri(uri):
    try:
        scheme = uri.split("://")[0]
        rest = uri.split("://", 1)[1]
        result = {"scheme": scheme, "raw": uri}

        if scheme == "vmess":
            return decode_vmess(uri)

        if scheme in ("hy2", "hysteria2"):
            return parse_hy2(uri)

        if "@" in rest:
            auth_part, server_part = rest.split("@", 1)

            if scheme == "ss":
                try:
                    auth_decoded = base64.b64decode(auth_part + "==").decode("utf-8")
                    if ":" in auth_decoded:
                        result["method"] = auth_decoded.split(":")[0]
                        result["password"] = auth_decoded.split(":", 1)[1]
                except:
                    result["auth_b64"] = auth_part
            else:
                result["uuid"] = auth_part

            if "?" in server_part:
                addr_port, query = server_part.split("?", 1)
            else:
                addr_port = server_part
                query = ""

            if ":" in addr_port:
                result["address"] = addr_port.rsplit(":", 1)[0]
                result["port"] = int(addr_port.rsplit(":", 1)[1].replace("/", ""))

            if query:
                if "#" in query:
                    query, fragment = query.split("#", 1)
                    result["name"] = unquote(fragment)
                params = parse_qs(query)
                for k, v in params.items():
                    result[k] = v[0]

        return result
    except Exception as e:
        return {"error": str(e), "raw": uri}

# ========== КОНВЕРТЕР JSON (Sing-box/v2ray) → URI ==========
def json_to_uri(obj):
    """Конвертирует JSON-конфиг sing-box/v2ray в URI (один outbound)"""
    try:
        outbounds = obj.get("outbounds", [])
        if not outbounds:
            return None

        proxy = None
        for ob in outbounds:
            tag = ob.get("tag", "")
            if tag in ("direct", "block", "DIRECT", "BLOCK", "freedom", "blackhole"):
                continue
            if ob.get("protocol", "") in ("vless", "trojan", "shadowsocks", "vmess"):
                proxy = ob
                break
        if not proxy:
            return None

        protocol = proxy.get("protocol", "")
        settings = proxy.get("settings", {})
        stream = proxy.get("streamSettings", {})
        remarks = obj.get("remarks", "")

        if protocol == "vless":
            vnext = settings.get("vnext", [{}])[0]
            address = vnext.get("address", "")
            port = vnext.get("port", "")
            user = vnext.get("users", [{}])[0]
            uid = user.get("id", "")
            flow = user.get("flow", "")

            params = {}
            if flow:
                params["flow"] = flow

            net = stream.get("network", "tcp")
            if net and net != "tcp":
                params["type"] = net

            sec = stream.get("security", "")
            if sec == "reality":
                params["security"] = "reality"
                rs = stream.get("realitySettings", {})
                if rs.get("serverName"):
                    params["sni"] = rs["serverName"]
                if rs.get("publicKey"):
                    params["pbk"] = rs["publicKey"]
                if rs.get("shortId"):
                    params["sid"] = rs["shortId"]
                if rs.get("fingerprint"):
                    params["fp"] = rs["fingerprint"]
                if rs.get("spiderX"):
                    params["spx"] = quote(rs["spiderX"], safe="")
            elif sec == "tls":
                params["security"] = "tls"

            if net == "grpc":
                gs = stream.get("grpcSettings", {})
                if gs.get("serviceName"):
                    params["serviceName"] = gs["serviceName"]

            param_str = "&".join(f"{k}={quote(str(v), safe='')}" for k, v in params.items())
            uri = f"vless://{uid}@{address}:{port}"
            if param_str:
                uri += "?" + param_str
            if remarks:
                uri += "#" + quote(remarks, safe="")
            return uri

        elif protocol == "shadowsocks":
            servers = settings.get("servers", [{}])[0]
            address = servers.get("address", "")
            port = servers.get("port", "")
            password = servers.get("password", "")
            method = servers.get("method", "")
            auth = base64.b64encode(f"{method}:{password}".encode()).decode().rstrip("=")
            uri = f"ss://{auth}@{address}:{port}"
            if remarks:
                uri += "#" + quote(remarks, safe="")
            return uri

        elif protocol == "trojan":
            servers = settings.get("servers", [{}])[0]
            address = servers.get("address", "")
            port = servers.get("port", "")
            password = servers.get("password", "")
            params = {}
            net = stream.get("network", "")
            if net and net != "tcp":
                params["type"] = net
            sec = stream.get("security", "")
            if sec:
                params["security"] = sec
            param_str = "&".join(f"{k}={quote(str(v), safe='')}" for k, v in params.items())
            uri = f"trojan://{password}@{address}:{port}"
            if param_str:
                uri += "?" + param_str
            if remarks:
                uri += "#" + quote(remarks, safe="")
            return uri

        elif protocol == "vmess":
            vnext = settings.get("vnext", [{}])[0]
            address = vnext.get("address", "")
            port = vnext.get("port", "")
            user = vnext.get("users", [{}])[0]
            uid = user.get("id", "")
            vmess_json = {
                "v": "2", "ps": remarks, "add": address, "port": str(port),
                "id": uid, "aid": "0", "scy": "auto",
                "net": stream.get("network", "tcp"), "type": "none",
                "host": "", "path": "", "tls": stream.get("security", ""),
                "sni": "", "fp": "",
            }
            b64 = base64.b64encode(json.dumps(vmess_json).encode()).decode()
            return f"vmess://{b64}"

        return None
    except Exception:
        return None


def json_to_uris(obj):
    """
    Извлекает ВСЕ прокси-outbound's из JSON-конфига и возвращает список URI.
    Поддерживает конфиги с balancers (много outbounds).
    """
    uris = []
    try:
        outbounds = obj.get("outbounds", [])
        if not outbounds:
            return uris

        remarks = obj.get("remarks", "")

        for ob in outbounds:
            tag = ob.get("tag", "")
            protocol = ob.get("protocol", "")
            # Пропускаем non-proxy
            if tag in ("direct", "block", "DIRECT", "BLOCK", "freedom", "blackhole"):
                continue
            if protocol not in ("vless", "trojan", "shadowsocks", "vmess"):
                continue

            # Формируем мини-объект для конвертации
            mini_obj = {
                "outbounds": [ob],
                "remarks": remarks
            }
            uri = json_to_uri(mini_obj)
            if uri:
                # Если remarks нет, используем tag как имя
                if not remarks and tag:
                    uri += "#" + quote(tag, safe="")
                uris.append(uri)
    except Exception:
        pass
    return uris


# ========== JSON КОНФИГИ ==========
def parse_json_configs(text):
    """Парсит JSON и конвертирует в URI через json_to_uri и json_to_uris"""
    uris = []
    try:
        data = json.loads(text)
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    # Сначала пробуем извлечь ВСЕ прокси из конфига
                    extracted = json_to_uris(item)
                    if extracted:
                        uris.extend(extracted)
                    else:
                        # Fallback — одиночный URI
                        uri = json_to_uri(item)
                        if uri:
                            uris.append(uri)
        elif isinstance(data, dict):
            extracted = json_to_uris(data)
            if extracted:
                uris.extend(extracted)
            else:
                uri = json_to_uri(data)
                if uri:
                    uris.append(uri)
    except json.JSONDecodeError:
        pass
    return uris

# ========== ОБРАБОТКА ПОДПИСКИ (FALLBACK) ==========
def process_subscription(url, custom_hwid=None):
    """
    Последовательный fallback:
    1. Happ -> если OK, возвращаем результат
    2. Incy -> если Happ упал, пробуем Incy
    3. V2RayTun -> если Incy упал, пробуем V2RayTun
    Только 1 подключение за раз.
    """
    all_results = []
    all_keys = []
    all_crypts = []
    all_decrypted = []
    all_json = []
    all_parsed = []
    errors = []
    success_client = None
    
    for client_key in ["happ", "incy", "v2raytun"]:
        if client_key == "v2raytun":
            hwid = custom_hwid or generate_hwid_v2raytun()
        else:
            hwid = custom_hwid or (HWID_HAPP if client_key == "happ" else HWID_INCY)
        
        resp = fetch_subscription(url, client_key, hwid)
        
        all_results.append({
            "client": client_key,
            "hwid": resp["hwid"],
            "status": resp["status"],
        })
        
        if resp["text"].startswith("ERROR:"):
            errors.append(f"{client_key}: {resp['text']}")
            continue  # Пробуем следующий клиент
        
        # Успех! Обрабатываем результат и выходим
        success_client = client_key
        text = resp["text"]
        
        # Crypt ссылки
        crypt_pattern = r'(happ://crypt\d?-?\d?/[^\s]+|v2raytun://[^\s]+|incy://crypt\d?-?\d?/[^\s]+)'
        crypt_matches = re.findall(crypt_pattern, text)
        all_crypts.extend(crypt_matches)
        
        for c in crypt_matches:
            decrypted, ok = decrypt_link(c)
            all_decrypted.append({
                "client": client_key,
                "encrypted": c,
                "decrypted": decrypted,
                "success": ok
            })
            if ok:
                text += "\n" + decrypted
        
        # Base64 decode
        decoded, is_b64 = try_base64_decode(text)
        if is_b64:
            text = decoded
        
        # Извлечение ключей из текста
        keys = extract_all_keys(text)
        for k in keys:
            all_keys.append({"client": client_key, "key": k})
            all_parsed.append({"client": client_key, "parsed": parse_proxy_uri(k)})
        
        # JSON конфиги → URI
        json_uris = parse_json_configs(text)
        for uri in json_uris:
            all_keys.append({"client": client_key, "key": uri})
            all_parsed.append({"client": client_key, "parsed": parse_proxy_uri(uri)})

        # Сырые JSON для info
        try:
            raw_json = json.loads(text)
            if isinstance(raw_json, list):
                for item in raw_json:
                    if isinstance(item, dict):
                        all_json.append({"client": client_key, "config": item})
            elif isinstance(raw_json, dict):
                all_json.append({"client": client_key, "config": raw_json})
        except:
            pass
        
        break  # Успех — останавливаемся
    
    # Уникальные ключи
    seen = set()
    unique_keys = []
    for k in all_keys:
        if k["key"] not in seen:
            seen.add(k["key"])
            unique_keys.append(k)
    
    return {
        "url": url,
        "clients": all_results,
        "success_client": success_client,
        "keys": unique_keys,
        "all_keys_count": len(all_keys),
        "json_configs": all_json,
        "happ_crypt": list(set(all_crypts)),
        "decrypted_crypt": all_decrypted,
        "parsed_configs": all_parsed,
        "errors": errors
    }

def format_result(result):
    lines = []
    lines.append(f"🔗 `{result['url']}`")
    lines.append("")

    for cr in result["clients"]:
        icon = "✅" if cr["status"] == 200 else ("⚠️" if cr["status"] != 0 else "❌")
        lines.append(f"{icon} **{cr['client'].upper()}** | HWID: `{cr['hwid']}` | HTTP {cr['status']}")
    lines.append("")

    if result["errors"]:
        lines.append("⚠️ Errors:")
        for e in result["errors"][:3]:
            lines.append(f"  `{e}`")
        lines.append("")

    lines.append(f"🔑 Keys: **{len(result['keys'])}** unique ({result['all_keys_count']} total)")
    lines.append(f"🔒 Crypt: {len(result['happ_crypt'])} | 🔓 Decrypted: {sum(1 for d in result['decrypted_crypt'] if d['success'])}")
    lines.append(f"📄 JSON: {len(result['json_configs'])}")
    if result.get("success_client"):
        lines.append(f"✅ **Работает через:** {result['success_client'].upper()}")
    lines.append("")

    if result["keys"]:
        lines.append("📋 **Keys:**")
        for k in result["keys"][:15]:
            lines.append(f"`[{k['client']}] {k['key']}`")
        if len(result["keys"]) > 15:
            lines.append(f"... +{len(result['keys']) - 15} more")
        lines.append("")
    else:
        lines.append("📋 **Keys:** не найдено")
        lines.append("")

    if result["decrypted_crypt"]:
        success_dec = [d for d in result["decrypted_crypt"] if d["success"]]
        if success_dec:
            lines.append("🔓 **Decrypted:**")
            for d in success_dec[:10]:
                lines.append(f"`[{d['client']}] {d['decrypted']}`")
            lines.append("")

    return "\n".join(lines)

# ========== TELEGRAM HANDLERS ==========
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "👋 **VPN Subscription Parser**\n"
        "Multi-client: Happ -> Incy -> V2RayTun\n\n"
        "**Отправь URL подписки** — спарсю всеми тремя клиентами\n\n"
        "**Команды:**\n"
        "/hwid_happ `<hwid>` — HWID Happ\n"
        "/hwid_incy `<hwid>` — HWID Incy\n"
        "/hwid_v2 `<hwid>` — HWID V2RayTun (default: random)\n"
        "/random_v2 — новый рандомный HWID V2RayTun\n"
        "/status — текущие HWID\n"
        "/decrypt `<link>` — расшифровать happ://crypt/\n",
        parse_mode="Markdown"
    )

async def set_hwid_happ(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("Использование: /hwid_happ `<hwid>`", parse_mode="Markdown")
        return
    context.user_data["hwid_happ"] = context.args[0]
    await update.message.reply_text(f"✅ Happ HWID: `{context.args[0]}`", parse_mode="Markdown")

async def set_hwid_incy(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("Использование: /hwid_incy `<hwid>`", parse_mode="Markdown")
        return
    context.user_data["hwid_incy"] = context.args[0]
    await update.message.reply_text(f"✅ Incy HWID: `{context.args[0]}`", parse_mode="Markdown")

async def set_hwid_v2(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("Использование: /hwid_v2 `<hwid>`", parse_mode="Markdown")
        return
    context.user_data["hwid_v2raytun"] = context.args[0]
    await update.message.reply_text(f"✅ V2RayTun HWID: `{context.args[0]}`", parse_mode="Markdown")

async def random_v2(update: Update, context: ContextTypes.DEFAULT_TYPE):
    hwid = generate_hwid_v2raytun()
    context.user_data["hwid_v2raytun"] = hwid
    await update.message.reply_text(f"🎲 V2RayTun HWID: `{hwid}`", parse_mode="Markdown")

async def status(update: Update, context: ContextTypes.DEFAULT_TYPE):
    h = context.user_data.get("hwid_happ", HWID_HAPP)
    i = context.user_data.get("hwid_incy", HWID_INCY)
    v = context.user_data.get("hwid_v2raytun", "random (per request)")
    await update.message.reply_text(
        f"🆔 **HWID Status**\n"
        f"Happ: `{h}`\n"
        f"Incy: `{i}`\n"
        f"V2RayTun: `{v}`",
        parse_mode="Markdown"
    )

async def decrypt_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("Использование: /decrypt `<link>`", parse_mode="Markdown")
        return
    link = context.args[0]
    msg = await update.message.reply_text("🔓 Расшифровываю...")
    decrypted, ok = decrypt_link(link)
    if ok:
        await msg.edit_text(f"✅ Расшифровано:\n`{decrypted}`", parse_mode="Markdown")
    else:
        await msg.edit_text(f"❌ Ошибка: `{decrypted}`", parse_mode="Markdown")

async def parse_subscription(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = update.message.text.strip()

    if not (text.startswith("http") or text.startswith("happ://") or 
            text.startswith("v2raytun://") or text.startswith("incy://")):
        await update.message.reply_text("Отправь URL подписки или crypt-ссылку")
        return

    custom_hwids = {}
    if "hwid_happ" in context.user_data:
        custom_hwids["happ"] = context.user_data["hwid_happ"]
    if "hwid_incy" in context.user_data:
        custom_hwids["incy"] = context.user_data["hwid_incy"]
    if "hwid_v2raytun" in context.user_data:
        custom_hwids["v2raytun"] = context.user_data["hwid_v2raytun"]

    msg = await update.message.reply_text("⏳ Запрашиваю: Happ -> Incy -> V2RayTun...")

    try:
        v2_hwid = custom_hwids.get("v2raytun")
        result = process_subscription(text, custom_hwid=v2_hwid)

        for cr in result["clients"]:
            if cr["client"] == "happ" and "happ" in custom_hwids:
                cr["hwid"] = custom_hwids["happ"]
            if cr["client"] == "incy" and "incy" in custom_hwids:
                cr["hwid"] = custom_hwids["incy"]
            if cr["client"] == "v2raytun" and "v2raytun" in custom_hwids:
                cr["hwid"] = custom_hwids["v2raytun"]

        response = format_result(result)

        # Всегда сохраняем ключи в файл и отправляем
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False, encoding='utf-8') as f:
            for k in result["keys"]:
                f.write(f"{k['key']}\n")
            tmp_path = f.name

        try:
            await update.message.reply_document(
                document=open(tmp_path, 'rb'),
                caption=f"📄 {result.get('success_client', 'unknown').upper()} | Keys: {len(result['keys'])} | Crypt: {len(result['happ_crypt'])}",
            )
        except Exception as doc_err:
            await msg.edit_text(f"❌ Ошибка отправки файла: {doc_err}")
        finally:
            try:
                os.unlink(tmp_path)
            except:
                pass

        # Отправляем summary текстом
        try:
            if len(response) <= 4000:
                await update.message.reply_text(response, parse_mode="Markdown")
        except Exception:
            pass

        try:
            await msg.delete()
        except Exception:
            pass

    except Exception as e:
        await msg.edit_text(f"❌ Ошибка: `{e}`", parse_mode="Markdown")

def main():
    app = Application.builder().token(BOT_TOKEN).build()

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("hwid_happ", set_hwid_happ))
    app.add_handler(CommandHandler("hwid_incy", set_hwid_incy))
    app.add_handler(CommandHandler("hwid_v2", set_hwid_v2))
    app.add_handler(CommandHandler("random_v2", random_v2))
    app.add_handler(CommandHandler("status", status))
    app.add_handler(CommandHandler("decrypt", decrypt_cmd))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, parse_subscription))

    print("🤖 Бот запущен! Multi-client: Happ -> Incy -> V2RayTun")
    app.run_polling()

if __name__ == "__main__":
    main()
