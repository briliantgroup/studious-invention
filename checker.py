#!/usr/bin/env python3
"""
VpnSingboxCheker
Проверка VPN ключей через sing-box — "как человек":
  1. Запускаем sing-box с ключом как outbound
  2. Делаем HTTP запрос через SOCKS5 (как браузер через VPN)
  3. Измеряем: загружается ли страница, за сколько, какой IP/страна

Протоколы: VLESS (WS/gRPC/TCP/Reality), VMess, Trojan, Shadowsocks,
           Hysteria2, TUIC v5
"""

import argparse
import asyncio
import base64
import json
import os
import platform
import re
import shutil
import socket
import stat
import subprocess
import sys
import time
import urllib.parse
import urllib.request
import zipfile
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from threading import Lock, Semaphore

import requests
import urllib3

urllib3.disable_warnings()

# ─── Пути ────────────────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).parent
SUBS_FILE = BASE_DIR / "subscriptions.txt"
RESULTS = BASE_DIR / "results"
COUNTRIES = RESULTS / "countries"
BIN_DIR = BASE_DIR / "bin"
TMP_DIR = BASE_DIR / ".tmp"

for d in (RESULTS, COUNTRIES, BIN_DIR, TMP_DIR):
    d.mkdir(exist_ok=True)

# ─── Конфигурация ─────────────────────────────────────────────────────────────
CFG = {
    "test_url": "http://cp.cloudflare.com/generate_204",
    "timeout": 5,  # секунды на TTFB запрос
    "tcp_timeout": 2.0,
    "tcp_workers": 300,
    "workers": 50,
    "warmup_ms": 300,  # sing-box стартует быстрее Mihomo
    "startup_timeout": 4.0,
    "kill_delay": 0.02,
    "max_ping_ms": 0,
    "check_speed": False,
    "min_speed_mbps": 0.0,
    "speed_max_mb": 5.0,
    "speed_timeout": 15.0,
}

REAL_IP: str = ""

# ─── Счётчики фейлов ──────────────────────────────────────────────────────────
import threading as _threading

_stats_lock = _threading.Lock()
FAIL_STATS: dict[str, int] = defaultdict(int)
DEBUG_LOG: list[str] = []
DEBUG_MAX = 20
VERBOSE_LIMIT = 15
_verbose_count = 0


def _fail(reason: str, uri: str = "") -> None:
    global _verbose_count
    with _stats_lock:
        FAIL_STATS[reason] += 1
        if len(DEBUG_LOG) < DEBUG_MAX and uri:
            DEBUG_LOG.append(f"[{reason}] {uri[:80]}")
        if _verbose_count < VERBOSE_LIMIT:
            _verbose_count += 1
            print(
                f"\n  ❌ FAIL[{_verbose_count}] {reason}\n       {uri[:70]}", flush=True
            )


def print_fail_stats() -> None:
    print("\n" + "=" * 60)
    print("  ДИАГНОСТИКА")
    print("=" * 60)
    total = sum(FAIL_STATS.values())
    for r, c in sorted(FAIL_STATS.items(), key=lambda x: -x[1]):
        bar = "#" * min(35, int(c / max(total, 1) * 35))
        print(f"  {r:<40} {c:>5}  {bar}")
    if DEBUG_LOG:
        print("\n  Примеры:")
        for l in DEBUG_LOG[:10]:
            print(f"    {l}")
    print("=" * 60)


# ─── Allowed SS ciphers ───────────────────────────────────────────────────────
SS_ALLOWED = {
    # SS 2022
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
    # AEAD
    "aes-128-gcm",
    "aes-256-gcm",
    "chacha20-poly1305",
    "chacha20-ietf-poly1305",
    "xchacha20-poly1305",
    "xchacha20-ietf-poly1305",
    # Stream (sing-box поддерживает)
    "aes-128-cfb",
    "aes-256-cfb",
    "aes-128-ctr",
    "aes-256-ctr",
    "rc4-md5",
    "chacha20",
    "chacha20-ietf",
    "bf-cfb",
    "none",
    "plain",
}


# ─── Флаги стран ──────────────────────────────────────────────────────────────
def country_flag(code: str) -> str:
    code = (code or "").upper().strip()
    if len(code) != 2:
        return "🌍"
    return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in code)


def shorten_provider(name: str) -> str:
    if not name:
        return ""
    shortcuts = {
        "DigitalOcean": "DO",
        "Digital Ocean": "DO",
        "Amazon": "AWS",
        "Google": "GCP",
        "Microsoft": "Azure",
        "Hetzner Online": "Hetzner",
        "OVH": "OVH",
        "Vultr": "Vultr",
        "Cloudflare": "CF",
        "Contabo": "Contabo",
        "Aeza": "Aeza",
        "Selectel": "Selectel",
        "TimeWeb": "TimeWeb",
    }
    for k, v in shortcuts.items():
        if k.lower() in name.lower():
            return v
    name = re.sub(r"^AS\d+\s+", "", name).strip()
    return name[:28] + "..." if len(name) > 28 else name


# ═══════════════════════════════════════════════════════════════════════════════
# ШАГ 0: Установка sing-box
# ═══════════════════════════════════════════════════════════════════════════════


def get_singbox_path() -> Path:
    name = "sing-box.exe" if platform.system() == "Windows" else "sing-box"
    return BIN_DIR / name


def is_singbox_installed() -> bool:
    return get_singbox_path().exists()


def install_singbox():
    print("⬇️  Устанавливаю sing-box...")
    system = platform.system().lower()
    machine = platform.machine().lower()

    if system == "windows":
        ext = ".zip"
        arch = "arm64" if "arm" in machine else "amd64"
    elif system == "linux":
        ext = ".tar.gz"
        arch = "arm64" if ("aarch64" in machine or "arm64" in machine) else "amd64"
    else:  # darwin
        ext = ".tar.gz"
        arch = "arm64" if "arm" in machine else "amd64"

    api = "https://api.github.com/repos/SagerNet/sing-box/releases/latest"
    try:
        r = requests.get(
            api, timeout=15, headers={"User-Agent": "VpnSingboxCheker/1.0"}
        )
        data = r.json()
        tag = data["tag_name"]
        assets = data["assets"]
    except Exception as e:
        sys.exit(f"GitHub API error: {e}")

    ver = tag.lstrip("v")
    print(f"   Версия: {tag}, os: {system}, arch: {arch}")

    # Формат ассета: sing-box-{ver}-{os}-{arch}[{-variant}].{ext}
    # Приоритет выбора:
    #   1. Точное имя без суффикса (plain): sing-box-{ver}-linux-amd64.tar.gz
    #   2. glibc вариант: sing-box-{ver}-linux-amd64-glibc.tar.gz
    #   3. Любой подходящий
    plat = system  # "linux", "windows", "darwin"

    exact_name = f"sing-box-{ver}-{plat}-{arch}{ext}"
    glibc_name = f"sing-box-{ver}-{plat}-{arch}-glibc{ext}"

    # Словарь имя → url
    asset_map = {a["name"]: a["browser_download_url"] for a in assets}

    url = (
        asset_map.get(exact_name)  # 1. plain
        or asset_map.get(glibc_name)  # 2. glibc
    )

    if not url:
        # 3. Любой с правильной платформой/arch/расширение
        #    Исключаем: android, apk, deb, rpm, pkg, musl, legacy, softfloat
        skip = {
            "android",
            "apk",
            ".deb",
            ".rpm",
            ".pkg",
            ".zst",
            "musl",
            "legacy",
            "softfloat",
        }
        candidates = []
        for a in assets:
            n = a["name"]
            if (
                f"-{plat}-{arch}" in n
                and n.endswith(ext)
                and not any(s in n for s in skip)
            ):
                candidates.append(a["browser_download_url"])
        if candidates:
            url = candidates[0]

    if not url:
        names = [a["name"] for a in assets if arch in a["name"]][:10]
        sys.exit(f"Не нашёл asset для {system}/{arch}.\nДоступные: {names}")

    print(f"   Скачиваю: {url.split('/')[-1]}")
    r = requests.get(
        url, timeout=300, stream=True, headers={"User-Agent": "VpnSingboxCheker/1.0"}
    )
    r.raise_for_status()

    dl_path = TMP_DIR / f"singbox_dl{ext}"
    with open(dl_path, "wb") as f:
        for chunk in r.iter_content(65536):
            f.write(chunk)

    target = get_singbox_path()

    if ext == ".zip":
        with zipfile.ZipFile(dl_path) as z:
            for name in z.namelist():
                if name.endswith(".exe") and "sing-box" in name.lower():
                    with z.open(name) as src, open(target, "wb") as dst:
                        shutil.copyfileobj(src, dst)
                    break
            else:
                z.extractall(BIN_DIR)
    else:
        import tarfile

        with tarfile.open(dl_path) as tf:
            for m in tf.getmembers():
                if m.name.endswith("sing-box") and not m.isdir():
                    f = tf.extractfile(m)
                    if f:
                        with open(target, "wb") as dst:
                            shutil.copyfileobj(f, dst)
                    break

    if target.exists():
        os.chmod(
            target, target.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH
        )
        print(f"   ✅ sing-box установлен: {target}")
    else:
        sys.exit(f"sing-box не найден после распаковки: {target}")


# ═══════════════════════════════════════════════════════════════════════════════
# ШАГ 1: Сбор ключей
# ═══════════════════════════════════════════════════════════════════════════════


def load_subscription_urls() -> list[str]:
    if not SUBS_FILE.exists():
        sys.exit(f"❌ {SUBS_FILE} не найден")
    urls = []
    with open(SUBS_FILE, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                urls.append(line)
    return urls


PROTOCOLS = (
    "vless://",
    "vmess://",
    "trojan://",
    "ss://",
    "hy2://",
    "hysteria2://",
    "tuic://",
    "wireguard://",
)


def decode_content(text: str) -> str:
    text = text.strip()
    if any(text.startswith(p) for p in PROTOCOLS):
        return text
    try:
        decoded = base64.b64decode(pad_b64(text)).decode("utf-8", errors="ignore")
        if any(p in decoded for p in PROTOCOLS):
            return decoded
    except Exception:
        pass
    return text


def extract_keys(text: str) -> list[str]:
    keys = []
    for line in text.splitlines():
        line = line.strip()
        if any(line.startswith(p) for p in PROTOCOLS):
            keys.append(line)
    return keys


def fetch_all_keys(urls: list[str]) -> list[str]:
    all_keys = []
    print(f"📥 Загружаю {len(urls)} подписок...")

    def fetch_one(url):
        try:
            r = requests.get(
                url, timeout=15, verify=False, headers={"User-Agent": "Mozilla/5.0"}
            )
            if r.status_code >= 400:
                return []
            return extract_keys(decode_content(r.text))
        except Exception:
            return []

    with ThreadPoolExecutor(max_workers=20) as ex:
        futures = {ex.submit(fetch_one, u): u for u in urls}
        done = 0
        for fut in as_completed(futures):
            all_keys.extend(fut.result())
            done += 1
            print(
                f"\r   {done}/{len(urls)} подписок | {len(all_keys)} ключей",
                end="",
                flush=True,
            )
    print(f"\n✅ Собрано: {len(all_keys)} ключей")
    return all_keys


# ═══════════════════════════════════════════════════════════════════════════════
# ШАГ 2: Дедупликация
# ═══════════════════════════════════════════════════════════════════════════════


def pad_b64(s: str) -> str:
    return s + "=" * (4 - len(s) % 4)


def _qs(query: str) -> dict:
    d = {}
    for part in query.lstrip("?").split("&"):
        if "=" in part:
            k, v = part.split("=", 1)
            d[urllib.parse.unquote(k)] = urllib.parse.unquote(v)
    return d


def get_uri_identity(uri: str):
    try:
        clean = uri.split("#")[0].strip()
        if clean.startswith("vmess://"):
            data = json.loads(
                base64.b64decode(pad_b64(clean[8:])).decode("utf-8", errors="ignore")
            )
            return (
                "vmess",
                str(data.get("add", "")).lower(),
                int(data.get("port", 0)),
                str(data.get("id", "")),
            )
        p = urllib.parse.urlparse(clean)
        host = (p.hostname or "").lower()
        port = p.port or 0
        proto = p.scheme.lower()
        if proto == "vless":
            return ("vless", host, port, p.username or "")
        if proto == "trojan":
            return ("trojan", host, port, urllib.parse.unquote(p.username or ""))
        if proto == "ss":
            return ("ss", host, port, p.username or "")
        if proto in ("hysteria2", "hy2"):
            return ("hy2", host, port, p.username or "")
        if proto == "tuic":
            return ("tuic", host, port, p.username or "")
    except Exception:
        pass
    return None


def get_host_port(uri: str) -> tuple[str, int]:
    try:
        clean = uri.split("#")[0]
        if "vmess://" in clean:
            data = json.loads(
                base64.b64decode(pad_b64(clean[8:])).decode("utf-8", errors="ignore")
            )
            return str(data.get("add", "")), int(data.get("port", 0))
        p = urllib.parse.urlparse(clean)
        return (p.hostname or "").lower(), p.port or 0
    except Exception:
        return "", 0


def deduplicate(keys: list[str]) -> list[str]:
    seen, result, dupes, invalid = set(), [], 0, 0
    for k in keys:
        ident = get_uri_identity(k)
        if ident is None:
            invalid += 1
            continue
        if ident in seen:
            dupes += 1
            continue
        seen.add(ident)
        result.append(k)
    msg = f"🔄 Дедупликация: {len(keys)} → {len(result)} (дублей: {dupes}"
    if invalid:
        msg += f", невалидных: {invalid}"
    print(msg + ")")
    return result


# ═══════════════════════════════════════════════════════════════════════════════
# ШАГ 3: TCP пре-фильтр
# ═══════════════════════════════════════════════════════════════════════════════


async def _tcp_check(host: str, port: int, timeout: float) -> bool:
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except Exception:
        return False


async def _tcp_filter_async(
    uris: list[str], timeout: float, max_workers: int
) -> list[str]:
    sem = asyncio.Semaphore(max_workers)
    results = []
    done = [0]
    lock = asyncio.Lock()

    async def check(uri):
        host, port = get_host_port(uri)
        if not host or not port:
            async with lock:
                done[0] += 1
            return
        async with sem:
            ok = await _tcp_check(host, port, timeout)
        async with lock:
            done[0] += 1
            if ok:
                results.append(uri)
            print(
                f"\r   TCP: {done[0]}/{len(uris)} | живых: {len(results)}",
                end="",
                flush=True,
            )

    await asyncio.gather(*[check(u) for u in uris])
    return results


def tcp_filter(uris: list[str]) -> list[str]:
    print(f"🔍 TCP пре-фильтр {len(uris)} ключей (timeout={CFG['tcp_timeout']}s)...")
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    result = asyncio.run(
        _tcp_filter_async(uris, CFG["tcp_timeout"], CFG["tcp_workers"])
    )
    print(f"\n✅ TCP: {len(result)}/{len(uris)} доступно")
    return result


# ═══════════════════════════════════════════════════════════════════════════════
# ШАГ 4: Парсер URI → sing-box outbound JSON
# ═══════════════════════════════════════════════════════════════════════════════

_CF_PREFIXES = (
    "172.64.",
    "172.65.",
    "172.66.",
    "172.67.",
    "104.16.",
    "104.17.",
    "104.18.",
    "104.19.",
    "104.20.",
    "104.21.",
    "173.245.",
    "108.162.",
    "190.93.",
    "188.114.",
    "197.234.",
    "162.158.",
    "141.101.",
)


def _is_cdn_ip(server: str) -> bool:
    return any(server.startswith(p) for p in _CF_PREFIXES)


def _make_tls(
    sni: str, insecure: bool = True, fp: str = "chrome", alpn: list | None = None
) -> dict:
    t: dict = {
        "enabled": True,
        "server_name": sni,
        "insecure": insecure,
    }
    if fp:
        t["utls"] = {"enabled": True, "fingerprint": fp}
    if alpn:
        t["alpn"] = alpn
    return t


def _make_transport(
    raw: str, path: str, host: str, sni: str, service_name: str = ""
) -> dict | None:
    """Возвращает блок transport для sing-box или None если TCP."""
    raw = re.sub(r"[^a-z0-9]", "", raw.lower())
    if raw in ("tcp", "", "none"):
        return None
    if raw in ("ws", "websocket"):
        tr: dict = {"type": "ws", "path": path or "/"}
        # CDN-fronting: Host header = SNI если host не задан
        effective_host = host or sni
        if effective_host:
            tr["headers"] = {"Host": effective_host}
        return tr
    if raw == "httpupgrade":
        tr = {"type": "httpupgrade", "path": path or "/"}
        if host or sni:
            tr["host"] = host or sni
        return tr
    if raw in ("grpc", "gun"):
        sn = service_name or path.strip("/")
        tr = {"type": "grpc"}
        if sn:
            tr["service_name"] = sn
        return tr
    if raw in ("h2", "http"):
        tr: dict = {"type": "http", "path": path or "/"}
        if host:
            tr["host"] = [host]
        return tr
    # xhttp → ws fallback
    if raw == "xhttp":
        tr = {"type": "ws", "path": path or "/"}
        if host or sni:
            tr["headers"] = {"Host": host or sni}
        return tr
    return None


def parse_to_singbox(uri: str) -> dict | None:
    """Конвертирует VPN URI в sing-box outbound dict."""
    try:
        clean = uri.split("#")[0].strip()
        proto = clean.split("://")[0].lower()

        # ── VMess ──────────────────────────────────────────────────────
        if proto == "vmess":
            b64 = clean[8:]
            data = json.loads(
                base64.b64decode(pad_b64(b64)).decode("utf-8", errors="ignore")
            )
            server = data.get("add", "")
            port = int(data.get("port", 0))
            uuid = data.get("id", "")
            if not server or not port or not uuid:
                return None

            raw_net = (
                re.sub(r"[^a-z0-9]", "", str(data.get("net", "tcp")).lower()) or "tcp"
            )
            path_val = data.get("path", "/")
            host_val = data.get("host", "")
            sni = data.get("sni", "") or host_val
            fp = data.get("fp", "chrome") or "chrome"
            tls_enabled = data.get("tls", "") == "tls"
            svc_name = data.get("serviceName", "") or path_val

            out: dict = {
                "type": "vmess",
                "tag": "proxy",
                "server": server,
                "server_port": port,
                "uuid": uuid,
                "security": data.get("scy", "auto") or "auto",
                "alter_id": int(data.get("aid", 0)),
            }
            if tls_enabled:
                out["tls"] = _make_tls(sni, insecure=True, fp=fp)
            tr = _make_transport(raw_net, path_val, host_val, sni, svc_name)
            if tr:
                out["transport"] = tr
            return out

        # Общие поля для остальных протоколов
        p = urllib.parse.urlparse(clean)
        qs = _qs(p.query)
        server = p.hostname or ""
        port = p.port or 0
        if not server or not port:
            return None

        sec = qs.get("security", "").lower()
        sni = qs.get("sni", "") or qs.get("peer", "") or server
        fp = qs.get("fp", "chrome") or "chrome"
        raw_net = re.sub(r"[^a-z0-9]", "", qs.get("type", "tcp").lower()) or "tcp"
        path_val = urllib.parse.unquote(qs.get("path", "/"))
        host_val = qs.get("host", "")
        svc_name = qs.get("serviceName", "")

        # CDN-fronting: если host не задан, используем SNI
        effective_host = host_val or (sni if sni != server else "")

        # ── VLESS ──────────────────────────────────────────────────────
        if proto == "vless":
            uuid = p.username or ""
            if not uuid:
                return None

            out: dict = {
                "type": "vless",
                "tag": "proxy",
                "server": server,
                "server_port": port,
                "uuid": uuid,
            }

            flow = qs.get("flow", "").lower()
            if flow in ("xtls-rprx-vision", "xtls-rprx-visi"):
                out["flow"] = "xtls-rprx-vision"

            if sec in ("tls", "reality"):
                tls = _make_tls(sni, insecure=True, fp=fp)
                # Reality
                if sec == "reality":
                    pbk = qs.get("pbk", "")
                    if not pbk:
                        return None
                    tls["reality"] = {"enabled": True, "public_key": pbk}
                    sid = qs.get("sid", "")
                    if sid:
                        tls["reality"]["short_id"] = sid
                out["tls"] = tls

            tr = _make_transport(raw_net, path_val, effective_host, sni, svc_name)
            if tr:
                out["transport"] = tr
            return out

        # ── Trojan ─────────────────────────────────────────────────────
        if proto == "trojan":
            pw = urllib.parse.unquote(p.username or "")
            if not pw:
                return None
            out = {
                "type": "trojan",
                "tag": "proxy",
                "server": server,
                "server_port": port,
                "password": pw,
                "tls": _make_tls(sni, insecure=True, fp=fp),
            }
            tr = _make_transport(raw_net, path_val, effective_host, sni, svc_name)
            if tr:
                out["transport"] = tr
            return out

        # ── Shadowsocks ────────────────────────────────────────────────
        if proto == "ss":
            ui = p.username or ""
            method, password = "", ""
            try:
                decoded = base64.b64decode(pad_b64(ui)).decode("utf-8", errors="ignore")
                if ":" in decoded:
                    method, password = decoded.split(":", 1)
            except Exception:
                pass
            if not method and ":" in ui:
                method, password = ui.split(":", 1)
            method = method.lower().strip()
            if method == "chacha20-poly1305":
                method = "chacha20-ietf-poly1305"
            if method not in SS_ALLOWED:
                return None
            return {
                "type": "shadowsocks",
                "tag": "proxy",
                "server": server,
                "server_port": port,
                "method": method,
                "password": password,
            }

        # ── Hysteria2 ──────────────────────────────────────────────────
        if proto in ("hysteria2", "hy2"):
            pw = p.username or ""
            if not pw:
                return None
            out: dict = {
                "type": "hysteria2",
                "tag": "proxy",
                "server": server,
                "server_port": port,
                "password": pw,
                "tls": _make_tls(sni, insecure=True),
            }
            obfs = qs.get("obfs", "")
            if obfs and obfs != "none":
                out["obfs"] = {"type": obfs, "password": qs.get("obfs-password", "")}
            return out

        # ── TUIC v5 ────────────────────────────────────────────────────
        if proto == "tuic":
            uuid = p.username or ""
            raw_pass = urllib.parse.unquote(p.password or "")
            if not uuid:
                return None
            alpn_str = qs.get("alpn", "h3")
            alpn = [a.strip() for a in alpn_str.split(",") if a.strip()]
            tls = _make_tls(sni, insecure=True, fp="")
            tls["alpn"] = alpn
            return {
                "type": "tuic",
                "tag": "proxy",
                "server": server,
                "server_port": port,
                "uuid": uuid,
                "password": raw_pass,
                "congestion_control": qs.get("congestion_control", "bbr"),
                "udp_relay_mode": qs.get("udp_relay_mode", "native"),
                "tls": tls,
            }

    except Exception as e:
        proto_name = uri.split("://")[0].lower() if "://" in uri else "unknown"
        _fail(f"parse_exception({proto_name},{type(e).__name__})", uri)
    return None


def make_singbox_config(outbound: dict, socks_port: int) -> dict:
    """
    Конфиг sing-box: SOCKS5 inbound → proxy outbound.
    "Как человек" — весь трафик идёт через VPN.
    """
    return {
        "log": {"level": "error", "timestamp": False},
        "inbounds": [
            {
                "type": "socks",
                "tag": "socks-in",
                "listen": "127.0.0.1",
                "listen_port": socks_port,
            }
        ],
        "outbounds": [
            outbound,
            {"type": "direct", "tag": "direct"},
        ],
        "route": {
            "rules": [],
            "final": "proxy",
        },
    }


# ═══════════════════════════════════════════════════════════════════════════════
# ШАГ 5: Вспомогательные функции проверки
# ═══════════════════════════════════════════════════════════════════════════════


def wait_for_port(port: int, max_wait: float = 5.0) -> bool:
    deadline = time.time() + max_wait
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return True
        except Exception:
            pass
        time.sleep(0.05)
    return False


def _proxies(port: int) -> dict:
    return {
        "http": f"socks5h://127.0.0.1:{port}",
        "https": f"socks5h://127.0.0.1:{port}",
    }


# Код страны для преобразования ipinfo.io code → название
_COUNTRY_NAMES: dict[str, str] = {
    "RU": "Russia",
    "DE": "Germany",
    "US": "United States",
    "NL": "Netherlands",
    "FR": "France",
    "GB": "United Kingdom",
    "FI": "Finland",
    "SE": "Sweden",
    "CH": "Switzerland",
    "AT": "Austria",
    "PL": "Poland",
    "CZ": "Czech Republic",
    "UA": "Ukraine",
    "TR": "Turkey",
    "JP": "Japan",
    "SG": "Singapore",
    "HK": "Hong Kong",
    "CA": "Canada",
    "AU": "Australia",
    "NO": "Norway",
    "KR": "South Korea",
    "BR": "Brazil",
    "IN": "India",
    "CN": "China",
    "IR": "Iran",
    "IT": "Italy",
    "ES": "Spain",
    "PT": "Portugal",
    "RO": "Romania",
    "BG": "Bulgaria",
    "HU": "Hungary",
    "LT": "Lithuania",
    "LV": "Latvia",
    "EE": "Estonia",
    "BY": "Belarus",
    "MD": "Moldova",
    "AZ": "Azerbaijan",
    "GE": "Georgia",
    "KZ": "Kazakhstan",
    "UZ": "Uzbekistan",
    "AM": "Armenia",
    "TH": "Thailand",
    "VN": "Vietnam",
    "ID": "Indonesia",
    "MY": "Malaysia",
    "PH": "Philippines",
    "TW": "Taiwan",
    "IL": "Israel",
    "AE": "UAE",
    "SA": "Saudi Arabia",
    "EG": "Egypt",
    "ZA": "South Africa",
    "MX": "Mexico",
    "AR": "Argentina",
    "CL": "Chile",
    "CO": "Colombia",
}


class CheckInfo:
    """\u0420езультат одного запроса через прокси."""

    __slots__ = ("latency", "exit_ip", "country", "country_code", "isp")

    def __init__(
        self, latency: int, exit_ip: str, country: str, country_code: str, isp: str
    ):
        self.latency = latency
        self.exit_ip = exit_ip
        self.country = country
        self.country_code = country_code
        self.isp = isp


def check_via_info(port: int, timeout: int) -> CheckInfo | None:
    """
    Один запрос через SOCKS5 → latency + IP + страна + ISP.

    Как человек открывает 2ip.io под VPN — всё сразу:
      - загрузилась ли страница (подключение)
      - за сколько (латентность)
      - какой IP и страна (выходный IP VPN)

    Запросы идут ОТ VPN сервера к ip-api.com —
    каждый сервер свой IP → нет общего rate limit!
    """
    # Приоритет:
    #   1. ipinfo.io — нет строгих лимитов, быстрый JSON
    #   2. ip-api.com — больше полей, есть rate limit но безопасен т.к. запрос С VPN IP
    #   3. Fallback: generate_204 + без GeoIP
    _info_sources = [
        ("https://ipinfo.io/json", "ipinfo"),
        ("http://ip-api.com/json", "ipapi"),
    ]
    for url, kind in _info_sources:
        try:
            t = time.time()
            r = requests.get(
                url,
                proxies=_proxies(port),
                timeout=timeout,
                verify=False,
                headers={"User-Agent": "Mozilla/5.0"},
            )
            ms = max(1, int((time.time() - t) * 1000))
            if r.status_code >= 400:
                continue
            data = r.json()

            if kind == "ipinfo":
                ip = data.get("ip", "")
                code = data.get("country", "XX")[:2].upper()
                name = _COUNTRY_NAMES.get(code, code)
                isp = data.get("org", "")
                if ip:
                    return CheckInfo(ms, ip, name, code, isp)

            elif kind == "ipapi":
                if data.get("status") != "success":
                    continue
                ip = data.get("query", "")
                code = data.get("countryCode", "XX")
                name = data.get("country", _COUNTRY_NAMES.get(code, code))
                isp = data.get("org") or data.get("isp", "")
                if ip:
                    return CheckInfo(ms, ip, name, code, isp)

        except Exception:
            continue

    # Fallback: хотя бы проверить подключение (без GeoIP)
    for fallback_url in (
        "http://cp.cloudflare.com/generate_204",
        "https://www.google.com/generate_204",
    ):
        try:
            t = time.time()
            r = requests.get(
                fallback_url, proxies=_proxies(port), timeout=timeout, verify=False
            )
            ms = max(1, int((time.time() - t) * 1000))
            if r.status_code < 400:
                return CheckInfo(ms, "", "Unknown", "XX", "")
        except Exception:
            continue

    return None


_SPEED_URLS = [
    "https://speed.cloudflare.com/__down?bytes=5242880",
    "https://proof.ovh.net/files/10Mb.dat",
    "http://speedtest.tele2.net/10MB.zip",
    "https://speed.hetzner.de/10MB.bin",
]


def measure_speed(port: int) -> float:
    limit = int(CFG["speed_max_mb"] * 1024 * 1024)
    r_timeout = CFG["speed_timeout"]
    hdrs = {"User-Agent": "Mozilla/5.0", "Accept": "*/*"}
    for url in _SPEED_URLS:
        try:
            with requests.get(
                url,
                proxies=_proxies(port),
                headers=hdrs,
                stream=True,
                timeout=(5, r_timeout),
                verify=False,
            ) as r:
                if r.status_code >= 400:
                    continue
                t0, total = time.time(), 0
                for chunk in r.iter_content(65536):
                    if chunk:
                        total += len(chunk)
                    if total >= limit or time.time() - t0 >= r_timeout:
                        break
                elapsed = time.time() - t0
                if elapsed < 0.3 or total < 50_000:
                    continue
                return round(total * 8 / elapsed / 1_000_000, 2)
        except Exception:
            continue
    return 0.0


# ═══════════════════════════════════════════════════════════════════════════════
# ШАГ 6: Проверка одного ключа через sing-box
# ═══════════════════════════════════════════════════════════════════════════════


def check_one(uri: str, socks_port: int, test_url: str) -> dict | None:
    """
    Проверяет один ключ через sing-box.
    Эмулирует пользователя: запустил VPN → открыл сайт → смотрит IP.
    """
    outbound = parse_to_singbox(uri)
    if not outbound:
        proto = uri.split("://")[0].lower() if "://" in uri else "unknown"
        _fail(f"parse_fail({proto})", uri)
        return None

    cfg_path = TMP_DIR / f"sb_{socks_port}.json"
    config = make_singbox_config(outbound, socks_port)

    try:
        with open(cfg_path, "w", encoding="utf-8") as f:
            json.dump(config, f, ensure_ascii=False)
    except Exception:
        return None

    # Запускаем sing-box
    proc = subprocess.Popen(
        [str(get_singbox_path()), "run", "-c", str(cfg_path)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )

    # Дренируем stderr в фоне
    _stderr_buf: list[bytes] = []

    def _drain():
        try:
            data = proc.stderr.read() if proc.stderr else b""
            if data:
                _stderr_buf.append(data)
        except Exception:
            pass

    drain_t = _threading.Thread(target=_drain, daemon=True)
    drain_t.start()

    result = None
    try:
        # Ждём открытия SOCKS5 порта
        if not wait_for_port(socks_port, CFG["startup_timeout"]):
            if proc.poll() is not None:
                drain_t.join(timeout=1.0)
                err = (
                    b"".join(_stderr_buf).decode(errors="ignore").strip()[-150:]
                    or "no stderr"
                )
                _fail(f"proc_died: {err[:60]}", uri)
            else:
                _fail("port_timeout", uri)
            return None

        time.sleep(CFG["warmup_ms"] / 1000)
        if proc.poll() is not None:
            _fail("proc_died_after_warmup", uri)
            return None

        t = CFG["timeout"]

        # ── Один запрос — как человек открывает 2ip.io под VPN ──────────
        # Получаем всё сразу: latency + IP + страна + ISP
        info: CheckInfo | None = None
        for attempt in range(3):
            info = check_via_info(socks_port, t)
            if info is not None:
                break
            if attempt < 2:
                time.sleep(0.5)

        if info is None:
            _fail("no_response", uri)
            return None

        if CFG["max_ping_ms"] and info.latency > CFG["max_ping_ms"]:
            _fail(f"max_ping_exceeded({info.latency}>{CFG['max_ping_ms']})", uri)
            return None
        if info.latency < 5:
            _fail(f"ping_suspiciously_low({info.latency}ms)", uri)
            return None

        # Проверка IP leak
        if info.exit_ip and REAL_IP and info.exit_ip == REAL_IP:
            _fail("ip_leak", uri)
            return None

        # ── 3. Скорость (если включена) ───────────────────────────────
        speed_mbps = 0.0
        if CFG["check_speed"]:
            try:
                speed_mbps = measure_speed(socks_port)
            except Exception:
                pass
            if CFG["min_speed_mbps"] > 0 and speed_mbps < CFG["min_speed_mbps"]:
                _fail(f"speed_too_low({speed_mbps:.1f}<{CFG['min_speed_mbps']})", uri)
                return None

        result = {
            "uri": uri,
            "latency": info.latency,
            "exit_ip": info.exit_ip,
            "country": info.country,
            "country_code": info.country_code,
            "isp": info.isp,
            "speed_mbps": speed_mbps,
        }

    except Exception as e:
        _fail(f"exception({type(e).__name__})", uri)
    finally:
        try:
            proc.kill()
            proc.wait(timeout=2)
        except Exception:
            pass
        time.sleep(CFG["kill_delay"])
        try:
            cfg_path.unlink()
        except Exception:
            pass

    return result


# ═══════════════════════════════════════════════════════════════════════════════
# ШАГ 7: Параллельная проверка
# ═══════════════════════════════════════════════════════════════════════════════


def singbox_check_all(uris: list[str]) -> list[dict]:
    import threading

    total = len(uris)
    base_port = 20000
    workers = CFG["workers"]
    chunk_size = max(1, (total + workers - 1) // workers)
    all_results: list[dict] = []
    lock = threading.Lock()
    done_count = [0]

    print(f"🛡️  Sing-box проверка {total} ключей (workers={workers})...")

    def worker_thread(chunk: list[str], port_offset: int):
        for i, uri in enumerate(chunk):
            port = base_port + port_offset + i
            res = check_one(uri, port, CFG["test_url"])
            with lock:
                done_count[0] += 1
                if res:
                    all_results.append(res)
                d = done_count[0]
                print(
                    f"\r   {d}/{total} проверено | рабочих: {len(all_results)}",
                    end="",
                    flush=True,
                )
                if d % 100 == 0:
                    all_f = sorted(FAIL_STATS.items(), key=lambda x: -x[1])
                    fs = " | ".join(f"{r}:{c}" for r, c in all_f) or "none"
                    print(
                        f"\n  [стат @{d}] рабочих:{len(all_results)} фейлов:{sum(c for _, c in all_f)}\n  {fs}",
                        flush=True,
                    )

    threads = []
    for t_idx in range(workers):
        start = t_idx * chunk_size
        chunk = uris[start : start + chunk_size]
        if not chunk:
            break
        t = threading.Thread(target=worker_thread, args=(chunk, start), daemon=True)
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    print(f"\n✅ Рабочих ключей: {len(all_results)}/{total}")
    print_fail_stats()
    return all_results


# ═══════════════════════════════════════════════════════════════════════════════
# ШАГ 8: GeoIP пакетный
# ═══════════════════════════════════════════════════════════════════════════════

_geo_cache: dict[str, dict] = {}


def geoip_batch(ips: list[str]) -> dict[str, dict]:
    unique = [ip for ip in {ip for ip in ips if ip} if ip not in _geo_cache]
    if not unique:
        return _geo_cache
    print(f"🌍 GeoIP для {len(unique)} IP (batch)...")
    fields = "status,country,countryCode,city,isp,org"
    for i in range(0, len(unique), 100):
        chunk = unique[i : i + 100]
        try:
            r = requests.post(
                "http://ip-api.com/batch",
                json=[{"query": ip, "fields": fields} for ip in chunk],
                timeout=10,
            )
            data = r.json()
            if isinstance(data, list):
                for j, item in enumerate(data):
                    ip = chunk[j]
                    _geo_cache[ip] = item if item.get("status") == "success" else {}
        except Exception:
            for ip in chunk:
                _geo_cache.setdefault(ip, {})
        if i + 100 < len(unique):
            time.sleep(1.5)
    return _geo_cache


# ═══════════════════════════════════════════════════════════════════════════════
# ШАГ 9: Сохранение результатов
# ═══════════════════════════════════════════════════════════════════════════════


def _sub_header(title: str) -> str:
    encoded = base64.b64encode(title.encode("utf-8")).decode()
    return (
        "#profile-update-interval: 3\n"
        f"#profile-title: encode:{encoded}\n"
        "#subscription-userinfo: upload=0; download=0; total=107374182400; expire=1893456000\n"
    )


def rename_key(
    uri: str, country: str, country_code: str, provider: str, num: int
) -> str:
    flag = country_flag(country_code)
    prov = shorten_provider(provider)
    tag = f"{flag} {country} | {prov} {num}" if prov else f"{flag} {country} {num}"
    return f"{uri.split('#')[0].rstrip()}#{tag}"


def save_results(working: list[dict]):
    if not working:
        print("⚠️  Нет рабочих ключей для сохранения")
        return

    # GeoIP для всех exit IP
    ips = [r["exit_ip"] for r in working if r.get("exit_ip")]
    geo_data = geoip_batch(ips)

    COUNTRY_PRIORITY = {
        "RU": 1,
        "FI": 2,
        "DE": 3,
        "NL": 4,
        "FR": 5,
        "GB": 6,
        "SE": 7,
        "NO": 8,
        "CH": 9,
        "AT": 10,
        "PL": 11,
        "US": 12,
        "CA": 13,
        "JP": 14,
        "SG": 15,
        "HK": 16,
        "TR": 17,
        "UA": 18,
    }

    counters: dict[tuple, int] = defaultdict(int)
    enriched = []
    for r in working:
        geo = _geo_cache.get(r.get("exit_ip", ""), {})
        if not geo:
            host, _ = get_host_port(r["uri"])
            geo = geoip_batch([host]).get(host, {}) if host else {}

        country = r.get("country") or geo.get("country", "Unknown")
        country_code = geo.get("countryCode", "XX")
        org = geo.get("org", "") or geo.get("isp", "") or r.get("isp", "")

        key = (country_code, shorten_provider(org))
        counters[key] += 1
        final_uri = rename_key(r["uri"], country, country_code, org, counters[key])

        enriched.append(
            {
                **r,
                "country": country,
                "country_code": country_code,
                "provider": shorten_provider(org),
                "final_uri": final_uri,
            }
        )

    enriched.sort(
        key=lambda r: (
            COUNTRY_PRIORITY.get(r["country_code"], 999),
            r["country_code"],
            r["latency"],
        )
    )

    # ── all_working.txt ────────────────────────────────────────────────
    all_keys = [r["final_uri"] for r in enriched]
    (RESULTS / "all_working.txt").write_text("\n".join(all_keys), encoding="utf-8")

    header = _sub_header("BobiVPN ✅ All Countries")
    content = header + "\n".join(all_keys)
    (RESULTS / "all_working_sub.txt").write_text(
        base64.b64encode(content.encode()).decode(), encoding="utf-8"
    )

    # ── countries/ ────────────────────────────────────────────────────
    by_country: dict[str, list] = defaultdict(list)
    for r in enriched:
        by_country[r["country_code"]].append(r)

    for f in COUNTRIES.glob("*.txt"):
        f.unlink()
    for code, items in by_country.items():
        name = items[0]["country"]
        flag = country_flag(code)
        keys = [r["final_uri"] for r in sorted(items, key=lambda x: x["latency"])]
        hdr = _sub_header(f"BobiVPN {flag} {name}")
        (COUNTRIES / f"{code}.txt").write_text(hdr + "\n".join(keys), encoding="utf-8")

    # ── top_200.txt ───────────────────────────────────────────────────
    has_speed = any(r.get("speed_mbps", 0) > 0 for r in enriched)
    top = sorted(
        enriched, key=lambda x: -x.get("speed_mbps", 0) if has_speed else x["latency"]
    )[:200]
    top_hdr = _sub_header("BobiVPN 🚀 Top 200 Fastest")
    (RESULTS / "top_200.txt").write_text(
        top_hdr + "\n".join(r["final_uri"] for r in top), encoding="utf-8"
    )

    # ── stats.json ────────────────────────────────────────────────────
    latencies = [r["latency"] for r in enriched]
    speeds = [r["speed_mbps"] for r in enriched if r.get("speed_mbps", 0) > 0]
    stats = {
        "checked_at": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "total_working": len(enriched),
        "avg_latency_ms": round(sum(latencies) / len(latencies), 1) if latencies else 0,
        "min_latency_ms": min(latencies) if latencies else 0,
        "avg_speed_mbps": round(sum(speeds) / len(speeds), 2) if speeds else 0,
        "speed_checked": has_speed,
        "countries": {
            k: {
                "count": len(v),
                "avg_ping_ms": round(sum(r["latency"] for r in v) / len(v), 1),
            }
            for k, v in sorted(by_country.items())
        },
    }
    (RESULTS / "stats.json").write_text(
        json.dumps(stats, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    print(f"\n💾 Результаты сохранены:")
    print(f"   all_working.txt     — {len(all_keys)} ключей")
    print(f"   all_working_sub.txt — base64 подписка")
    print(f"   countries/          — {len(by_country)} стран")
    for code, items in sorted(by_country.items(), key=lambda x: -len(x[1])):
        print(f"     {country_flag(code)} {code}: {len(items)}")


# ═══════════════════════════════════════════════════════════════════════════════
# SELF-TEST
# ═══════════════════════════════════════════════════════════════════════════════


def self_test():
    print("\n[Self-test]")
    ok = True

    try:
        import socks  # noqa

        print("  [OK] PySocks installed")
    except ImportError:
        print("  [FAIL] PySocks NOT installed — pip install PySocks")
        ok = False

    try:
        import requests as _req

        _req.get(
            "http://1.1.1.1/", proxies={"http": "socks5://127.0.0.1:1"}, timeout=0.5
        )
    except _req.exceptions.InvalidSchema:
        print("  [FAIL] requests SOCKS5 not working — pip install PySocks")
        ok = False
    except Exception:
        print("  [OK] requests SOCKS5 support works")

    sb = get_singbox_path()
    if sb.exists():
        print(f"  [OK] sing-box found: {sb}")
        try:
            r = subprocess.run([str(sb), "version"], capture_output=True, timeout=3)
            ver = (
                (r.stdout or r.stderr or b"")
                .decode(errors="ignore")
                .strip()
                .split("\n")[0]
            )
            print(f"       Version: {ver}")
        except Exception as e:
            print(f"  [WARN] Cannot run sing-box version: {e}")
    else:
        print(f"  [FAIL] sing-box NOT found: {sb}")
        ok = False

    # Тест парсера
    test_vless = "vless://12345678-1234-1234-1234-123456789abc@1.2.3.4:443?security=reality&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=&type=tcp&flow=xtls-rprx-vision#test"
    parsed = parse_to_singbox(test_vless)
    if parsed:
        print(
            f"  [OK] Parser works: {parsed.get('type')} server={parsed.get('server')}"
        )
    else:
        print("  [FAIL] Parser returned None for test VLESS URI")
        ok = False

    if not ok:
        sys.exit("\n[ABORT] Self-test failed.")
    print("  All checks passed!\n")


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════════


def parse_args():
    ap = argparse.ArgumentParser(description="VpnSingboxCheker")
    ap.add_argument("--timeout", type=int, default=5)
    ap.add_argument("--tcp-timeout", type=float, default=2.0)
    ap.add_argument("--tcp-workers", type=int, default=300)
    ap.add_argument("--workers", type=int, default=50)
    ap.add_argument("--warmup", type=int, default=300)
    ap.add_argument("--max-ping", type=int, default=0)
    ap.add_argument(
        "--test-url", type=str, default="http://cp.cloudflare.com/generate_204"
    )
    ap.add_argument("--skip-tcp", action="store_true")
    ap.add_argument("--speed", action="store_true")
    ap.add_argument("--min-speed", type=float, default=0.0)
    ap.add_argument("--speed-max-mb", type=float, default=5.0)
    ap.add_argument("--no-install", action="store_true")
    return ap.parse_args()


def detect_real_ip() -> str:
    for url in ("https://api.ipify.org", "https://icanhazip.com"):
        try:
            r = requests.get(url, timeout=8, verify=False)
            ip = r.text.strip()
            if ip and len(ip) < 50:
                return ip
        except Exception:
            pass
    return ""


def main():
    args = parse_args()
    CFG.update(
        {
            "test_url": args.test_url,
            "timeout": args.timeout,
            "tcp_timeout": args.tcp_timeout,
            "tcp_workers": args.tcp_workers,
            "workers": args.workers,
            "warmup_ms": args.warmup,
            "max_ping_ms": args.max_ping,
            "check_speed": args.speed,
            "min_speed_mbps": args.min_speed,
            "speed_max_mb": args.speed_max_mb,
        }
    )

    print("=" * 60)
    print("  VpnSingboxCheker")
    print("=" * 60)

    # Установка sing-box
    if not args.no_install and not is_singbox_installed():
        install_singbox()
    elif not is_singbox_installed():
        sys.exit(f"❌ sing-box не найден: {get_singbox_path()}")

    # Реальный IP
    global REAL_IP
    print("\n🔍 Определяю реальный IP...")
    REAL_IP = detect_real_ip()
    if REAL_IP:
        print(f"   Реальный IP: {REAL_IP} (будет детектироваться IP leak)")
    else:
        print("   ⚠️  Не удалось определить — IP leak проверка отключена")

    self_test()

    # Шаг 1: Сбор
    urls = load_subscription_urls()
    raw_keys = fetch_all_keys(urls)
    if not raw_keys:
        sys.exit("❌ Не удалось собрать ключи")

    # Шаг 2: Дедупликация
    unique = deduplicate(raw_keys)

    # Шаг 3: TCP фильтр
    reachable = unique if args.skip_tcp else tcp_filter(unique)
    if not reachable:
        sys.exit("❌ После TCP фильтра не осталось ключей")

    # Шаг 4: Проверка
    working = singbox_check_all(reachable)
    if not working:
        print("⚠️  Рабочих ключей не найдено")
        return

    # Шаги 5-6: GeoIP + сохранение
    save_results(working)
    print("\n✅ Готово!")


if __name__ == "__main__":
    main()
