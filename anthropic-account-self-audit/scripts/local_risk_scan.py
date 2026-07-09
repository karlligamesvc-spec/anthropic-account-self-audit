#!/usr/bin/env python3
"""Local Claude Code / Anthropic account-risk scanner.

The script is intentionally low-intrusion: it reports names, paths, counts,
permissions, and secret-shape hints, but never prints secret values. Scope is
Claude Code only; Claude Desktop/App caches and generic Claude CLI locations are
not scanned unless this script is later extended explicitly.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import locale
import os
from pathlib import Path
import plistlib
import platform
import re
import shutil
import stat
import subprocess
import sys
import time
import urllib.request


ANTHROPIC_KEY_RE = re.compile(rb"sk-ant-api\d+-[A-Za-z0-9_-]{20,}")
GENERIC_SK_RE = re.compile(rb"\bsk-[A-Za-z0-9_-]{20,}")
ANTHROPIC_ENV_RE = re.compile(
    rb"\b(ANTHROPIC_API_KEY|ANTHROPIC_AUTH_TOKEN|CLAUDE_API_KEY)\b"
)
PROXY_RE = re.compile(rb"\b(HTTP_PROXY|HTTPS_PROXY|ALL_PROXY|SOCKS|proxy)\b", re.I)
MIXED_PROVIDER_RE = re.compile(
    rb"ANTHROPIC_[A-Z0-9_]*(BASE_URL|MODEL|AUTH_TOKEN)[^\n\r]*(deepseek|openrouter|openai|localhost|127\.0\.0\.1)",
    re.I,
)
BROWSER_SPOOFING_RE = re.compile(
    rb"Emulation\.set(Timezone|Locale|Geolocation)Override|Network\.setUserAgentOverride|chrome\.debugger",
    re.I,
)
BROWSER_ENV_PATCH_RE = re.compile(
    rb"navigator\.geolocation|navigator\.permissions\.query|Date\.prototype\.getTimezoneOffset|Intl\.DateTimeFormat|Intl\.NumberFormat|Intl\.Collator|navigator\.language|navigator\.languages|declarativeNetRequest|Accept-Language|data-geomirror|font-mask",
    re.I,
)
GEOTIME_STORAGE_RE = re.compile(rb"\b(targetTimezone|isActive)\b")
GEOMIRROR_STORAGE_RE = re.compile(
    rb"\b(tzEnabled|langEnabled|fontEnabled|acceptLanguage|ipTimezone|ipLocale|overrideLat|overrideLon|data-geomirror)\b",
    re.I,
)
CLAUDE_CODE_INSTALL_PATTERNS = [
    (
        "today_date_prompt",
        "Claude Code system prompt date text",
        [
            b"Today's date",
            "Today\u2019s date".encode("utf-8"),
            "Today\u02bcs date".encode("utf-8"),
            "Today\uff07s date".encode("utf-8"),
        ],
    ),
    (
        "cn_timezone_ids",
        "China timezone identifiers",
        [b"Asia/Shanghai", b"Asia/Urumqi"],
    ),
    (
        "anthropic_base_url_env",
        "ANTHROPIC_BASE_URL environment variable",
        [b"ANTHROPIC_BASE_URL"],
    ),
    (
        "official_api_hosts",
        "official Anthropic API host strings",
        [b"api.anthropic.com", b"https://api.anthropic.com"],
    ),
    (
        "domain_check_endpoint",
        "domain checking or blocklist endpoint strings",
        [
            b"domain_info?domain=",
            b"Domain blocklist check",
            b"is not a first-party Anthropic host",
        ],
    ),
    (
        "region_marker_labels",
        "short region-classifier label strings",
        [b"cnTZ", b"labKw"],
    ),
    (
        "base64_decode_hints",
        "base64 decode string hints",
        [b"base64", b"atob", b"Buffer.from"],
    ),
    (
        "xor_91_literal_hints",
        "literal XOR-91 implementation hints",
        [b"^91", b"^ 91", b"0x5b", b"0X5B"],
    ),
]

TIMEZONE_COUNTRY_HINTS = {
    "America/New_York": "US",
    "America/Chicago": "US",
    "America/Denver": "US",
    "America/Los_Angeles": "US",
    "America/Toronto": "CA",
    "America/Vancouver": "CA",
    "America/Mexico_City": "MX",
    "America/Sao_Paulo": "BR",
    "America/Buenos_Aires": "AR",
    "America/Bogota": "CO",
    "Europe/London": "GB",
    "Europe/Paris": "FR",
    "Europe/Berlin": "DE",
    "Europe/Madrid": "ES",
    "Europe/Rome": "IT",
    "Europe/Amsterdam": "NL",
    "Europe/Stockholm": "SE",
    "Europe/Moscow": "RU",
    "Europe/Istanbul": "TR",
    "Europe/Kyiv": "UA",
    "Europe/Warsaw": "PL",
    "Asia/Dubai": "AE",
    "Asia/Riyadh": "SA",
    "Asia/Tehran": "IR",
    "Asia/Mumbai": "IN",
    "Asia/Bangkok": "TH",
    "Asia/Jakarta": "ID",
    "Asia/Singapore": "SG",
    "Asia/Tokyo": "JP",
    "Asia/Seoul": "KR",
    "Asia/Shanghai": "CN",
    "Asia/Hong_Kong": "HK",
    "Australia/Sydney": "AU",
    "Australia/Melbourne": "AU",
    "Pacific/Auckland": "NZ",
    "Africa/Cairo": "EG",
    "Africa/Lagos": "NG",
    "Africa/Johannesburg": "ZA",
}

WINDOWS_TZ_TO_IANA = {
    "Pacific Standard Time": "America/Los_Angeles",
    "Mountain Standard Time": "America/Denver",
    "Central Standard Time": "America/Chicago",
    "Eastern Standard Time": "America/New_York",
    "Canada Central Standard Time": "America/Winnipeg",
    "GMT Standard Time": "Europe/London",
    "W. Europe Standard Time": "Europe/Berlin",
    "Romance Standard Time": "Europe/Paris",
    "China Standard Time": "Asia/Shanghai",
    "Singapore Standard Time": "Asia/Singapore",
    "Tokyo Standard Time": "Asia/Tokyo",
    "Korea Standard Time": "Asia/Seoul",
    "India Standard Time": "Asia/Kolkata",
    "AUS Eastern Standard Time": "Australia/Sydney",
    "New Zealand Standard Time": "Pacific/Auckland",
}

SKIP_DIRS = {
    ".git",
    "node_modules",
    "dist",
    "build",
    ".next",
    "target",
    "vendor",
    "plugins",
    "telemetry",
    "cache",
    "Cache",
    "GPUCache",
    "DawnGraphiteCache",
    "DawnWebGPUCache",
}


def run(cmd: list[str], timeout: int = 5) -> str:
    try:
        result = subprocess.run(
            cmd,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=timeout,
        )
    except Exception:
        return ""
    return result.stdout.strip()


def mode_string(path: Path) -> str:
    try:
        return stat.filemode(path.stat().st_mode)
    except OSError:
        return "unknown"


def is_group_or_other_readable(path: Path) -> bool:
    try:
        mode = path.stat().st_mode
    except OSError:
        return False
    return bool(mode & (stat.S_IRGRP | stat.S_IROTH))


def iter_files(root: Path, max_files: int = 1500, max_size: int = 2_000_000):
    seen = 0
    if not root.exists():
        return
    if root.is_file():
        try:
            if root.stat().st_size <= max_size:
                yield root
        except OSError:
            return
        return
    for current, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for name in files:
            if seen >= max_files:
                return
            path = Path(current) / name
            try:
                if path.stat().st_size > max_size:
                    continue
            except OSError:
                continue
            seen += 1
            yield path


def read_bytes(path: Path) -> bytes:
    try:
        return path.read_bytes()
    except Exception:
        return b""


def env_scan() -> dict:
    items = []
    for key in sorted(os.environ):
        if not re.search(r"(ANTHROPIC|CLAUDE|API_KEY|AUTH_TOKEN|ACCESS_TOKEN|PROXY)", key, re.I):
            continue
        value = os.environ.get(key, "")
        hints = []
        if re.search(r"ANTHROPIC|CLAUDE", key, re.I):
            hints.append("anthropic_related")
        if re.search(r"PROXY", key, re.I) and value:
            hints.append("proxy_set")
        if re.search(r"KEY|TOKEN", key, re.I) and value:
            hints.append(f"value_present_len_{len(value)}")
        if re.search(r"sk-ant-api\d+-", value):
            hints.append("anthropic_key_shape")
        elif re.search(r"\bsk-[A-Za-z0-9_-]{20,}", value):
            hints.append("generic_sk_shape")
        items.append({"name": key, "hints": hints or ["present"]})
    return {"matches": items, "count": len(items)}


def project_slug(cwd: Path) -> str:
    return str(cwd).replace("/", "-")


def config_scan(cwd: Path, home: Path) -> dict:
    paths = [
        home / ".claude",
        home / ".claude.json",
        home / ".claude" / "settings.json",
        home / ".claude" / "settings.local.json",
        home / ".claude" / "projects" / project_slug(cwd),
        home / ".claude" / "session-env",
        home / ".claude" / "tasks",
        home / ".claude" / "shell-snapshots",
        cwd / ".claude" / "settings.json",
        cwd / ".claude" / "settings.local.json",
    ]
    found = []
    loose = []
    for path in paths:
        if not path.exists():
            continue
        entry = {
            "path": str(path),
            "type": "dir" if path.is_dir() else "file",
            "mode": mode_string(path),
        }
        found.append(entry)
        if is_group_or_other_readable(path):
            loose.append(entry)

    sensitive_files = []
    for path in [
        home / ".claude.json",
        home / ".claude" / "settings.json",
        home / ".claude" / "settings.local.json",
        cwd / ".claude" / "settings.json",
        cwd / ".claude" / "settings.local.json",
    ]:
        if path.exists():
            sensitive_files.append(
                {
                    "path": str(path),
                    "mode": mode_string(path),
                    "group_or_other_readable": is_group_or_other_readable(path),
                }
            )

    return {"found": found, "loose_paths": loose, "sensitive_files": sensitive_files}


def secret_scan(cwd: Path, home: Path) -> dict:
    targets = [
        cwd,
        home / ".claude.json",
        home / ".claude" / "settings.json",
        home / ".claude" / "settings.local.json",
        home / ".claude" / "history.jsonl",
        home / ".claude" / "shell-snapshots",
        home / ".claude" / "projects" / project_slug(cwd),
        home / ".claude" / "session-env",
        home / ".claude" / "tasks",
        home / ".claude" / "deepseek.env",
        home / ".claude" / "deepseek.env.save",
        cwd / ".claude",
    ]
    summary = {
        "targets": [str(t) for t in targets if t.exists()],
        "anthropic_key_shape_files": [],
        "generic_sk_shape_files": [],
        "anthropic_env_name_files": [],
        "proxy_text_files": [],
        "mixed_provider_files": [],
        "files_scanned": 0,
    }
    for target in targets:
        for path in iter_files(target):
            data = read_bytes(path)
            if not data:
                continue
            summary["files_scanned"] += 1
            path_str = str(path)
            if ANTHROPIC_KEY_RE.search(data):
                summary["anthropic_key_shape_files"].append(path_str)
            elif GENERIC_SK_RE.search(data):
                summary["generic_sk_shape_files"].append(path_str)
            if ANTHROPIC_ENV_RE.search(data):
                summary["anthropic_env_name_files"].append(path_str)
            if PROXY_RE.search(data):
                summary["proxy_text_files"].append(path_str)
            if MIXED_PROVIDER_RE.search(data):
                summary["mixed_provider_files"].append(path_str)
    for key in list(summary):
        if key.endswith("_files"):
            summary[key] = sorted(set(summary[key]))[:50]
    return summary


def claude_code_root_from_path(path: Path) -> Path | None:
    try:
        resolved = path.expanduser().resolve()
    except OSError:
        resolved = path.expanduser()
    for candidate in [resolved, *resolved.parents]:
        if (
            candidate.name == "claude-code"
            and candidate.parent.name == "@anthropic-ai"
        ):
            return candidate
    return None


def claude_code_candidate_roots(home: Path) -> tuple[list[str], list[Path]]:
    binaries = []
    roots: set[Path] = set()

    binary = shutil.which("claude")
    if binary:
        binary_path = Path(binary)
        binaries.append(str(binary_path))
        root = claude_code_root_from_path(binary_path)
        if root:
            roots.add(root)

    npm_root = run(["npm", "root", "-g"], timeout=3)
    global_roots = [
        Path(npm_root) if npm_root else None,
        home / ".local" / "lib" / "node_modules",
        home / ".npm-global" / "lib" / "node_modules",
        Path("/opt/homebrew/lib/node_modules"),
        Path("/usr/local/lib/node_modules"),
    ]
    for node_modules in global_roots:
        if not node_modules:
            continue
        root = node_modules / "@anthropic-ai" / "claude-code"
        if root.exists():
            roots.add(root)

    for root in home.glob(".nvm/versions/node/*/lib/node_modules/@anthropic-ai/claude-code"):
        if root.exists():
            roots.add(root)

    return binaries, sorted(roots)


def claude_code_package_info(root: Path) -> dict:
    data = load_json(root / "package.json") or {}
    return {
        "name": data.get("name"),
        "version": data.get("version"),
        "homepage": data.get("homepage"),
    }


def sha256_prefix(path: Path, limit_bytes: int = 64 * 1024 * 1024) -> str | None:
    try:
        digest = hashlib.sha256()
        read_total = 0
        with path.open("rb") as handle:
            while read_total < limit_bytes:
                chunk = handle.read(min(1024 * 1024, limit_bytes - read_total))
                if not chunk:
                    break
                digest.update(chunk)
                read_total += len(chunk)
    except OSError:
        return None
    return digest.hexdigest()[:16]


def claude_code_scan_files(root: Path) -> list[Path]:
    files = []
    for relative in [
        "package.json",
        "cli-wrapper.cjs",
        "install.cjs",
        "bin/claude",
        "bin/claude.exe",
    ]:
        path = root / relative
        if path.exists() and path.is_file():
            files.append(path)

    platform_root = root / "node_modules" / "@anthropic-ai"
    if platform_root.exists():
        for package in platform_root.glob("claude-code-*"):
            for name in ["package.json", "claude", "claude.exe"]:
                path = package / name
                if path.exists() and path.is_file():
                    files.append(path)

    return sorted(set(files))


def scan_file_for_patterns(path: Path) -> dict:
    hits = {
        label: {"description": description, "count": 0, "offsets": []}
        for label, description, _ in CLAUDE_CODE_INSTALL_PATTERNS
    }
    seen_offsets = {label: set() for label, _, _ in CLAUDE_CODE_INSTALL_PATTERNS}
    max_pattern_len = max(
        len(pattern)
        for _, _, patterns in CLAUDE_CODE_INSTALL_PATTERNS
        for pattern in patterns
    )
    try:
        offset = 0
        tail = b""
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                data = tail + chunk
                data_base_offset = offset - len(tail)
                for label, _, patterns in CLAUDE_CODE_INSTALL_PATTERNS:
                    for pattern in patterns:
                        start = 0
                        while True:
                            index = data.find(pattern, start)
                            if index == -1:
                                break
                            absolute = data_base_offset + index
                            if absolute not in seen_offsets[label]:
                                seen_offsets[label].add(absolute)
                                hits[label]["count"] += 1
                                if len(hits[label]["offsets"]) < 5:
                                    hits[label]["offsets"].append(absolute)
                            start = index + 1
                offset += len(chunk)
                tail = data[-(max_pattern_len - 1) :]
    except OSError:
        return {}

    return {label: value for label, value in hits.items() if value["count"]}


def claude_code_install_scan(home: Path) -> dict:
    binaries, roots = claude_code_candidate_roots(home)
    packages = []
    for root in roots:
        package = {
            "root": str(root),
            **claude_code_package_info(root),
            "files_scanned": 0,
            "matched_files": [],
        }
        for path in claude_code_scan_files(root):
            hits = scan_file_for_patterns(path)
            package["files_scanned"] += 1
            if not hits:
                continue
            try:
                size = path.stat().st_size
            except OSError:
                size = None
            package["matched_files"].append(
                {
                    "path": str(path),
                    "size": size,
                    "sha256_prefix_64mb": sha256_prefix(path),
                    "hits": hits,
                }
            )
        packages.append(package)

    return {
        "checked": True,
        "claude_binaries": binaries,
        "packages": packages,
        "note": "Reports package paths and pattern names only; it does not prove server-side use or intent.",
    }


def proxy_scan() -> dict:
    result = {"env_proxy_names": [], "system_proxy_enabled": None, "details": []}
    for key in sorted(os.environ):
        if re.match(r"(?i)^(http|https|all)_proxy$", key):
            result["env_proxy_names"].append(key)
    system = platform.system()
    if system == "Darwin":
        output = run(["scutil", "--proxy"])
        enabled_lines = []
        for line in output.splitlines():
            if re.search(r"(HTTPEnable|HTTPSEnable|SOCKSEnable|ProxyAutoConfigEnable|ProxyAutoDiscoveryEnable)\s*:\s*1", line):
                enabled_lines.append(line.strip())
        result["system_proxy_enabled"] = bool(enabled_lines)
        result["details"] = enabled_lines
    elif system == "Windows":
        output = run(["netsh", "winhttp", "show", "proxy"])
        if output:
            direct = "Direct access" in output or "direct access" in output.lower()
            result["system_proxy_enabled"] = not direct
            result["details"] = output.splitlines()[:12]
    return result


def network_scan(enabled: bool) -> dict:
    if not enabled:
        return {"checked": False}
    try:
        with urllib.request.urlopen("https://ipinfo.io/json", timeout=8) as response:
            data = json.load(response)
    except Exception as exc:
        return {"checked": True, "error": type(exc).__name__}
    org = str(data.get("org", ""))
    cloud_hint = any(
        token in org.lower()
        for token in [
            "cloud",
            "hosting",
            "data",
            "amazon",
            "google",
            "microsoft",
            "digitalocean",
            "ovh",
            "vultr",
            "linode",
            "oracle",
        ]
    )
    return {
        "checked": True,
        "country": data.get("country"),
        "region": data.get("region"),
        "city": data.get("city"),
        "org_type_hint": "cloud_or_datacenter" if cloud_hint else "residential_or_unknown",
    }


def local_signals() -> dict:
    return {
        "platform": platform.platform(),
        "locale": locale.getlocale(),
        "date_timezone": run(["date", "+%Z %z"]),
        "iana_timezone": iana_timezone(),
    }


def iana_timezone() -> str | None:
    tz_env = os.environ.get("TZ")
    if tz_env and "/" in tz_env:
        return tz_env
    if platform.system() == "Windows":
        windows_tz = run(["tzutil", "/g"])
        if windows_tz:
            return WINDOWS_TZ_TO_IANA.get(windows_tz, windows_tz)
    for path in [Path("/etc/localtime"), Path("/var/db/timezone/localtime")]:
        try:
            resolved = os.readlink(path)
        except OSError:
            continue
        marker = "zoneinfo/"
        if marker in resolved:
            return resolved.split(marker, 1)[1]
    timedatectl = run(["timedatectl", "show", "-p", "Timezone", "--value"])
    if timedatectl and "/" in timedatectl:
        return timedatectl
    systemsetup = run(["systemsetup", "-gettimezone"])
    if "Time Zone:" in systemsetup:
        return systemsetup.split("Time Zone:", 1)[1].strip()
    return None


def language_region(language: str | None) -> str | None:
    if not language:
        return None
    for tag in re.split(r"\s*,\s*", language):
        parts = re.split(r"[-_]", tag.strip())
        for part in reversed(parts):
            if re.fullmatch(r"[A-Za-z]{2}", part):
                upper = part.upper()
                if upper not in {"EN", "ZH", "FR", "JA", "RU", "VI"}:
                    return upper
    return None


def parse_apple_languages(output: str) -> list[str]:
    if not output:
        return []
    quoted = re.findall(r'"([^"]+)"', output)
    if quoted:
        return quoted
    tokens = []
    for line in output.splitlines():
        line = line.strip().strip(",")
        if re.fullmatch(r"[A-Za-z]{2,3}(?:[-_][A-Za-z0-9]+){0,3}", line):
            tokens.append(line)
    return tokens


def plist_apple_languages(path: Path) -> list[str]:
    try:
        with path.open("rb") as handle:
            data = plistlib.load(handle)
    except Exception:
        return []
    languages = data.get("AppleLanguages")
    if isinstance(languages, list):
        return [str(item) for item in languages if item]
    if isinstance(languages, str):
        return [languages]
    return []


def macos_app_languages(bundle_id: str, home: Path | None = None) -> list[str]:
    output = run(["defaults", "read", bundle_id, "AppleLanguages"])
    languages = parse_apple_languages(output)
    if languages:
        return languages
    if not home:
        return []
    for path in [
        home / "Library" / "Preferences" / f"{bundle_id}.plist",
        home / "Library" / "Containers" / bundle_id / "Data" / "Library" / "Preferences" / f"{bundle_id}.plist",
    ]:
        languages = plist_apple_languages(path)
        if languages:
            return languages
    return []


def chrome_profile_roots(home: Path) -> list[tuple[str, Path]]:
    system = platform.system()
    if system == "Darwin":
        candidates = [
            ("Chrome", home / "Library" / "Application Support" / "Google" / "Chrome"),
            ("Chromium", home / "Library" / "Application Support" / "Chromium"),
            ("Brave", home / "Library" / "Application Support" / "BraveSoftware" / "Brave-Browser"),
            ("Edge", home / "Library" / "Application Support" / "Microsoft Edge"),
            ("Arc", home / "Library" / "Application Support" / "Arc" / "User Data"),
            ("360Chrome", home / "Library" / "Application Support" / "360Chrome"),
            ("360Browser", home / "Library" / "Application Support" / "360Safe Browser"),
        ]
    elif system == "Windows":
        local_app_data = Path(os.environ.get("LOCALAPPDATA", str(home / "AppData" / "Local")))
        app_data = Path(os.environ.get("APPDATA", str(home / "AppData" / "Roaming")))
        candidates = [
            ("Chrome", local_app_data / "Google" / "Chrome" / "User Data"),
            ("Chromium", local_app_data / "Chromium" / "User Data"),
            ("Brave", local_app_data / "BraveSoftware" / "Brave-Browser" / "User Data"),
            ("Edge", local_app_data / "Microsoft" / "Edge" / "User Data"),
            ("Arc", app_data / "Arc" / "User Data"),
            ("360Chrome", local_app_data / "360Chrome" / "Chrome" / "User Data"),
            ("360Chrome", app_data / "360Chrome" / "Chrome" / "User Data"),
            ("360Browser", local_app_data / "360se6" / "User Data"),
            ("360Browser", app_data / "360se6" / "User Data"),
            ("360BrowserX", local_app_data / "360ChromeX" / "Chrome" / "User Data"),
        ]
    else:
        config = Path(os.environ.get("XDG_CONFIG_HOME", str(home / ".config")))
        candidates = [
            ("Chrome", config / "google-chrome"),
            ("Chrome", config / "google-chrome-beta"),
            ("Chromium", config / "chromium"),
            ("Brave", config / "BraveSoftware" / "Brave-Browser"),
            ("Edge", config / "microsoft-edge"),
        ]
    return [(name, path) for name, path in candidates if path.exists()]


def is_chrome_profile(path: Path) -> bool:
    return (path / "Preferences").exists()


def load_json(path: Path):
    try:
        return json.loads(path.read_text(errors="ignore"))
    except Exception:
        return None


def manifest_summary(manifest: dict | None) -> dict:
    manifest = manifest or {}
    return {
        "name": manifest.get("name"),
        "version": manifest.get("version"),
        "description": manifest.get("description"),
        "permissions": sorted(set(manifest.get("permissions") or [])),
        "host_permissions": sorted(set(manifest.get("host_permissions") or [])),
        "content_scripts": manifest.get("content_scripts") or [],
        "homepage_url": manifest.get("homepage_url"),
    }


def extension_storage_hints(profile: Path, extension_id: str) -> dict:
    storage_dir = profile / "Local Extension Settings" / extension_id
    hints = {"geotime": False, "geomirror": False}
    if not storage_dir.exists():
        return hints
    for path in iter_files(storage_dir, max_files=100, max_size=5_000_000):
        data = read_bytes(path)
        if GEOTIME_STORAGE_RE.search(data):
            hints["geotime"] = True
        if GEOMIRROR_STORAGE_RE.search(data):
            hints["geomirror"] = True
        if hints["geotime"] and hints["geomirror"]:
            return hints
    return hints


def extension_code_hints(extension_path: Path | None) -> dict:
    hints = {"cdp_override": False, "browser_env_patch": False}
    if not extension_path or not extension_path.exists():
        return hints
    for path in iter_files(extension_path, max_files=200, max_size=1_000_000):
        if path.suffix.lower() not in {".js", ".json", ".html"}:
            continue
        data = read_bytes(path)
        if BROWSER_SPOOFING_RE.search(data):
            hints["cdp_override"] = True
        if BROWSER_ENV_PATCH_RE.search(data):
            hints["browser_env_patch"] = True
        if hints["cdp_override"] and hints["browser_env_patch"]:
            return hints
    return hints


def manifest_has_main_world_document_start(summary: dict) -> bool:
    for script in summary.get("content_scripts") or []:
        if script.get("world") == "MAIN" and script.get("run_at") == "document_start":
            matches = script.get("matches") or []
            if "<all_urls>" in matches or matches:
                return True
    return False


def manifest_has_ip_geo_hosts(summary: dict) -> bool:
    hosts = " ".join(summary.get("host_permissions") or []).lower()
    return any(
        token in hosts
        for token in [
            "ipinfo.io",
            "ipwho.is",
            "ipapi.co",
            "reallyfreegeoip",
            "overpass",
            "bigdatacloud",
        ]
    )


def find_extension_path(profile: Path, extension_id: str, extension_data: dict) -> Path | None:
    raw_path = extension_data.get("path")
    if raw_path:
        path = Path(raw_path).expanduser()
        if path.exists():
            return path
    packaged_root = profile / "Extensions" / extension_id
    if packaged_root.exists():
        versions = [p for p in packaged_root.iterdir() if p.is_dir()]
        versions.sort(reverse=True)
        if versions:
            return versions[0]
    return None


def browser_fingerprint_scan(home: Path, network: dict, enabled: bool) -> dict:
    if not enabled:
        return {"checked": False}

    profiles = []
    interesting_extensions = []
    languages = []
    for browser_name, root in chrome_profile_roots(home):
        candidates = [p for p in root.iterdir() if p.is_dir()] + [root]
        for profile in candidates:
            if not is_chrome_profile(profile):
                continue
            prefs = load_json(profile / "Preferences") or {}
            profile_name = prefs.get("profile", {}).get("name") or profile.name
            accept_languages = (
                prefs.get("intl", {}).get("accept_languages")
                or prefs.get("intl", {}).get("selected_languages")
            )
            if accept_languages:
                languages.append(
                    {
                        "browser": browser_name,
                        "profile": profile_name,
                        "accept_languages": accept_languages,
                        "region_hint": language_region(str(accept_languages)),
                    }
                )
            profile_record = {
                "browser": browser_name,
                "profile": profile_name,
                "path": str(profile),
            }
            profiles.append(profile_record)

            settings = prefs.get("extensions", {}).get("settings", {}) or {}
            for extension_id, extension_data in settings.items():
                manifest = extension_data.get("manifest") or {}
                summary = manifest_summary(manifest)
                extension_path = find_extension_path(profile, extension_id, extension_data)
                if extension_path and not summary["name"]:
                    disk_manifest = load_json(extension_path / "manifest.json")
                    if disk_manifest:
                        summary = manifest_summary(disk_manifest)

                text_blob = " ".join(
                    str(summary.get(field) or "")
                    for field in ["name", "description"]
                ).lower()
                permissions = set(summary["permissions"])
                has_debugger = "debugger" in permissions
                has_dnr = "declarativeNetRequest" in permissions
                has_main_world_document_start = manifest_has_main_world_document_start(summary)
                has_ip_geo_hosts = manifest_has_ip_geo_hosts(summary)
                geotime_like = any(
                    token in text_blob
                    for token in [
                        "geotime",
                        "timezone",
                        "geolocation",
                        "locale",
                        "language",
                        "spoofer",
                        "fingerprint",
                    ]
                )
                geomirror_text_like = any(
                    token in text_blob
                    for token in [
                        "geomirror",
                        "visible ip",
                        "accept-language",
                        "regional",
                        "font",
                        "mirror",
                    ]
                )
                code_hints = extension_code_hints(extension_path)
                cdp_override_code = code_hints["cdp_override"]
                browser_env_patch_code = code_hints["browser_env_patch"]
                storage_hints = extension_storage_hints(profile, extension_id)
                storage_hint = storage_hints["geotime"]
                geomirror_storage_hint = storage_hints["geomirror"]
                geomirror_like = (
                    geomirror_text_like
                    or (
                        has_dnr
                        and has_main_world_document_start
                        and (browser_env_patch_code or has_ip_geo_hosts or geomirror_storage_hint)
                    )
                )
                if (
                    has_debugger
                    or has_dnr
                    or geotime_like
                    or geomirror_like
                    or cdp_override_code
                    or browser_env_patch_code
                    or storage_hint
                    or geomirror_storage_hint
                ):
                    interesting_extensions.append(
                        {
                            "browser": browser_name,
                            "profile": profile_name,
                            "id": extension_id,
                            "name": summary["name"],
                            "version": summary["version"],
                            "permissions": summary["permissions"],
                            "has_debugger_permission": has_debugger,
                            "has_declarative_net_request": has_dnr,
                            "has_main_world_document_start": has_main_world_document_start,
                            "has_ip_geo_host_permissions": has_ip_geo_hosts,
                            "geotime_like": geotime_like,
                            "geomirror_like": geomirror_like,
                            "cdp_override_code_hint": cdp_override_code,
                            "browser_env_patch_code_hint": browser_env_patch_code,
                            "geotime_storage_key_hint": storage_hint,
                            "geomirror_storage_key_hint": geomirror_storage_hint,
                            "path": str(extension_path) if extension_path else None,
                        }
                    )

    if platform.system() == "Darwin":
        safari_present = (
            (home / "Library" / "Safari").exists()
            or (home / "Library" / "Containers" / "com.apple.Safari").exists()
            or (home / "Library" / "Preferences" / "com.apple.Safari.plist").exists()
        )
        if safari_present:
            safari_languages = macos_app_languages("com.apple.Safari", home)
            source = "com.apple.Safari AppleLanguages"
            if not safari_languages:
                safari_languages = parse_apple_languages(run(["defaults", "read", "-g", "AppleLanguages"]))
                source = "global AppleLanguages"
            if safari_languages:
                value = ",".join(safari_languages)
                languages.append(
                    {
                        "browser": "Safari",
                        "profile": source,
                        "accept_languages": value,
                        "region_hint": language_region(value),
                    }
                )
                profiles.append(
                    {
                        "browser": "Safari",
                        "profile": source,
                        "path": str(home / "Library" / "Safari"),
                    }
                )

    system_tz = iana_timezone()
    tz_country = TIMEZONE_COUNTRY_HINTS.get(system_tz or "")
    ip_country = network.get("country") if network.get("checked") else None
    mismatch_signals = []
    if ip_country and tz_country and ip_country != tz_country:
        mismatch_signals.append(
            {
                "type": "ip_timezone_country_mismatch",
                "ip_country": ip_country,
                "timezone": system_tz,
                "timezone_country_hint": tz_country,
            }
        )
    for language in languages[:10]:
        region_hint = language.get("region_hint")
        if ip_country and region_hint and region_hint != ip_country:
            mismatch_signals.append(
                {
                    "type": "ip_browser_language_region_mismatch",
                    "ip_country": ip_country,
                    "browser": language["browser"],
                    "profile": language["profile"],
                    "language_region_hint": region_hint,
                }
            )

    return {
        "checked": True,
        "profiles_checked": profiles,
        "browser_languages": languages,
        "interesting_extensions": interesting_extensions,
        "mismatch_signals": mismatch_signals,
        "system_timezone": system_tz,
        "system_timezone_country_hint": tz_country,
    }


def add_action(actions: list[dict], status: str, action: str, detail: str):
    actions.append({"status": status, "action": action, "detail": detail})


def third_party_config_dir(home: Path) -> Path:
    if platform.system() == "Windows":
        app_data = Path(os.environ.get("APPDATA", str(home / "AppData" / "Roaming")))
        return app_data / "third-party-models"
    return home / ".config" / "third-party-models"


def safe_destination(path: Path) -> Path:
    if not path.exists():
        return path
    stamp = time.strftime("%Y%m%d-%H%M%S")
    return path.with_name(f"{path.name}.moved-{stamp}")


def chmod_if_exists(path: Path, mode: int, actions: list[dict]):
    if not path.exists():
        return
    try:
        os.chmod(path, mode)
    except OSError as exc:
        add_action(actions, "error", "chmod", f"{path}: {type(exc).__name__}")
        return
    add_action(actions, "changed", "chmod", f"{path} -> {oct(mode)}")


def relocate_third_party_env_files(home: Path, actions: list[dict]) -> Path:
    destination_dir = third_party_config_dir(home)
    sources = {
        home / ".claude" / "deepseek.env": "deepseek-anthropic-compatible.env",
        home / ".claude" / "deepseek.env.save": "deepseek-anthropic-compatible.env.save",
        home / ".claude" / "claude-deepseek.env": "claude-deepseek.env",
    }
    moved_any = False
    for source, destination_name in sources.items():
        if not source.exists():
            continue
        try:
            destination_dir.mkdir(parents=True, exist_ok=True)
            destination = safe_destination(destination_dir / destination_name)
            shutil.move(str(source), str(destination))
        except OSError as exc:
            add_action(actions, "error", "relocate_env", f"{source}: {type(exc).__name__}")
            continue
        moved_any = True
        add_action(actions, "changed", "relocate_env", f"{source} -> {destination}")
    if not moved_any:
        add_action(actions, "skipped", "relocate_env", "No known third-party env files found under Claude Code state.")
    return destination_dir


def apply_unix_permissions(cwd: Path, home: Path, third_party_dir: Path, actions: list[dict]):
    if os.name == "nt":
        add_action(
            actions,
            "skipped",
            "chmod",
            "Windows ACL changes are not applied automatically; review file ownership manually if this is a shared machine.",
        )
        return

    for path in [home / ".claude", cwd / ".claude", third_party_dir]:
        chmod_if_exists(path, 0o700, actions)
    for path in [
        home / ".claude.json",
        home / ".claude" / "settings.json",
        home / ".claude" / "settings.local.json",
        cwd / ".claude" / "settings.json",
        cwd / ".claude" / "settings.local.json",
        third_party_dir / "deepseek-anthropic-compatible.env",
        third_party_dir / "deepseek-anthropic-compatible.env.save",
        third_party_dir / "claude-deepseek.env",
    ]:
        chmod_if_exists(path, 0o600, actions)


def chrome_is_running() -> bool:
    system = platform.system()
    if system == "Darwin":
        return bool(run(["pgrep", "-x", "Google Chrome"]))
    if system == "Windows":
        output = run(["tasklist", "/FI", "IMAGENAME eq chrome.exe"], timeout=5)
        return "chrome.exe" in output.lower()
    return bool(
        run(["pgrep", "-x", "chrome"])
        or run(["pgrep", "-x", "google-chrome"])
        or run(["pgrep", "-x", "chromium"])
    )


def quit_chrome_for_fixes(actions: list[dict]):
    system = platform.system()
    if system == "Darwin":
        run(["osascript", "-e", 'tell application "Google Chrome" to quit'], timeout=5)
        for _ in range(20):
            if not chrome_is_running():
                add_action(actions, "changed", "quit_chrome", "Google Chrome quit before language preference edit.")
                return
            time.sleep(0.5)
        add_action(actions, "warning", "quit_chrome", "Google Chrome still appears to be running.")
    elif system == "Windows":
        run(["taskkill", "/IM", "chrome.exe", "/T"], timeout=8)
        add_action(actions, "changed", "quit_chrome", "Requested Windows to close chrome.exe before language preference edit.")
    else:
        run(["pkill", "-x", "chrome"], timeout=5)
        run(["pkill", "-x", "google-chrome"], timeout=5)
        run(["pkill", "-x", "chromium"], timeout=5)
        add_action(actions, "changed", "quit_chrome", "Requested Linux Chromium-family browsers to close before language preference edit.")


def apply_chrome_language(home: Path, language: str, all_chromium: bool, actions: list[dict]):
    changed = 0
    targets = {"chrome"} if not all_chromium else None
    for browser_name, root in chrome_profile_roots(home):
        if targets and browser_name.lower() not in targets:
            continue
        candidates = [p for p in root.iterdir() if p.is_dir()] + [root]
        for profile in candidates:
            prefs_path = profile / "Preferences"
            if not prefs_path.exists():
                continue
            prefs = load_json(prefs_path)
            if not isinstance(prefs, dict):
                continue
            stamp = time.strftime("%Y%m%d-%H%M%S")
            backup = prefs_path.with_name(f"Preferences.backup-language-{stamp}")
            try:
                shutil.copy2(prefs_path, backup)
                prefs.setdefault("intl", {})["accept_languages"] = language
                prefs.setdefault("intl", {})["selected_languages"] = language
                prefs_path.write_text(json.dumps(prefs, ensure_ascii=False, separators=(",", ":")))
            except OSError as exc:
                add_action(actions, "error", "chrome_language", f"{prefs_path}: {type(exc).__name__}")
                continue
            changed += 1
            profile_name = prefs.get("profile", {}).get("name") or profile.name
            add_action(
                actions,
                "changed",
                "chrome_language",
                f"{browser_name}/{profile_name}: {language}; backup={backup}",
            )

    if platform.system() == "Darwin" and changed:
        primary = language.split(",", 1)[0]
        fallback = primary.split("-", 1)[0]
        run(["defaults", "write", "com.google.Chrome", "AppleLanguages", "-array", primary, fallback])
        run(["defaults", "write", "com.google.Chrome", "AppleLocale", primary.replace("-", "_")])
        add_action(actions, "changed", "chrome_app_language", f"com.google.Chrome AppleLanguages={primary},{fallback}")

    if not changed:
        add_action(actions, "skipped", "chrome_language", "No Chrome Preferences files found to update.")


def safari_is_running() -> bool:
    if platform.system() != "Darwin":
        return False
    return bool(run(["pgrep", "-x", "Safari"]))


def quit_safari_for_fixes(actions: list[dict]):
    if platform.system() != "Darwin":
        return
    run(["osascript", "-e", 'tell application "Safari" to quit'], timeout=5)
    for _ in range(20):
        if not safari_is_running():
            add_action(actions, "changed", "quit_safari", "Safari quit before language preference edit.")
            return
        time.sleep(0.5)
    add_action(actions, "warning", "quit_safari", "Safari still appears to be running.")


def apply_safari_language(language: str, actions: list[dict]):
    if platform.system() != "Darwin":
        add_action(actions, "skipped", "safari_language", "Safari language fixes are macOS-only.")
        return
    primary = language.split(",", 1)[0]
    fallback = primary.split("-", 1)[0]
    home = Path.home()
    changed = 0
    for path in [
        home / "Library" / "Preferences" / "com.apple.Safari.plist",
        home / "Library" / "Containers" / "com.apple.Safari" / "Data" / "Library" / "Preferences" / "com.apple.Safari.plist",
    ]:
        if not path.exists():
            continue
        stamp = time.strftime("%Y%m%d-%H%M%S")
        backup = path.with_name(f"{path.name}.backup-language-{stamp}")
        try:
            shutil.copy2(path, backup)
            with path.open("rb") as handle:
                data = plistlib.load(handle)
            data["AppleLanguages"] = [primary, fallback]
            data["AppleLocale"] = primary.replace("-", "_")
            with path.open("wb") as handle:
                plistlib.dump(data, handle, fmt=plistlib.FMT_BINARY)
        except PermissionError:
            add_action(actions, "warning", "safari_language", f"{path}: PermissionError; macOS privacy controls may require changing Safari language in System Settings.")
            continue
        except Exception as exc:
            add_action(actions, "error", "safari_language", f"{path}: {type(exc).__name__}")
            continue
        changed += 1
        add_action(actions, "changed", "safari_language", f"{path}: AppleLanguages={primary},{fallback}; backup={backup}")

    if not changed:
        run(["defaults", "write", "com.apple.Safari", "AppleLanguages", "-array", primary, fallback])
        run(["defaults", "write", "com.apple.Safari", "AppleLocale", primary.replace("-", "_")])
        add_action(actions, "changed", "safari_language", f"Attempted defaults write com.apple.Safari AppleLanguages={primary},{fallback}")


def apply_low_risk_fixes(args: argparse.Namespace) -> dict:
    home = Path.home()
    cwd = Path(args.cwd).expanduser().resolve()
    actions: list[dict] = []

    if args.quit_browsers_for_fixes:
        quit_chrome_for_fixes(actions)
    elif chrome_is_running():
        add_action(
            actions,
            "warning",
            "chrome_language",
            "Chrome appears to be running; close and reopen it after fixes, or rerun with --quit-browsers-for-fixes.",
        )
    if args.fix_safari_language and args.quit_browsers_for_fixes:
        quit_safari_for_fixes(actions)
    elif args.fix_safari_language and safari_is_running():
        add_action(
            actions,
            "warning",
            "safari_language",
            "Safari appears to be running; close and reopen it after fixes, or rerun with --quit-browsers-for-fixes.",
        )

    third_party_dir = relocate_third_party_env_files(home, actions)
    apply_unix_permissions(cwd, home, third_party_dir, actions)
    apply_chrome_language(home, args.fix_browser_language, args.fix_all_chromium_languages, actions)
    if args.fix_safari_language:
        apply_safari_language(args.fix_browser_language, actions)

    return {
        "checked": True,
        "applied": True,
        "browser_language": args.fix_browser_language,
        "actions": actions,
        "note": "Low-risk fixes require explicit user authorization. They do not change proxies, system timezone, official Claude Code binaries, or account facts.",
    }


def add_finding(findings: list[dict], severity: str, title: str, evidence: str, remediation: str):
    findings.append(
        {
            "severity": severity,
            "title": title,
            "evidence": evidence,
            "remediation": remediation,
        }
    )


def score_report(data: dict) -> dict:
    score = 100
    findings: list[dict] = []

    env_matches = data["environment"]["matches"]
    if any("anthropic_key_shape" in item["hints"] for item in env_matches):
        score -= 30
        add_finding(
            findings,
            "high",
            "Anthropic key-shaped value is present in the process environment",
            "An Anthropic-shaped secret was detected by shape only; the value was not printed.",
            "Move secrets into a scoped secret store, rotate if exposure is possible, and avoid passing them through broad shell sessions.",
        )
    elif any("generic_sk_shape" in item["hints"] for item in env_matches):
        score -= 12
        add_finding(
            findings,
            "medium",
            "Generic sk-* token shape is present in the process environment",
            "A secret-shaped value exists in an environment variable; provider cannot be confirmed by local shape alone.",
            "Confirm provider ownership, scope, and storage. Keep third-party keys separate from Anthropic account credentials.",
        )

    anthropic_env_names = [
        item["name"]
        for item in env_matches
        if re.search(r"ANTHROPIC|CLAUDE", item["name"], re.I)
    ]
    if anthropic_env_names:
        score -= 5
        add_finding(
            findings,
            "low",
            "Anthropic/Claude-related environment variables are active",
            "Variables: " + ", ".join(anthropic_env_names[:12]),
            "Keep active shells narrow and avoid mixing official Anthropic credentials with third-party endpoints.",
        )

    if data["proxy"]["env_proxy_names"] or data["proxy"].get("system_proxy_enabled"):
        score -= 12
        add_finding(
            findings,
            "medium",
            "Proxy configuration is active",
            "Proxy environment variables or OS proxy settings are enabled.",
            "Ensure account region, billing region, usual login region, and egress location are consistent and explainable.",
        )

    network = data["network"]
    if network.get("checked") and network.get("org_type_hint") == "cloud_or_datacenter":
        score -= 8
        add_finding(
            findings,
            "medium",
            "Public egress appears to be cloud or datacenter network",
            f"Egress: {network.get('country')}/{network.get('region')}/{network.get('city')}, org hint: cloud_or_datacenter.",
            "Prefer stable, expected access patterns. Document legitimate cloud/VPN use if it matches your account and billing facts.",
        )

    loose_sensitive = [
        f for f in data["config"]["sensitive_files"] if f["group_or_other_readable"]
    ]
    if loose_sensitive:
        score -= min(18, 6 * len(loose_sensitive))
        add_finding(
            findings,
            "medium",
            "Sensitive Claude config files are group/other readable",
            "Files: " + ", ".join(f["path"] for f in loose_sensitive[:8]),
            "Restrict sensitive config files to the current user, for example mode 600 for files and 700 for directories.",
        )

    loose_dirs = [
        f for f in data["config"]["loose_paths"] if f["type"] == "dir" and f["path"].endswith(".claude")
    ]
    if loose_dirs:
        score -= 4
        add_finding(
            findings,
            "low",
            "Claude directory is readable/traversable by group or others",
            "Path: " + loose_dirs[0]["path"],
            "Consider mode 700 for local Claude state directories on multi-user machines.",
        )

    secrets = data["secret_scan"]
    if secrets["anthropic_key_shape_files"]:
        score -= 35
        add_finding(
            findings,
            "critical",
            "Anthropic key-shaped secret appears in scanned files",
            "Files: " + ", ".join(secrets["anthropic_key_shape_files"][:10]),
            "Rotate the key, remove it from files/history, and move it into a secret manager or private environment file.",
        )
    elif secrets["generic_sk_shape_files"]:
        score -= 10
        add_finding(
            findings,
            "medium",
            "Generic sk-* secret-shaped values appear in scanned files",
            "Files: " + ", ".join(secrets["generic_sk_shape_files"][:10]),
            "Confirm these are not Anthropic credentials and restrict/rotate them if exposure is possible.",
        )

    if secrets["mixed_provider_files"]:
        score -= 12
        add_finding(
            findings,
            "medium",
            "Anthropic variable names appear to be used with non-Anthropic endpoints",
            "Files: " + ", ".join(secrets["mixed_provider_files"][:10]),
            "Rename third-party endpoint variables or isolate provider-specific env files to avoid account and audit confusion.",
        )

    install = data.get("claude_code_install", {})
    if install.get("checked"):
        categories = set()
        versions = []
        files = []
        for package in install.get("packages", []):
            if package.get("version"):
                versions.append(str(package["version"]))
            for matched in package.get("matched_files", []):
                files.append(matched["path"])
                categories.update(matched.get("hits", {}).keys())
        high_interest_categories = {
            "cn_timezone_ids",
            "anthropic_base_url_env",
            "domain_check_endpoint",
            "region_marker_labels",
            "today_date_prompt",
        }
        if categories & high_interest_categories:
            add_finding(
                findings,
                "info",
                "Claude Code package contains region/domain check strings",
                "Versions: "
                + ", ".join(sorted(set(versions))[:5])
                + "; categories: "
                + ", ".join(sorted(categories))
                + "; files: "
                + ", ".join(files[:6]),
                "Treat this as local forensic evidence only. It does not by itself prove hidden transmission, account targeting, or server-side enforcement.",
            )

    browser = data.get("browser_fingerprint", {})
    if browser.get("checked"):
        interesting = browser.get("interesting_extensions", [])
        geotime_like = [
            item
            for item in interesting
            if item.get("has_debugger_permission")
            and (
                item.get("geotime_like")
                or item.get("cdp_override_code_hint")
                or item.get("geotime_storage_key_hint")
            )
        ]
        geomirror_like = [
            item
            for item in interesting
            if item.get("geomirror_like")
            or (
                item.get("has_declarative_net_request")
                and item.get("has_main_world_document_start")
                and (
                    item.get("browser_env_patch_code_hint")
                    or item.get("geomirror_storage_key_hint")
                )
            )
        ]
        browser_env_patch_extensions = [
            item
            for item in interesting
            if item.get("browser_env_patch_code_hint")
            and not item.get("has_debugger_permission")
            and not item.get("geomirror_like")
        ]
        debugger_extensions = [
            item for item in interesting if item.get("has_debugger_permission")
        ]
        if geotime_like or geomirror_like:
            score -= 20
            names = [
                f"{item.get('name') or item.get('id')} ({item.get('browser')}/{item.get('profile')})"
                for item in (geotime_like + geomirror_like)[:8]
            ]
            add_finding(
                findings,
                "high",
                "GeoTime/GeoMirror-style browser spoofing extension detected",
                "Extensions: " + ", ".join(names),
                "Remove or disable browser environment spoofing for Anthropic account use, or document a legitimate testing-only profile that is separate from account access.",
            )
        elif debugger_extensions:
            score -= 8
            names = [
                f"{item.get('name') or item.get('id')} ({item.get('browser')}/{item.get('profile')})"
                for item in debugger_extensions[:8]
            ]
            add_finding(
                findings,
                "medium",
                "Chrome extension with debugger permission detected",
                "Extensions: " + ", ".join(names),
                "Review whether any debugger-capable extension can override browser environment signals used during Anthropic account access.",
            )
        elif browser_env_patch_extensions:
            score -= 8
            names = [
                f"{item.get('name') or item.get('id')} ({item.get('browser')}/{item.get('profile')})"
                for item in browser_env_patch_extensions[:8]
            ]
            add_finding(
                findings,
                "medium",
                "Browser extension may patch regional environment APIs",
                "Extensions: " + ", ".join(names),
                "Review whether the extension changes timezone, locale, geolocation, language, or request-language signals while using Anthropic accounts.",
            )

        mismatches = browser.get("mismatch_signals", [])
        if mismatches:
            score -= min(18, 6 * len(mismatches))
            kinds = sorted({item.get("type", "unknown") for item in mismatches})
            add_finding(
                findings,
                "medium",
                "Browser/network consistency mismatch signals detected",
                "Signals: " + ", ".join(kinds),
                "Align account facts, expected travel/proxy use, browser language, system timezone, and public egress region; document legitimate differences.",
            )

    if not findings:
        add_finding(
            findings,
            "info",
            "No major local-environment issues detected",
            "The scanner found no Anthropic key-shaped leaks, no active proxy signals, and no loose sensitive Claude config files.",
            "Still verify account region, billing country, product use case, and warning history with the user.",
        )

    score = max(0, min(100, score))
    if score >= 85:
        level = "low"
    elif score >= 70:
        level = "medium"
    elif score >= 50:
        level = "high"
    else:
        level = "critical"

    blind_spots = [
        "Anthropic 服务端的真实风控分、内部原因码、历史登录/IP/设备记录。",
        "账号创建地、支付卡/账单校验、失败付款、拒付、订阅变更和税务/账单资料。",
        "服务端请求内容、请求 ID、限流记录、并发/重试历史、模型安全标记和 abuse classifier 结果。",
        "邮件、warning、disabled notice、support ticket、申诉处理记录和 trust-and-safety 备注。",
        "其他设备、手机 App、远程服务器、CI、MCP、网关、共享脚本或团队成员的使用行为。",
    ]

    self_check = {
        "账号/支付": [
            "账号创建时间、注册国家、账单国家、支付卡国家是否能解释清楚。",
            "最近有没有换卡、失败扣款、退款、拒付、订阅升级/降级或账单地址变更。",
            "账号是否只属于一个自然人/一个组织，没有租借、转卖、代登或多人共用。",
        ],
        "登录/设备": [
            "最近 30 天登录国家、代理出口、设备、浏览器 profile 是否频繁变化。",
            "有没有新设备、手机 App、Safari/Chrome/Edge/360、多浏览器同时登录。",
            "有没有密码重置、2FA 变化、OAuth 重新授权、异常登录邮件或安全提醒。",
        ],
        "请求/自动化": [
            "Claude Code 是否跑了大量并发、循环重试、定时任务、CI、批量 agent 或 MCP 工具链。",
            "请求内容是否涉及高风险领域：网络安全、金融、医疗、法律、招聘、未成年人、政府或身份验证。",
            "是否有用户-facing 产品让陌生人直接驱动 Claude，是否有日志、限流、人工审核和滥用处理。",
        ],
        "凭据/网关": [
            "OAuth token、API key、session、cookie 有没有复制到其他机器、服务器、脚本或网关。",
            "是否混用 Anthropic 官方账号和第三方中转/兼容接口，变量名是否清楚隔离。",
            "团队成员、外包、客户、面板、机器人是否能间接使用同一个账号或 key。",
        ],
        "警告/申诉": [
            "是否收到过 safeguard warning、disabled、suspicious activity、payment 或 unsupported location 提示。",
            "是否保存了邮件原文、时间戳、request ID、相关日志和已经做过的整改。",
            "如果要申诉，是否能给出事实、证据、整改动作，而不是只写“我没违规”。",
        ],
    }

    questions = [
        "你用 Claude Code 是订阅登录、API key、团队/企业账号，还是第三方/云市场接入？",
        "账号注册国家、账单国家、常用登录国家、当前出口国家分别是哪里？这些变化能否解释？",
        "最近 30 天有没有换设备、换浏览器、换代理出口、换支付方式、重新登录 OAuth 或收到安全邮件？",
        "Claude 账号、Anthropic API key、OAuth token 有没有给团队成员、客户、面板、网关、CI 或自动化脚本共用？",
        "主要用途是什么？是否面向终端用户，是否让 agent 调工具/MCP，是否涉及医疗、法律、金融、招聘、教育、未成年人、政府或网络安全？",
        "平时请求量、并发、重试频率大概是多少？最近有没有突然暴涨、循环任务或批量处理？",
        "有没有收到过 safeguard warning、账号 disabled、suspicious activity、payment、unsupported location 提示，或者提交过申诉？",
    ]

    return {
        "score": score,
        "level": level,
        "findings": findings,
        "blind_spots": blind_spots,
        "self_check": self_check,
        "questions": questions,
    }


def build_report(args: argparse.Namespace) -> dict:
    home = Path.home()
    cwd = Path(args.cwd).expanduser().resolve()
    data = {
        "metadata": {
            "scanner": "anthropic-account-self-audit/scripts/local_risk_scan.py",
            "scope": "Claude Code local state by default; optional browser-fingerprint scan checks Chromium extensions and consistency signals",
            "cwd": str(cwd),
            "network_enabled": args.network,
            "browser_fingerprint_enabled": args.browser_fingerprint,
        },
        "local": local_signals(),
        "environment": env_scan(),
        "config": config_scan(cwd, home),
        "proxy": proxy_scan(),
        "network": network_scan(args.network),
        "secret_scan": secret_scan(cwd, home),
        "claude_code_install": claude_code_install_scan(home),
    }
    data["browser_fingerprint"] = browser_fingerprint_scan(
        home, data["network"], args.browser_fingerprint
    )
    data["assessment"] = score_report(data)
    return data


def print_markdown(report: dict) -> None:
    assessment = report["assessment"]
    level_label = {
        "low": "低",
        "medium": "中",
        "high": "高",
        "critical": "严重",
    }.get(assessment["level"], assessment["level"])
    plain = {
        "Proxy configuration is active": (
            "系统代理正在开启",
            "你的电脑网络可能正在通过代理或中转出去。",
            "如果账号注册地、账单地、常用登录地和这个网络出口对不上，平台可能会觉得登录环境不稳定或不一致。",
        ),
        "Public egress appears to be cloud or datacenter network": (
            "网络出口像云服务器",
            "公网出口看起来不是普通家庭/办公网络，而是云机房或数据中心。",
            "这不一定有问题，但如果长期用于个人账号登录，需要能解释为什么账号会从这种网络出来。",
        ),
        "Sensitive Claude config files are group/other readable": (
            "Claude Code 配置文件权限偏松",
            "有些 Claude Code 配置文件不是只有你自己能读。",
            "如果这台机器有其他本地用户，配置、路径或环境信息可能被看到。",
        ),
        "Claude directory is readable/traversable by group or others": (
            "Claude Code 状态目录权限偏松",
            "Claude Code 的本地目录允许其他本机用户进入或读取一部分信息。",
            "单用户电脑通常问题不大，多用户机器建议收紧。",
        ),
        "Generic sk-* secret-shaped values appear in scanned files": (
            "发现像 API key 的字符串",
            "扫描到 `sk-*` 这种像密钥的字符串，但不像 Anthropic 官方 `sk-ant-api...` key。",
            "需要确认它是不是第三方 key；如果可能暴露过，建议轮换。",
        ),
        "Anthropic variable names appear to be used with non-Anthropic endpoints": (
            "第三方模型配置用了 Anthropic 变量名",
            "有些 DeepSeek/第三方配置用了 `ANTHROPIC_*` 这样的变量名。",
            "这容易让 Claude Code 官方环境和第三方模型环境混在一起，排查和申诉时也不好解释。",
        ),
        "Browser/network consistency mismatch signals detected": (
            "浏览器和网络地区不一致",
            "你的电脑时区/浏览器语言像一个地区，但公网出口像另一个地区。",
            "这不是违规证明，但属于账号环境一致性风险，需要能解释。",
        ),
        "GeoTime/GeoMirror-style browser spoofing extension detected": (
            "发现类似 GeoTime / GeoMirror 的浏览器地区伪装扩展",
            "浏览器里可能有能改时区、语言、请求头或地理位置的扩展。",
            "如果这个浏览器也用来登录 Anthropic，账号环境会显得更复杂。",
        ),
        "Browser extension may patch regional environment APIs": (
            "发现可能改浏览器地区信息的扩展",
            "有扩展代码看起来会动时区、语言、定位或请求语言。",
            "如果它和 Anthropic 登录共用同一个浏览器 profile，就需要确认用途并保持可解释。",
        ),
        "Chrome extension with debugger permission detected": (
            "发现有高权限浏览器扩展",
            "有扩展拿到了 Chrome debugger 权限。",
            "这种权限可以影响网页看到的浏览器环境，建议确认它和 Anthropic 登录无关。",
        ),
        "Anthropic key-shaped value is present in the process environment": (
            "当前环境里有 Anthropic key 形态的值",
            "当前 shell 里检测到像 Anthropic 官方 key 的字符串，但没有打印内容。",
            "建议改用更窄的密钥存放方式，必要时轮换。",
        ),
        "Anthropic key-shaped secret appears in scanned files": (
            "文件里出现 Anthropic key 形态的值",
            "本地文件里检测到像 Anthropic 官方 key 的字符串，但没有打印内容。",
            "建议立即轮换 key，并清理文件和历史记录。",
        ),
        "Claude Code package contains region/domain check strings": (
            "Claude Code 安装包里有区域/域名检查相关字符串",
            "本机 Claude Code 包里能看到时区、`ANTHROPIC_BASE_URL`、域名检查等相关字样。",
            "这只能说明安装包里存在这些本地可复查信号，不能单凭它证明隐写传输、定向封号或服务端怎么使用这些信息。",
        ),
    }
    print("一句话结论：")
    print(
        f"这台机器的 Claude Code/Anthropic 本机环境风险分是 {assessment['score']}/100，"
        f"等级是{level_label}；这表示本机有需要修的风险信号，不等于账号一定会被封。"
    )
    print("")
    print("这个报告看不到什么：")
    print("本机扫描只能看你这台机器上的配置、浏览器和网络出口；它看不到 Anthropic 服务端掌握的账号历史。")
    for item in assessment.get("blind_spots", []):
        print(f"- {item}")
    print("")
    fixes = report.get("remediation_actions")
    if fixes and fixes.get("applied"):
        print("已执行的低风险修改：")
        for action in fixes.get("actions", []):
            print(f"- {action['status']}: {action['action']} - {action['detail']}")
        print("")
    print("我看到的主要问题：")
    for index, finding in enumerate(assessment["findings"], 1):
        title, what, why = plain.get(
            finding["title"],
            (finding["title"], finding["evidence"], finding["remediation"]),
        )
        print(f"{index}. {title}")
        print(f"   发生了什么：{what}")
        print(f"   为什么要紧：{why}")
        print(f"   技术证据：{finding['evidence']}")
    print("")
    print("用户自己要查的清单：")
    for group, items in assessment.get("self_check", {}).items():
        print(f"{group}：")
        for item in items:
            print(f"- {item}")
    print("")
    print("我还需要确认：")
    for question in assessment["questions"]:
        print(f"- {question}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cwd", default=os.getcwd(), help="Project directory to scan")
    parser.add_argument(
        "--network",
        action="store_true",
        help="Perform public egress lookup through ipinfo.io",
    )
    parser.add_argument(
        "--browser-fingerprint",
        action="store_true",
        help="Scan Chromium browser profiles for GeoTime-style extension and consistency signals",
    )
    parser.add_argument(
        "--apply-low-risk-fixes",
        action="store_true",
        help="After explicit user authorization, apply low-risk local hygiene fixes before rescanning",
    )
    parser.add_argument(
        "--fix-browser-language",
        default="en-US,en",
        help="Browser Accept-Language value to write when --apply-low-risk-fixes is enabled",
    )
    parser.add_argument(
        "--fix-all-chromium-languages",
        action="store_true",
        help="Apply browser language preference to all detected Chromium-family browsers, not only Chrome",
    )
    parser.add_argument(
        "--fix-safari-language",
        action="store_true",
        help="With --apply-low-risk-fixes on macOS, set Safari's app-specific language preference",
    )
    parser.add_argument(
        "--quit-browsers-for-fixes",
        action="store_true",
        help="With --apply-low-risk-fixes, try to close affected browsers before editing Preferences",
    )
    parser.add_argument("--format", choices=["json", "markdown"], default="json")
    args = parser.parse_args()

    fixes = None
    if args.apply_low_risk_fixes:
        fixes = apply_low_risk_fixes(args)
    report = build_report(args)
    if fixes:
        report["remediation_actions"] = fixes
    if args.format == "markdown":
        print_markdown(report)
    else:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
