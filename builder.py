#!/usr/bin/env python3
import requests
import json
import re
import io
import zipfile
import os
import logging
import time
from collections import defaultdict
from urllib.parse import urlparse

# --- CONFIGURATION ---
INPUT_FILE = "repos.txt"
OUTPUT_FILE = "plugins.json"
MAX_ZIP_SIZE = 50 * 1024 * 1024  # 50MB hard cap for ZIP downloads
MAX_RETRIES = 3

# Logging setup
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

# --- SMART CATEGORY DICTIONARY ---
KEYWORDS = {
    'GPS': ['gps', 'geo', 'lat', 'lon', 'location', 'map', 'coordinates', 'nmea', 'track', 'wigle', 'wardrive'],
    'Social': ['discord', 'telegram', 'twitter', 'social', 'chat', 'bot', 'webhook', 'slack', 'message', 'notify'],
    'Display': ['screen', 'display', 'ui', 'theme', 'face', 'font', 'oled', 'ink', 'led', 'view', 'clock', 'weather', 'status', 'mem', 'cpu', 'info'],
    'Attack': ['pwn', 'crack', 'handshake', 'deauth', 'assoc', 'brute', 'attack', 'wardriving', 'pmkid', 'wpa', 'eapol', 'sniff'],
    'Hardware': ['ups', 'battery', 'power', 'shutdown', 'reboot', 'button', 'switch', 'gpio', 'i2c', 'spi', 'bluetooth', 'ble', 'hw'],
    'System': ['backup', 'ssh', 'log', 'update', 'fix', 'clean', 'config', 'manage', 'util', 'internet', 'wifi', 'connection']
}

# Counters for summary
failed_urls = []
skipped_files = 0

def compare_versions(v1, v2):
    """Compare semantic versions properly. Returns 1 if v1>v2, -1 if v1<v2, 0 if equal."""
    try:
        v1_parts = [int(x) for x in v1.lstrip('v').split('.')]
        v2_parts = [int(x) for x in v2.lstrip('v').split('.')]
        while len(v1_parts) < len(v2_parts): v1_parts.append(0)
        while len(v2_parts) < len(v1_parts): v2_parts.append(0)
        for a, b in zip(v1_parts, v2_parts):
            if a > b: return 1
            elif a < b: return -1
        return 0
    except (ValueError, AttributeError):
        try:
            return (v1 > v2) - (v1 < v2)
        except Exception:
            return 0

def fetch_with_retry(url, timeout=30):
    """Fetch a URL with exponential backoff. Returns the Response or None."""
    for attempt in range(MAX_RETRIES):
        try:
            r = requests.get(url, timeout=timeout, stream=True)
            r.raise_for_status()
            return r
        except Exception as e:
            if attempt < MAX_RETRIES - 1:
                wait = 2 ** attempt  # 1s, 2s
                logging.warning(f"    [!] Attempt {attempt + 1} failed for {url}: {e}. Retrying in {wait}s...")
                time.sleep(wait)
            else:
                logging.error(f"    [!] All {MAX_RETRIES} attempts failed for {url}: {e}")
                return None

def fetch_zip_safe(url, timeout=30):
    """Stream-download a ZIP with a size cap to prevent OOM."""
    r = fetch_with_retry(url, timeout=timeout)
    if r is None:
        return None

    # Check Content-Length if available
    content_length = r.headers.get('Content-Length')
    if content_length and int(content_length) > MAX_ZIP_SIZE:
        logging.error(f"    [!] ZIP too large ({int(content_length)} bytes > {MAX_ZIP_SIZE}): {url}")
        r.close()
        return None

    # Stream download with size cap
    chunks = []
    total = 0
    for chunk in r.iter_content(chunk_size=8192):
        total += len(chunk)
        if total > MAX_ZIP_SIZE:
            logging.error(f"    [!] ZIP exceeded {MAX_ZIP_SIZE} bytes during download: {url}")
            r.close()
            return None
        chunks.append(chunk)

    return b''.join(chunks)

def looks_like_plugin(text):
    """Sanity check: reject obvious non-Python responses (e.g. GitHub 503 HTML pages)."""
    if not text or len(text.strip()) == 0:
        return False
    stripped = text.strip()
    if stripped.startswith('<!') or stripped.startswith('<html') or stripped.startswith('<HTML'):
        return False
    if '<!DOCTYPE' in stripped[:200]:
        return False
    return True

def detect_category(name, description, code):
    scores = defaultdict(int)
    name_lower = name.lower()
    desc_lower = description.lower() if description else ""
    code_lower = code.lower()  # Full file, not truncated

    for category, tags in KEYWORDS.items():
        for tag in tags:
            if tag in name_lower: scores[category] += 10
            if re.search(r'\b' + re.escape(tag) + r'\b', desc_lower): scores[category] += 3
            if tag in code_lower: scores[category] += 1

    if "ui.set" in code_lower: scores["Display"] += 5
    if "gpio" in code_lower: scores["Hardware"] += 2

    if not scores: return "System"
    return max(scores, key=scores.get)

def resolve_variable(code, var_name):
    """Resolve a variable name to its string literal value in the source code."""
    val_match = re.search(rf'{re.escape(var_name)}\s*=\s*[\'"](.+?)[\'"]', code)
    return val_match.group(1) if val_match else None

def resolve_paren_string(code, attr_name):
    """Resolve __attr__ = ("str1 " "str2 " "str3") to a joined string."""
    paren_match = re.search(rf'{attr_name}\s*=\s*\(([\s\S]*?)\)', code)
    if not paren_match:
        return None
    inner = paren_match.group(1)
    parts = re.findall(r'"((?:[^"\\]|\\.)*)"', inner)
    if not parts:
        parts = re.findall(r"'((?:[^'\\]|\\.)*)'", inner)
    return "".join(parts).strip() if parts else None

def parse_python_content(code, filename, origin_url, internal_path=None):
    global skipped_files
    data = {}

    try:
        # --- Version: try string literal first, then variable reference ---
        version_match = re.search(r"__version__\s*=\s*['\"](.+?)['\"]", code)
        if version_match:
            data['version'] = version_match.group(1)
        else:
            var_match = re.search(r"__version__\s*=\s*([A-Za-z_][A-Za-z0-9_]*)", code)
            resolved = resolve_variable(code, var_match.group(1)) if var_match else None
            data['version'] = resolved if resolved else "0.0.1"

        # --- Author: string literal or variable reference ---
        author_match = re.search(r"__author__\s*=\s*['\"](.+?)['\"]", code)
        if author_match:
            data['author'] = author_match.group(1)
        else:
            var_match = re.search(r"__author__\s*=\s*([A-Za-z_][A-Za-z0-9_]*)", code)
            resolved = resolve_variable(code, var_match.group(1)) if var_match else None
            data['author'] = resolved if resolved else "Unknown"

        # --- Description: string literal, triple-quoted, parenthesized multi-line, then variable ---
        # Try triple-quoted first (""" or ''')
        desc_match = re.search(r'__description__\s*=\s*"""(.*?)"""', code, re.DOTALL)
        if not desc_match:
            desc_match = re.search(r"__description__\s*=\s*'''(.*?)'''", code, re.DOTALL)
        if desc_match:
            data['description'] = desc_match.group(1).strip()
        else:
            # Single/double quoted
            desc_match = re.search(r"__description__\s*=\s*([\"'])((?:(?!\1).)*)\1", code, re.DOTALL)
            if desc_match:
                data['description'] = desc_match.group(2).strip()
            else:
                # Parenthesized multi-line
                paren_desc = resolve_paren_string(code, '__description__')
                if paren_desc:
                    data['description'] = paren_desc
                else:
                    # Variable reference
                    var_match = re.search(r"__description__\s*=\s*([A-Za-z_][A-Za-z0-9_]*)", code)
                    resolved = resolve_variable(code, var_match.group(1)) if var_match else None
                    data['description'] = resolved if resolved else "No description provided."

        # Determine category
        data['category'] = detect_category(filename.replace(".py", ""), data['description'], code)

        # Only return data if we found enough metadata
        if data['description'] != "No description provided." or data['version'] != "0.0.1":
            return {
                "name": filename.replace(".py", ""),
                "version": data['version'],
                "description": data['description'],
                "author": data['author'],
                "category": data['category'],
                "origin_type": "zip" if internal_path else "single",
                "download_url": origin_url,
                "path_inside_zip": internal_path
            }
        else:
            skipped_files += 1

    except Exception as e:
        logging.debug(f"    [!] Parse error for {filename}: {e}")
        skipped_files += 1

    return None

def is_zip_url(url):
    """Check if URL points to a zip file, ignoring query strings."""
    parsed = urlparse(url)
    return parsed.path.lower().endswith('.zip')

def process_zip_url(url):
    found = []
    try:
        logging.info(f"[*] Downloading ZIP: {url}...")
        data = fetch_zip_safe(url)
        if data is None:
            failed_urls.append(url)
            return found

        z = zipfile.ZipFile(io.BytesIO(data))

        for filename in z.namelist():
            if filename.endswith(".py") and "__init__" not in filename and "/." not in filename:
                with z.open(filename) as f:
                    code = f.read().decode('utf-8', errors='ignore')

                plugin = parse_python_content(code, filename.split("/")[-1], url, filename)
                if plugin:
                    logging.info(f"    [+] {plugin['name']:<25} -> {plugin['category']}")
                    found.append(plugin)

    except Exception as e:
        logging.error(f"    [!] ZIP Error for {url}: {e}")
        failed_urls.append(url)
    return found

def main():
    global skipped_files
    print("--- PwnStore Builder v1.4 Starting ---")
    master_list = []

    if not os.path.exists(INPUT_FILE):
        logging.error(f"Error: {INPUT_FILE} not found.")
        return

    with open(INPUT_FILE, "r") as f:
        raw_urls = [line.strip() for line in f.readlines() if line.strip() and not line.startswith("#")]

    # Deduplicate URLs while preserving order
    seen_urls = set()
    urls = []
    for url in raw_urls:
        if url not in seen_urls:
            seen_urls.add(url)
            urls.append(url)
        else:
            logging.warning(f"    [!] Duplicate URL skipped: {url}")

    for url in urls:
        if is_zip_url(url):
            plugins = process_zip_url(url)
            master_list.extend(plugins)
        else:
            try:
                r = fetch_with_retry(url, timeout=15)
                if r is None:
                    failed_urls.append(url)
                    continue
                code = r.text
                if not looks_like_plugin(code):
                    logging.warning(f"    [!] Skipped (not a Python file): {url}")
                    skipped_files += 1
                    continue
                plugin = parse_python_content(code, url.split("/")[-1], url, None)
                if plugin:
                    logging.info(f"    [+] {plugin['name']:<25} -> {plugin['category']}")
                    master_list.append(plugin)
            except Exception as e:
                logging.error(f"    [!] Raw File Error for {url}: {e}")
                failed_urls.append(url)

    # --- DEDUPLICATION AND SORT ---
    final_plugins = {}
    for plugin in master_list:
        name_key = plugin['name'].lower()
        if name_key not in final_plugins or compare_versions(plugin['version'], final_plugins[name_key]['version']) > 0:
            final_plugins[name_key] = plugin

    sorted_plugins = sorted(final_plugins.values(), key=lambda p: p['name'].lower())

    with open(OUTPUT_FILE, "w") as f:
        json.dump(sorted_plugins, f, indent=2)

    # --- Summary ---
    print(f"\n[SUCCESS] Generated sorted registry with {len(sorted_plugins)} unique plugins.")
    if failed_urls:
        print(f"[WARNING] {len(failed_urls)} URL(s) failed:")
        for u in failed_urls:
            print(f"  - {u}")
    if skipped_files:
        print(f"[INFO] {skipped_files} file(s) skipped (insufficient metadata or not a plugin).")

if __name__ == "__main__":
    main()
