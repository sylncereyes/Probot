#!/usr/bin/env python3
"""
Advanced Async URL Scanner v1
Includes: smart HTTP/HTTPS switch, --alive, --detect-waf, --cdn-check, --tech-detect (compact Wappalyzer dataset)
"""
import sys
import asyncio
import aiohttp
import argparse
import ssl
import socket
import time
import re
from aiohttp import ClientTimeout, TCPConnector
from urllib.parse import urlparse

# ---------------------------
# Banner
# ---------------------------
BANNER = r"""
 /$$$$$$$  /$$$$$$$   /$$$$$$  /$$$$$$$   /$$$$$$  /$$$$$$$$
| $$__  $$| $$__  $$ /$$__  $$| $$__  $$ /$$__  $$|__  $$__/
| $$  \ $$| $$  \ $$| $$  \ $$| $$  \ $$| $$  \ $$   | $$   
| $$$$$$$/| $$$$$$$/| $$  | $$| $$$$$$$ | $$  | $$   | $$   
| $$____/ | $$__  $$| $$  | $$| $$__  $$| $$  | $$   | $$   
| $$      | $$  \ $$| $$  | $$| $$  \ $$| $$  | $$   | $$   
| $$      | $$  | $$|  $$$$$$/| $$$$$$$/|  $$$$$$/   | $$   
|__/      |__/  |__/ \______/ |_______/  \______/    |__/   
                                                            
 Ultra-Fast Async URL Scanner v1
"""

# ---------------------------
# Compact tech dataset (ringkas)
# patterns: header substrings, meta generator, body regex, script src substrings
# ---------------------------
COMPACT_TECH = {
    "WordPress": {
        "meta": [r'wordpress'],
        "body": [r'wp-content', r'wp-includes', r'wp-'],
        "script": [r'wp-'],
        "header": []
    },
    "Joomla": {
        "meta": [r'joomla'],
        "body": [r'index.php\?option=com_', r'/components/'],
        "script": [],
        "header": []
    },
    "Drupal": {
        "meta": [r'drupal'],
        "body": [r'/sites/default/', r'drupal.settings'],
        "script": [],
        "header": []
    },
    "PHP": {
        "meta": [],
        "body": [r'\.php'],
        "script": [],
        "header": []
    },
    "Python": {
        "meta": [],
        "body": [r'py-?hton', r'wsgi', r'django'],
        "script": [],
        "header": []
    },
    "Node.js": {
        "meta": [],
        "body": [r'node', r'express'],
        "script": [],
        "header": []
    },
    "React": {
        "meta": [],
        "body": [r'<!-- react-text:|data-reactroot|data-reactid'],
        "script": [r'react', r'__REACT_DEVTOOLS_GLOBAL_HOOK__'],
        "header": []
    },
    "Vue": {
        "meta": [],
        "body": [r'vue', r'__vue_devtools__'],
        "script": [r'vue'],
        "header": []
    },
    "jQuery": {
        "meta": [],
        "body": [r'jquery', r'jQuery'],
        "script": [r'jquery'],
        "header": []
    },
    "Bootstrap": {
        "meta": [],
        "body": [r'bootstrap'],
        "script": [r'bootstrap'],
        "header": []
    },
    "Google Analytics": {
        "meta": [],
        "body": [r'ga\(', r'gtag\(\'config\'', r'google-analytics.com/analytics.js'],
        "script": [r'google-analytics', r'gtag'],
        "header": []
    },
    "Nginx": {
        "meta": [],
        "body": [],
        "script": [],
        "header": [r'nginx']
    },
    "Apache": {
        "meta": [],
        "body": [],
        "script": [],
        "header": [r'apache', r'httpd']
    },
    "IIS": {
        "meta": [],
        "body": [],
        "script": [],
        "header": [r'microsoft-iis', r'iis']
    },
    "Cloudflare": {
        "meta": [],
        "body": [],
        "script": [],
        "header": [r'cf-ray', r'cloudflare', r'cf-cache-status', r'__cfduid']
    },
    "CloudFront": {
        "meta": [],
        "body": [],
        "script": [],
        "header": [r'cloudfront', r'x-amz-cf-id']
    },
    "Fastly": {
        "meta": [],
        "body": [],
        "script": [],
        "header": [r'fastly']
    }
}

# ---------------------------
# WAF detection (simple heuristics)
# ---------------------------
def detect_waf_from_headers_and_body(headers: dict, body_text: str = ""):
    hv = {k.lower(): (v or "").lower() for k, v in headers.items()}
    cookie_blob = hv.get("set-cookie", "")

    if "cloudflare" in hv.get("server", "") or "cf-ray" in hv or "cf-cache-status" in hv:
        return "Cloudflare"
    if "sucuri" in hv.get("server", "") or "sucuri_cloudproxy" in cookie_blob or "x-sucuri-id" in hv:
        return "Sucuri"
    if "incapsula" in cookie_blob or "incap_ses_" in cookie_blob or "visid_incap" in cookie_blob:
        return "Imperva/Incapsula"
    if any(k.startswith("x-akamai-") for k in hv) or "akamai" in hv.get("server", ""):
        return "Akamai"
    if "x-amz-cf-id" in hv or "cloudfront" in hv.get("via", ""):
        return "CloudFront"
    if "x-fastly-request-id" in hv or "fastly" in hv.get("server", ""):
        return "Fastly"
    # fallback body checks
    b = (body_text or "").lower()
    if "checking your browser" in b and "cloudflare" in b:
        return "Cloudflare"
    if "sucuri" in b:
        return "Sucuri"
    if "incapsula" in b or "request blocked by incapsula" in b:
        return "Imperva/Incapsula"
    return None

# ---------------------------
# CDN detection (header-based)
# ---------------------------
def detect_cdn_from_headers_and_host(headers: dict, hostname: str = ""):
    hv = {k.lower(): (v or "").lower() for k, v in headers.items()}
    if "cf-ray" in hv or "cf-cache-status" in hv or "cloudflare" in hv.get("server", ""):
        return "Cloudflare"
    if "x-amz-cf-id" in hv or "cloudfront" in hv.get("via", "") or "cloudfront" in hv.get("server", ""):
        return "CloudFront"
    if "x-fastly-request-id" in hv or "fastly" in hv.get("server", ""):
        return "Fastly"
    if any(k.startswith("x-akamai-") for k in hv) or "akamai" in hv.get("server", ""):
        return "Akamai"
    if "bunnycdn" in " ".join(hv.values()) or "bunny" in hv.get("server", ""):
        return "BunnyCDN"
    # generic indicators
    if "via" in hv or "x-cache" in hv or "x-cdn" in hv:
        v = hv.get("via", "") + " " + hv.get("x-cache", "") + " " + hv.get("server", "")
        if "cloudflare" in v:
            return "Cloudflare"
        if "cloudfront" in v or "amazon" in v:
            return "CloudFront"
        if "fastly" in v:
            return "Fastly"
        if "akamai" in v:
            return "Akamai"
    return None

# ---------------------------
# Compact tech detection
# ---------------------------
def detect_tech_from_headers_body_scripts(headers: dict, body_text: str = "", script_srcs=None, meta_generator=""):
    found = []
    hv_values = " ".join((v or "").lower() for v in headers.values())
    body = (body_text or "").lower()
    scripts = " ".join(script_srcs or []).lower()

    # check meta generator first
    mg = (meta_generator or "").lower()
    for tech, pats in COMPACT_TECH.items():
        # header checks
        for ph in pats.get("header", []):
            if ph.lower() in hv_values:
                found.append(tech)
                break
        else:
            # meta
            for pm in pats.get("meta", []):
                if pm.lower() in mg:
                    found.append(tech)
                    break
            # body
            if tech not in found:
                for pb in pats.get("body", []):
                    try:
                        if re.search(pb, body, re.I):
                            found.append(tech)
                            break
                    except re.error:
                        if pb in body:
                            found.append(tech)
                            break
            # script srcs
            if tech not in found:
                for ps in pats.get("script", []):
                    if ps.lower() in scripts:
                        found.append(tech)
                        break

    # dedupe preserve order
    uniq = []
    for x in found:
        if x not in uniq:
            uniq.append(x)
    return uniq

# ---------------------------
# Helper: extract script srcs and meta generator
# ---------------------------
def extract_script_srcs_and_meta(html: str):
    if not html:
        return [], ""
    # scripts
    script_srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I)
    # meta generator
    mg = ""
    m = re.search(r'<meta[^>]+name=["\']generator["\'][^>]*content=["\']([^"\']+)["\']', html, re.I)
    if m:
        mg = m.group(1)
    # some sites put generator without name attr
    if not mg:
        m2 = re.search(r'<meta[^>]+content=["\']([^"\']+)["\'][^>]*name=["\']generator["\']', html, re.I)
        if m2:
            mg = m2.group(1)
    return script_srcs, mg

# ---------------------------
# Normalize URL (ensure scheme)
# ---------------------------
def normalize_url(u: str):
    u = u.strip()
    if not u:
        return None
    p = urlparse(u)
    if not p.scheme:
        return "http://" + u
    return u

# ---------------------------
# Probe logic (smart HTTP/HTTPS auto-switch)
# returns (output_string_or_None, alive_bool)
# ---------------------------
async def probe_url(session, url, flags, sem):
    url = url.strip()
    if not url:
        return None, False

    async with sem:

        async def attempt(target_url):
            start = time.time()
            try:
                resp = await session.get(target_url, allow_redirects=False)
                elapsed = (time.time() - start) * 1000
                return resp, elapsed
            except:
                return None, None

        original_url = url
        parsed = urlparse(url)

        resp, elapsed = None, None

        # If scheme is http (most normalized inputs)
        if parsed.scheme == "http":
            # try HTTP first
            resp, elapsed = await attempt(url)

            # if redirect to https -> switch
            if resp and resp.status in (301, 302, 307, 308):
                loc = resp.headers.get("Location", "")
                if loc and loc.startswith("https://"):
                    url = loc
                    resp, elapsed = await attempt(url)

            # if http ok -> keep
            elif resp:
                pass

            # http failed -> try https://hostname
            else:
                https_url = f"https://{parsed.hostname}"
                resp, elapsed = await attempt(https_url)
                if resp:
                    url = https_url
        else:
            resp, elapsed = await attempt(url)

        if not resp:
            # alive mode -> drop
            if flags.alive:
                return None, False
            # no detail flags -> show URL only
            if not (flags.status_code or flags.response_time or flags.title or flags.ip or flags.server or flags.detect_waf or flags.cdn_check or flags.tech_detect):
                return original_url, False
            return f"{original_url} [ERR]", False

        # Build output
        parts = [url]

        if flags.status_code:
            parts.append(f"[{resp.status}]")

        if flags.response_time:
            parts.append(f"[{elapsed:.1f}ms]")

        # fetch body if needed
        body_text = None
        need_body = flags.title or flags.detect_waf or flags.tech_detect
        if need_body:
            try:
                body_text = await resp.text()
            except:
                body_text = ""

        # title
        if flags.title:
            title = ""
            if body_text:
                m = re.search(r'<title>(.*?)</title>', body_text, re.I | re.S)
                if m:
                    title = m.group(1).strip()
            parts.append(f"[{title if title else 'No-Title'}]")

        if flags.server:
            server = resp.headers.get("Server", "")
            parts.append(f"[Server:{server}]")

        if flags.ip:
            try:
                host = urlparse(url).hostname
                ip = socket.gethostbyname(host)
                parts.append(f"[IP:{ip}]")
            except:
                parts.append("[IP-ERR]")

        # WAF
        if flags.detect_waf:
            waf = detect_waf_from_headers_and_body(resp.headers, body_text or "")
            if waf:
                parts.append(f"[WAF:{waf}]")

        # CDN
        if flags.cdn_check:
            cdn = detect_cdn_from_headers_and_host(resp.headers, urlparse(url).hostname)
            if cdn:
                parts.append(f"[CDN:{cdn}]")

        # Tech detect
        if flags.tech_detect:
            script_srcs, meta_gen = extract_script_srcs_and_meta(body_text or "")
            techs = detect_tech_from_headers_body_scripts(resp.headers, body_text or "", script_srcs, meta_gen)
            if techs:
                parts.append(f"[Tech:{', '.join(techs)}]")

        # Alive filter: treat as alive if response exists (we already did)
        return " ".join(parts), True

# ---------------------------
# Async runner
# ---------------------------
async def async_main(urls, flags):
    timeout = ClientTimeout(total=flags.timeout)
    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE

    sem = asyncio.Semaphore(flags.threads)
    connector = TCPConnector(limit=flags.threads, ssl=ssl_ctx)

    async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
        tasks = [probe_url(session, url, flags, sem) for url in urls]
        for coro in asyncio.as_completed(tasks):
            output, alive = await coro
            if flags.alive and not alive:
                continue
            if output:
                print(output)
            yield output

# ---------------------------
# CLI: improved help layout
# ---------------------------
HELP_TEXT = """Ultra-Fast Async URL Scanner v1

Usage:
  python3 main.py [options]

Input:
  -l, --list FILE            Read input from file (one host/URL per line)
  -u, --target URL [URL...]  Provide one or more targets on the command line
                             (also supports piped input: cat list.txt | python3 main.py)

Scanning Options:
  --alive                    Only display alive sites (drop dead/timeouts)
  -sc, --status-code         Display HTTP status code
  -rt, --response-time       Display response time (ms)
  -title                     Display <title> tag
  -ip                        Display resolved IP address
  -server                    Display server header
  --detect-waf               Detect WAF providers (Cloudflare, Sucuri, Imperva, Akamai...)
  --cdn-check                Detect CDN provider (Cloudflare, CloudFront, Fastly...)
  -td, --tech-detect         Detect technologies in use (compact Wappalyzer dataset)

Performance & Output:
  -t, --threads N            Concurrency (default: 50)
  -timeout N                 Request timeout in seconds (default: 10)
  -o, --output FILE          Save output to file
  -silent                    Disable banner and extra startup text
  -h, --help                 Show this help message
"""

def main():
    parser = argparse.ArgumentParser(add_help=False, formatter_class=argparse.RawTextHelpFormatter, description=HELP_TEXT)
    # input
    parser.add_argument("-l", "--list", help="Input file")
    parser.add_argument("-u", "--target", nargs="*", help="Target(s)")

    # scanning flags
    parser.add_argument("--alive", action="store_true", help="Only show alive hosts")
    parser.add_argument("-sc", "--status-code", action="store_true", help="Show status code")
    parser.add_argument("-rt", "--response-time", action="store_true", help="Show response time")
    parser.add_argument("-title", action="store_true", help="Show <title>")
    parser.add_argument("-ip", action="store_true", help="Show resolved IP")
    parser.add_argument("-server", action="store_true", help="Show server header")
    parser.add_argument("--detect-waf", action="store_true", help="Detect WAF")
    parser.add_argument("--cdn-check", action="store_true", help="Detect CDN")
    parser.add_argument("-td", "--tech-detect", action="store_true", help="Detect technology (compact dataset)")

    # perf & misc
    parser.add_argument("-t", "--threads", type=int, default=50, help="Concurrency")
    parser.add_argument("-timeout", type=int, default=10, help="Timeout seconds")
    parser.add_argument("-o", "--output", help="Save output")
    parser.add_argument("-silent", action="store_true", help="Disable banner/startup text")
    parser.add_argument("-h", "--help", action="store_true", help="Show this help message and exit")

    args = parser.parse_args()

    if args.help:
        print(HELP_TEXT)
        return

    if not args.silent:
        print(BANNER)

    # collect inputs: targets, list, pipe (merge all)
    urls = []
    if args.target:
        urls.extend(args.target)
    if args.list:
        try:
            with open(args.list, "r", encoding="utf-8") as f:
                urls.extend([line.strip() for line in f if line.strip()])
        except Exception as e:
            print(f"Failed to read list file: {e}", file=sys.stderr)
            sys.exit(1)
    if not sys.stdin.isatty():
        urls.extend([line.strip() for line in sys.stdin if line.strip()])

    # normalize + dedupe (preserve order)
    seen = set()
    normalized = []
    for u in urls:
        nu = normalize_url(u)
        if nu and nu not in seen:
            seen.add(nu)
            normalized.append(nu)
    urls = normalized

    if not urls:
        print("No valid URLs provided. Use -l file, -u target, or pipe input.", file=sys.stderr)
        sys.exit(1)

    # attach flags object
    class Flags:
        pass
    flags = Flags()
    flags.alive = args.alive
    flags.status_code = args.status_code
    flags.response_time = args.response_time
    flags.title = args.title
    flags.ip = args.ip
    flags.server = args.server
    flags.detect_waf = args.detect_waf
    flags.cdn_check = args.cdn_check
    flags.tech_detect = args.tech_detect
    flags.threads = args.threads
    flags.timeout = args.timeout

    # run
    async def runner():
        results = []
        async for r in async_main(urls, flags):
            if r:
                results.append(r)
        return results

    results = asyncio.run(runner())

    # save
    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write("\n".join(results))
            if not args.silent:
                print(f"\nSaved output to: {args.output}")
        except Exception as e:
            print(f"Failed to write output: {e}", file=sys.stderr)

if __name__ == "__main__":
    main()
