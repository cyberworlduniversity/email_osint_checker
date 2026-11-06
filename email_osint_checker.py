#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║           Email OSINT Checker - Breach Detection Tool        ║
║                  GitHub: hemanathan115                       ║
╚══════════════════════════════════════════════════════════════╝
"""

import re
import sys
import json
import time
import hashlib
import argparse
import os
import urllib.request
import urllib.error
from datetime import datetime

# ─────────────────────────────────────────────
#  BANNER
# ─────────────────────────────────────────────
BANNER = r"""
 ███████╗███╗   ███╗ █████╗ ██╗██╗      ██████╗ ███████╗██╗███╗   ██╗████████╗
 ██╔════╝████╗ ████║██╔══██╗██║██║     ██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝
 █████╗  ██╔████╔██║███████║██║██║     ██║   ██║███████╗██║██╔██╗ ██║   ██║   
 ██╔══╝  ██║╚██╔╝██║██╔══██║██║██║     ██║   ██║╚════██║██║██║╚██╗██║   ██║   
 ███████╗██║ ╚═╝ ██║██║  ██║██║███████╗╚██████╔╝███████║██║██║ ╚████║   ██║   
 ╚══════╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝╚══════╝ ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝   
                                                                                 
  ██████╗ ███████╗██╗███╗   ██╗████████╗     ██████╗██╗  ██╗███████╗ ██████╗██╗  ██╗███████╗██████╗ 
 ██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝    ██╔════╝██║  ██║██╔════╝██╔════╝██║ ██╔╝██╔════╝██╔══██╗
 ██║   ██║███████╗██║██╔██╗ ██║   ██║       ██║     ███████║█████╗  ██║     █████╔╝ █████╗  ██████╔╝
 ██║   ██║╚════██║██║██║╚██╗██║   ██║       ██║     ██╔══██║██╔══╝  ██║     ██╔═██╗ ██╔══╝  ██╔══██╗
 ╚██████╔╝███████║██║██║ ╚████║   ██║       ╚██████╗██║  ██║███████╗╚██████╗██║  ██╗███████╗██║  ██║
  ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝        ╚═════╝╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝

  [ Email OSINT Breach Checker v1.0 ]  |  GitHub: hemanathan115
"""

# ─────────────────────────────────────────────
#  COLORS
# ─────────────────────────────────────────────
class Colors:
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    BOLD    = "\033[1m"
    RESET   = "\033[0m"

def c(color, text):
    return f"{color}{text}{Colors.RESET}"

# ─────────────────────────────────────────────
#  VALIDATORS
# ─────────────────────────────────────────────
def is_valid_email(email: str) -> bool:
    pattern = r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))

# ─────────────────────────────────────────────
#  SHA-1 HASH (for HIBP password check style)
# ─────────────────────────────────────────────
def sha1_hash(text: str) -> str:
    return hashlib.sha1(text.encode('utf-8')).hexdigest().upper()

def md5_hash(text: str) -> str:
    return hashlib.md5(text.encode('utf-8')).hexdigest()

# ─────────────────────────────────────────────
#  HAVE I BEEN PWNED — Email Check (v3 API)
# ─────────────────────────────────────────────
def check_hibp(email: str, api_key: str = None) -> dict:
    """
    Check HaveIBeenPwned for email breaches.
    Requires a paid API key for the /breachedaccount endpoint.
    Returns simulated/demo response if no key provided.
    """
    result = {
        "source": "HaveIBeenPwned (HIBP)",
        "url": "https://haveibeenpwned.com",
        "checked": True,
        "breached": None,
        "details": [],
        "note": ""
    }

    if not api_key:
        result["checked"] = False
        result["note"] = (
            "HIBP v3 requires a paid API key. "
            "Get yours at https://haveibeenpwned.com/API/Key"
        )
        return result

    try:
        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{urllib.parse.quote(email)}?truncateResponse=false"
        req = urllib.request.Request(url)
        req.add_header("hibp-api-key", api_key)
        req.add_header("User-Agent", "EmailOSINTChecker/1.0 (github.com/hemanathan115)")
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
            result["breached"] = True
            result["details"] = [
                {
                    "name": b.get("Name"),
                    "domain": b.get("Domain"),
                    "breach_date": b.get("BreachDate"),
                    "pwn_count": b.get("PwnCount"),
                    "data_classes": b.get("DataClasses", [])
                }
                for b in data
            ]
    except urllib.error.HTTPError as e:
        if e.code == 404:
            result["breached"] = False
            result["note"] = "No breaches found."
        elif e.code == 401:
            result["checked"] = False
            result["note"] = "Invalid HIBP API key."
        else:
            result["checked"] = False
            result["note"] = f"HTTP Error {e.code}"
    except Exception as ex:
        result["checked"] = False
        result["note"] = str(ex)

    return result

# ─────────────────────────────────────────────
#  DEHASHED API CHECK
# ─────────────────────────────────────────────
def check_dehashed(email: str, api_key: str = None, username: str = None) -> dict:
    result = {
        "source": "DeHashed",
        "url": "https://dehashed.com",
        "checked": False,
        "breached": None,
        "details": [],
        "note": ""
    }

    if not api_key or not username:
        result["note"] = (
            "DeHashed requires API key + account email. "
            "Sign up at https://dehashed.com"
        )
        return result

    try:
        import base64
        credentials = base64.b64encode(f"{username}:{api_key}".encode()).decode()
        url = f"https://api.dehashed.com/search?query=email:{urllib.parse.quote(email)}&size=5"
        req = urllib.request.Request(url)
        req.add_header("Authorization", f"Basic {credentials}")
        req.add_header("Accept", "application/json")
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
            entries = data.get("entries") or []
            result["checked"] = True
            result["breached"] = len(entries) > 0
            result["details"] = [
                {
                    "id": e.get("id"),
                    "database_name": e.get("database_name"),
                    "username": e.get("username"),
                    "password_hash_present": bool(e.get("hashed_password")),
                    "obtained_from": e.get("obtained_from")
                }
                for e in entries[:5]
            ]
    except Exception as ex:
        result["note"] = str(ex)

    return result

# ─────────────────────────────────────────────
#  EMAIL REP CHECK (emailrep.io — free tier)
# ─────────────────────────────────────────────
def check_emailrep(email: str) -> dict:
    result = {
        "source": "EmailRep.io",
        "url": "https://emailrep.io",
        "checked": False,
        "breached": None,
        "details": {},
        "note": ""
    }
    try:
        url = f"https://emailrep.io/{urllib.parse.quote(email)}"
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "EmailOSINTChecker/1.0 (github.com/hemanathan115)")
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
            result["checked"] = True
            result["breached"] = data.get("details", {}).get("data_breach", False)
            result["details"] = {
                "reputation":      data.get("reputation"),
                "suspicious":      data.get("suspicious"),
                "references":      data.get("references"),
                "blacklisted":     data.get("details", {}).get("blacklisted"),
                "malicious_activity": data.get("details", {}).get("malicious_activity"),
                "credentials_leaked": data.get("details", {}).get("credentials_leaked"),
                "data_breach":     data.get("details", {}).get("data_breach"),
                "first_seen":      data.get("details", {}).get("first_seen"),
                "last_seen":       data.get("details", {}).get("last_seen"),
                "domain_reputation": data.get("details", {}).get("domain_reputation"),
                "profiles":        data.get("details", {}).get("profiles", [])
            }
    except urllib.error.HTTPError as e:
        result["note"] = f"HTTP {e.code} - may need API key for higher rate limits"
    except Exception as ex:
        result["note"] = str(ex)

    return result

# ─────────────────────────────────────────────
#  LEAKCHECK.IO (free tier available)
# ─────────────────────────────────────────────
def check_leakcheck(email: str, api_key: str = None) -> dict:
    result = {
        "source": "LeakCheck.io",
        "url": "https://leakcheck.io",
        "checked": False,
        "breached": None,
        "details": [],
        "note": ""
    }
    if not api_key:
        result["note"] = "Requires API key. Sign up free at https://leakcheck.io"
        return result
    try:
        url = f"https://leakcheck.io/api/public?key={api_key}&check={urllib.parse.quote(email)}"
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "EmailOSINTChecker/1.0")
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
            result["checked"] = True
            if data.get("success"):
                sources = data.get("sources", [])
                result["breached"] = len(sources) > 0
                result["details"] = sources
            else:
                result["note"] = data.get("error", "Unknown error")
    except Exception as ex:
        result["note"] = str(ex)
    return result

# ─────────────────────────────────────────────
#  LOCAL ANALYSIS (no API, instant)
# ─────────────────────────────────────────────
def local_analysis(email: str) -> dict:
    """Perform local heuristic analysis of the email address."""
    local, domain = email.lower().rsplit("@", 1)

    disposable_domains = {
        "mailinator.com", "guerrillamail.com", "10minutemail.com", "temp-mail.org",
        "throwaway.email", "fakeinbox.com", "maildrop.cc", "yopmail.com",
        "trashmail.com", "dispostable.com", "mailnull.com", "spamgourmet.com",
        "trashmail.net", "spamfree24.org", "0-mail.com", "discard.email",
        "sharklasers.com", "guerrillamailblock.com", "grr.la", "spam4.me"
    }

    suspicious_patterns = [
        r'\d{6,}',            # long number sequences
        r'[a-z]{20,}',        # very long random strings
        r'^(test|temp|fake|noreply|admin|user)\d*$'
    ]

    flags = []
    risk = "LOW"

    if domain in disposable_domains:
        flags.append("⚠️  Disposable/temporary email domain detected")
        risk = "HIGH"

    for pattern in suspicious_patterns:
        if re.search(pattern, local):
            flags.append(f"⚠️  Suspicious local-part pattern: {pattern}")
            risk = "MEDIUM" if risk == "LOW" else risk

    if len(local) < 3:
        flags.append("⚠️  Very short local-part (possible throwaway)")
        risk = "MEDIUM" if risk == "LOW" else risk

    # Generate hashes for reference
    sha1  = sha1_hash(email)
    md5   = md5_hash(email)

    return {
        "source": "Local Heuristic Analysis",
        "email": email,
        "domain": domain,
        "local_part": local,
        "risk_level": risk,
        "flags": flags if flags else ["✅ No suspicious patterns detected"],
        "hashes": {
            "md5":  md5,
            "sha1": sha1
        }
    }

# ─────────────────────────────────────────────
#  PRINTER HELPERS
# ─────────────────────────────────────────────
SEP = c(Colors.CYAN, "─" * 65)

def print_banner():
    print(c(Colors.CYAN, BANNER))

def print_section(title: str):
    print(f"\n{SEP}")
    print(c(Colors.BOLD + Colors.MAGENTA, f"  🔍 {title}"))
    print(SEP)

def print_result(result: dict):
    src    = result.get("source", "Unknown")
    url    = result.get("url", "")
    ok     = result.get("checked", False)
    breach = result.get("breached")
    note   = result.get("note", "")

    print(f"\n  {c(Colors.BOLD, src)}  {c(Colors.BLUE, url)}")

    if not ok:
        print(f"  {c(Colors.YELLOW, '⚠️  Skipped:')} {note or 'API key not configured'}")
        return

    if breach is True:
        print(f"  {c(Colors.RED, '🚨 BREACHED — Email found in leaked data!')}")
    elif breach is False:
        print(f"  {c(Colors.GREEN, '✅ Clean — No breaches found.')}")
    else:
        print(f"  {c(Colors.YELLOW, '❓ Status unknown')}")

    if note:
        print(f"  {c(Colors.YELLOW, 'Note:')} {note}")

    details = result.get("details")
    if isinstance(details, list) and details:
        print(f"\n  {c(Colors.BOLD, 'Breach Details:')}")
        for i, d in enumerate(details[:5], 1):
            if isinstance(d, dict):
                name = d.get("name") or d.get("database_name") or d.get("source") or "Unknown"
                date = d.get("breach_date") or d.get("date") or "N/A"
                data_classes = ", ".join(d.get("data_classes", [])) or "N/A"
                print(f"  [{i}] {c(Colors.RED, name)} | Date: {date} | Data: {data_classes}")
            else:
                print(f"  [{i}] {d}")

    elif isinstance(details, dict) and details:
        print(f"\n  {c(Colors.BOLD, 'Details:')}")
        for k, v in details.items():
            if v is not None and v != [] and v != "":
                label = k.replace("_", " ").title()
                val   = ", ".join(v) if isinstance(v, list) else str(v)
                color = Colors.RED if v is True else Colors.GREEN if v is False else Colors.WHITE
                print(f"  • {c(Colors.CYAN, label)}: {c(color, val)}")

def print_local(analysis: dict):
    print(f"\n  {c(Colors.BOLD, 'Email:')}     {analysis['email']}")
    print(f"  {c(Colors.BOLD, 'Domain:')}    {analysis['domain']}")
    print(f"  {c(Colors.BOLD, 'Risk:')}      {c(Colors.RED if analysis['risk_level']=='HIGH' else Colors.YELLOW if analysis['risk_level']=='MEDIUM' else Colors.GREEN, analysis['risk_level'])}")
    print(f"\n  {c(Colors.BOLD, 'Flags:')}")
    for flag in analysis["flags"]:
        print(f"    {flag}")
    print(f"\n  {c(Colors.BOLD, 'Hashes (for cross-reference):')}")
    print(f"    MD5 : {c(Colors.CYAN, analysis['hashes']['md5'])}")
    print(f"    SHA1: {c(Colors.CYAN, analysis['hashes']['sha1'])}")

# ─────────────────────────────────────────────
#  SAVE REPORT
# ─────────────────────────────────────────────
def save_report(email: str, results: list, local: dict, output_file: str = None):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_email = email.replace("@", "_at_").replace(".", "_")
    filename   = output_file or f"breach_report_{safe_email}_{timestamp}.json"

    report = {
        "tool": "Email OSINT Checker",
        "author": "hemanathan115",
        "github": "https://github.com/hemanathan115",
        "timestamp": datetime.now().isoformat(),
        "target_email": email,
        "local_analysis": local,
        "api_results": results
    }

    with open(filename, "w") as f:
        json.dump(report, f, indent=2)

    print(f"\n{c(Colors.GREEN, '💾 Report saved:')} {c(Colors.CYAN, filename)}")
    return filename

# ─────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Email OSINT Checker — Breach Detection Tool",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("email",
        nargs="?",
        help="Target email address to check")
    parser.add_argument("--dehashed-user",
        default=None,
        metavar="EMAIL",
        help="Your DeHashed account email")
    parser.add_argument("--output",
        default=None,
        metavar="FILE",
        help="Save JSON report to this file")
    parser.add_argument("--no-banner",
        action="store_true",
        help="Suppress ASCII banner")
    parser.add_argument("--batch",
        metavar="FILE",
        help="Check multiple emails from a text file (one per line)")

    args = parser.parse_args()

    if not args.no_banner:
        print_banner()

    emails_to_check = []

    if args.batch:
        try:
            with open(args.batch) as f:
                emails_to_check = [line.strip() for line in f if line.strip()]
            print(c(Colors.CYAN, f"\n📋 Loaded {len(emails_to_check)} emails from {args.batch}"))
        except FileNotFoundError:
            print(c(Colors.RED, f"❌ File not found: {args.batch}"))
            sys.exit(1)
    elif args.email:
        emails_to_check = [args.email]
    else:
        print(c(Colors.CYAN, "\n  Enter email(s) to check (comma-separated or single):"))
        raw = input(c(Colors.YELLOW, "  ➤ Email: ")).strip()
        emails_to_check = [e.strip() for e in raw.split(",")]

    for email in emails_to_check:
        if not is_valid_email(email):
            print(c(Colors.RED, f"\n  ❌ Invalid email format: {email}"))
            continue

        print(f"\n{c(Colors.BOLD + Colors.WHITE, '═'*65)}")
        print(c(Colors.BOLD + Colors.CYAN, f"  TARGET: {email}"))
        print(c(Colors.BOLD + Colors.WHITE, '═'*65))

        # 1. Local Analysis
        print_section("Local Heuristic Analysis")
        local = local_analysis(email)
        print_local(local)

        # 2. EmailRep.io (free)
        print_section("EmailRep.io — Reputation & Breach Check")
        time.sleep(1)
        emailrep_result = check_emailrep(email)
        print_result(emailrep_result)

        # 3. HIBP
        print_section("HaveIBeenPwned (HIBP)")
        hibp_result = check_hibp(email, api_key=os.environ.get('HIBP_API_KEY'))
        print_result(hibp_result)

        # 4. DeHashed
        print_section("DeHashed")
        dh_result = check_dehashed(email, api_key=os.environ.get('DEHASHED_API_KEY'), username=args.dehashed_user)
        print_result(dh_result)

        # 5. LeakCheck
        print_section("LeakCheck.io")
        lc_result = check_leakcheck(email, api_key=os.environ.get('LEAKCHECK_API_KEY'))
        print_result(lc_result)

        # Save report
        all_results = [emailrep_result, hibp_result, dh_result, lc_result]
        save_report(email, all_results, local, args.output)

        print(f"\n{c(Colors.BOLD + Colors.GREEN, '  ✅ Scan complete for: ' + email)}\n")

    print(c(Colors.CYAN, "\n  [ Tool by hemanathan115 | github.com/hemanathan115 ]\n"))

if __name__ == "__main__":
    # Fix missing import for batch mode URL encoding
    try:
        from urllib.parse import quote as _q
    except ImportError:
        pass
    import urllib.parse
    main()
