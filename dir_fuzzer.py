#!/usr/bin/env python3
"""
dir_fuzzer.py — Directory / path discovery tool for web servers.

Sends requests for each word in a wordlist and reports paths that exist,
filtered by HTTP status code. Educational tool — only use against web
applications you own or are explicitly authorized to test.

Usage:
    python dir_fuzzer.py <base_url> -w <wordlist> [-x STATUSES] [-t THREADS]

Examples:
    python dir_fuzzer.py http://localhost:3000 -w wordlist.txt
    python dir_fuzzer.py http://localhost:3000 -w wordlist.txt -x 200,301,302,401,403
"""

import argparse
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
except ImportError:
    print("[!] This tool needs 'requests'. Install it with: pip install requests", file=sys.stderr)
    raise SystemExit(1)

DEFAULT_STATUSES = {200, 204, 301, 302, 307, 401, 403}


def load_wordlist(path: str) -> list[str]:
    """Read a wordlist file, ignoring blank lines and comments."""
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        return [line.strip() for line in fh
                if line.strip() and not line.startswith("#")]


def check_path(session: requests.Session, base_url: str, word: str,
               statuses: set[int], timeout: float) -> tuple[str, int] | None:
    """Return (url, status) if the path returns an interesting status code."""
    url = f"{base_url.rstrip('/')}/{word.lstrip('/')}"
    try:
        resp = session.get(url, timeout=timeout, allow_redirects=False)
    except requests.RequestException:
        return None
    if resp.status_code in statuses:
        return url, resp.status_code
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description="Wordlist-based web directory fuzzer.")
    parser.add_argument("base_url", help="Base URL, e.g. http://localhost:3000")
    parser.add_argument("-w", "--wordlist", required=True, help="Path to a wordlist file")
    parser.add_argument("-x", "--statuses", default=None,
                        help="Comma-separated status codes to report (default: common ones)")
    parser.add_argument("-t", "--threads", type=int, default=20, help="Number of worker threads")
    parser.add_argument("--timeout", type=float, default=5.0, help="Request timeout in seconds")
    args = parser.parse_args()

    statuses = ({int(s) for s in args.statuses.split(",")}
                if args.statuses else DEFAULT_STATUSES)

    try:
        words = load_wordlist(args.wordlist)
    except OSError as exc:
        print(f"[!] Could not read wordlist: {exc}", file=sys.stderr)
        return 1

    print(f"[*] Fuzzing {args.base_url} — {len(words)} words, "
          f"reporting statuses {sorted(statuses)}\n")

    found = 0
    session = requests.Session()
    session.headers.update({"User-Agent": "daladh-dir-fuzzer/1.0"})

    with ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = [pool.submit(check_path, session, args.base_url, w, statuses, args.timeout)
                   for w in words]
        for future in as_completed(futures):
            result = future.result()
            if result:
                url, status = result
                found += 1
                print(f"[+] {status}  {url}")

    print(f"\n[*] Done. {found} path(s) found.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
