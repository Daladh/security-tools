#!/usr/bin/env python3
"""
port_scanner.py - Multithreaded TCP port scanner with banner grabbing.

Educational tool. Only scan hosts you own or are explicitly authorized to test.

Usage:
    python port_scanner.py <host> [-p PORTS] [-t THREADS] [--timeout SECONDS]

Examples:
    python port_scanner.py 127.0.0.1
    python port_scanner.py scanme.nmap.org -p 1-1024 -t 200
"""

import argparse
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

# A small set of commonly interesting ports, used when no range is given.
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
    993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443,
]


def parse_ports(spec: str) -> list[int]:
    """Parse a port spec like '80', '1-1024' or '22,80,443' into a list of ints."""
    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            ports.update(range(int(start), int(end) + 1))
        elif part:
            ports.add(int(part))
    return sorted(p for p in ports if 0 < p <= 65535)


def grab_banner(sock: socket.socket) -> str:
    """Try to read a short service banner from an open socket."""
    try:
        sock.settimeout(1.0)
        data = sock.recv(1024)
        return data.decode(errors="replace").strip()
    except OSError:
        return ""


def scan_port(host: str, port: int, timeout: float) -> tuple[int, str] | None:
    """Return (port, banner) if the port is open, else None."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        try:
            if sock.connect_ex((host, port)) == 0:
                return port, grab_banner(sock)
        except OSError:
            pass
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description="Simple multithreaded TCP port scanner.")
    parser.add_argument("host", help="Target hostname or IP address")
    parser.add_argument("-p", "--ports", default=None,
                        help="Port(s): e.g. '80', '1-1024', '22,80,443'. Default: common ports.")
    parser.add_argument("-t", "--threads", type=int, default=100, help="Number of worker threads")
    parser.add_argument("--timeout", type=float, default=0.5, help="Connection timeout in seconds")
    args = parser.parse_args()

    try:
        target_ip = socket.gethostbyname(args.host)
    except socket.gaierror:
        print(f"[!] Could not resolve host: {args.host}", file=sys.stderr)
        return 1

    ports = parse_ports(args.ports) if args.ports else COMMON_PORTS
    print(f"[*] Scanning {args.host} ({target_ip}) - {len(ports)} ports, {args.threads} threads\n")

    open_ports: list[tuple[int, str]] = []
    with ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = {pool.submit(scan_port, target_ip, p, args.timeout): p for p in ports}
        for future in as_completed(futures):
            result = future.result()
            if result:
                port, banner = result
                open_ports.append(result)
                line = f"[+] {port:>5}/tcp  open"
                if banner:
                    line += f"   {banner[:60]!r}"
                print(line)

    print(f"\n[*] Done. {len(open_ports)} open port(s) found.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
