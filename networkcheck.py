#!/usr/bin/env python3
"""
network_check.py - check DNS resolution and TCP reachability of hosts.

For every target the script:
  1. resolves the name via DNS,
  2. tries to open a TCP connection to the port,
  3. measures how long the connection took.

Targets look like  host  or  host:port  (default port is 443).

Examples:
    python3 network_check.py google.com github.com:443 example.com:53
    python3 network_check.py --file hosts.txt --csv report.csv
    python3 network_check.py router.local:22 --timeout 1.5

hosts.txt example (lines starting with # are ignored):
    # my lab
    router.local:22
    server.local:80
    example.com
"""

import argparse
import csv
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor

DEFAULT_PORT = 443


def parse_target(line: str, default_port: int):
    """Turn 'host' or 'host:port' into (host, port). Returns None for empty/comment lines."""
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    host, _, port_text = line.partition(":")
    port = int(port_text) if port_text else default_port
    if not host or not 1 <= port <= 65535:
        raise ValueError(f"bad target: {line!r}")
    return host, port


def check(host: str, port: int, timeout: float) -> dict:
    """Check one target and return the result as a dict."""
    result = {"host": host, "port": port, "ip": "-", "status": "", "latency_ms": ""}

    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        result["status"] = "DNS FAIL"
        return result
    result["ip"] = ip

    start = time.perf_counter()
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            result["latency_ms"] = round((time.perf_counter() - start) * 1000, 1)
            result["status"] = "OPEN"
    except TimeoutError:
        result["status"] = "TIMEOUT"
    except ConnectionRefusedError:
        result["status"] = "REFUSED"
    except OSError:
        result["status"] = "ERROR"
    return result


def print_table(results: list) -> None:
    print(f"{'HOST':<28}{'PORT':<7}{'IP':<17}{'STATUS':<10}LATENCY")
    print("-" * 70)
    for r in results:
        latency = f"{r['latency_ms']} ms" if r["latency_ms"] != "" else "-"
        print(f"{r['host']:<28}{r['port']:<7}{r['ip']:<17}{r['status']:<10}{latency}")


def save_csv(results: list, path: str) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["host", "port", "ip", "status", "latency_ms"])
        writer.writeheader()
        writer.writerows(results)
    print(f"\nSaved report to {path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="DNS + TCP reachability checker")
    parser.add_argument("targets", nargs="*", help="host or host:port")
    parser.add_argument("-f", "--file", help="text file with one target per line")
    parser.add_argument("-p", "--port", type=int, default=DEFAULT_PORT,
                        help=f"default port (default: {DEFAULT_PORT})")
    parser.add_argument("-t", "--timeout", type=float, default=3.0,
                        help="connection timeout in seconds (default: 3)")
    parser.add_argument("--csv", metavar="FILE", help="save results to a CSV file")
    args = parser.parse_args()

    lines = list(args.targets)
    if args.file:
        try:
            with open(args.file, encoding="utf-8") as f:
                lines += f.read().splitlines()
        except OSError as error:
            sys.exit(f"Error: cannot read {args.file}: {error}")

    targets = []
    for line in lines:
        try:
            parsed = parse_target(line, args.port)
        except ValueError as error:
            sys.exit(f"Error: {error}")
        if parsed:
            targets.append(parsed)

    if not targets:
        parser.error("no targets given (pass hosts or use --file)")

    # Check all targets in parallel so one slow host doesn't block the rest.
    with ThreadPoolExecutor(max_workers=20) as pool:
        results = list(pool.map(lambda t: check(t[0], t[1], args.timeout), targets))

    print_table(results)
    if args.csv:
        save_csv(results, args.csv)

    failed = sum(r["status"] != "OPEN" for r in results)
    print(f"\n{len(results) - failed}/{len(results)} reachable")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
