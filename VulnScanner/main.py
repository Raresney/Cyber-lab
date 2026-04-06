#!/usr/bin/env python3
"""
VulnScanner - Web Vulnerability Scanner
Usage: python main.py <target_url> [options]

For authorized security testing only.
"""

import argparse
import sys
import warnings

# Suppress SSL warnings for testing
warnings.filterwarnings("ignore", message="Unverified HTTPS request")

from scanner.core import VulnScanner


def main():
    parser = argparse.ArgumentParser(
        description="VulnScanner - Web Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py http://localhost:5000
  python main.py http://target.com -m sqli xss
  python main.py http://target.com -v -o json
  python main.py http://target.com --threads 20 --depth 5

Modules: sqli, xss, traversal, headers, dirbrute
        """,
    )

    parser.add_argument(
        "target",
        help="Target URL to scan (e.g., http://localhost:5000)",
    )
    parser.add_argument(
        "-m", "--modules",
        nargs="+",
        choices=["sqli", "xss", "traversal", "headers", "dirbrute"],
        help="Specific modules to run (default: all)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="count",
        default=1,
        help="Increase verbosity (-v, -vv)",
    )
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Minimal output",
    )
    parser.add_argument(
        "-o", "--output",
        choices=["html", "json"],
        default="html",
        help="Report format (default: html)",
    )
    parser.add_argument(
        "-c", "--config",
        default="config.yaml",
        help="Path to config file (default: config.yaml)",
    )
    parser.add_argument(
        "--threads",
        type=int,
        help="Number of threads (overrides config)",
    )
    parser.add_argument(
        "--depth",
        type=int,
        help="Crawler depth (overrides config)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        help="Request timeout in seconds (overrides config)",
    )
    parser.add_argument(
        "--no-crawl",
        action="store_true",
        help="Skip crawling, only scan the provided URL",
    )

    args = parser.parse_args()

    if args.quiet:
        args.verbose = 0

    # Initialize scanner
    scanner = VulnScanner(config_path=args.config, verbose=args.verbose)

    # Apply CLI overrides
    if args.output:
        scanner.config["reporting"]["format"] = args.output
    if args.threads:
        scanner.config["scanner"]["threads"] = args.threads
    if args.depth:
        scanner.config["scanner"]["max_depth"] = args.depth
    if args.timeout:
        scanner.config["scanner"]["timeout"] = args.timeout
    if args.no_crawl:
        scanner.config["scanner"]["max_depth"] = 0
        scanner.config["scanner"]["max_pages"] = 1

    # Module name mapping for CLI
    module_map = {
        "sqli": "SQLi",
        "xss": "XSS",
        "traversal": "Path Traversal",
        "headers": "Security Headers",
        "dirbrute": "Dir Bruteforce",
    }

    modules = None
    if args.modules:
        modules = [module_map.get(m, m) for m in args.modules]

    # Run scan
    try:
        result = scanner.scan(args.target, modules=modules)
        sys.exit(1 if result.vulnerabilities else 0)
    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user.")
        sys.exit(130)
    except Exception as e:
        print(f"\n[ERROR] {e}")
        if args.verbose >= 2:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
