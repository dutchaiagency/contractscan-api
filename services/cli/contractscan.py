#!/usr/bin/env python3
"""
ContractScan CLI — Scan smart contracts from the command line.

Usage:
    python contractscan.py 0xADDRESS [--chain base] [--deep --tx-hash 0x...]

Install: pip install web3 requests
"""

import argparse
import json
import sys
import os

# Try local import first, then fall back to API
def scan_local(address, chain, mode="basic"):
    try:
        sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
        from scanner_core import basic_scan, deep_scan
        if mode == "deep":
            return deep_scan(address, chain)
        return basic_scan(address, chain)
    except ImportError:
        return None

def scan_api(address, chain, mode="basic", tx_hash=None, api_url=None):
    import requests
    if not api_url:
        api_url = os.environ.get("CONTRACTSCAN_API", "https://dutchaiagency.github.io/contractscan-api/")
        # Try to detect running local server
        try:
            r = requests.get("http://localhost:4020/chains", timeout=2)
            if r.ok:
                api_url = "http://localhost:4020"
        except Exception:
            pass

    url = f"{api_url}/scan?address={address}&chain={chain}&mode={mode}"
    if tx_hash:
        url += f"&tx_hash={tx_hash}"

    r = requests.get(url, timeout=30)
    return r.json()


def colorize_risk(score):
    if score >= 60:
        return f"\033[91mHIGH RISK ({score}/100)\033[0m"
    elif score >= 30:
        return f"\033[93mMEDIUM RISK ({score}/100)\033[0m"
    else:
        return f"\033[92mLOW RISK ({score}/100)\033[0m"


def print_report(result):
    if "error" in result:
        print(f"\033[91mError:\033[0m {result['error']}")
        return

    addr = result.get("address", "?")
    chain = result.get("chain", "?")
    score = result.get("risk_score", 0)

    print(f"\n\033[1m{'=' * 60}\033[0m")
    print(f"\033[1mContractScan Report\033[0m")
    print(f"\033[1m{'=' * 60}\033[0m")
    print(f"Address: {addr}")
    print(f"Chain:   {chain}")
    print(f"Risk:    {colorize_risk(score)}")

    if result.get("is_proxy"):
        impl = result.get("proxy_impl", "unknown")
        print(f"\033[93mProxy:\033[0m  Yes (impl: {impl})")

    token = result.get("token_info", {})
    if token:
        name = token.get("name", "")
        symbol = token.get("symbol", "")
        if name or symbol:
            print(f"Token:   {name} ({symbol})")

    owner = result.get("ownership", {})
    if owner:
        o = owner.get("owner", "")
        if o and o != "0x" + "0" * 40:
            print(f"Owner:   {o}")

    flags = result.get("risk_flags", [])
    if flags:
        print(f"\n\033[93mRisk Flags:\033[0m")
        for f in flags:
            print(f"  - {f}")

    vulns = result.get("vulnerabilities", [])
    if vulns:
        print(f"\n\033[91mVulnerabilities (deep scan):\033[0m")
        for v in vulns:
            sev = v.get("severity", "?")
            name = v.get("name", "?")
            count = v.get("matches", 0)
            color = "\033[91m" if sev == "CRITICAL" else "\033[93m" if sev == "HIGH" else "\033[33m"
            print(f"  {color}[{sev}]\033[0m {name} ({count} matches)")

    safety = result.get("safety_features", [])
    if safety:
        print(f"\n\033[92mSafety Features:\033[0m")
        for s in safety:
            print(f"  + {s}")

    print(f"\n\033[1m{'=' * 60}\033[0m")


def main():
    parser = argparse.ArgumentParser(
        description="ContractScan — Smart contract security scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="GitHub: https://github.com/dutchaiagency/contractscan-api"
    )
    parser.add_argument("address", help="Contract address (0x...)")
    parser.add_argument("--chain", default="ethereum",
                        choices=["ethereum", "base", "arbitrum", "polygon", "bsc", "optimism"],
                        help="Blockchain (default: ethereum)")
    parser.add_argument("--deep", action="store_true", help="Deep scan with source code analysis ($2 USDC)")
    parser.add_argument("--tx-hash", help="Payment tx hash for deep scan")
    parser.add_argument("--api", help="API URL (default: auto-detect local or public)")
    parser.add_argument("--json", action="store_true", help="Output raw JSON")

    args = parser.parse_args()

    mode = "deep" if args.deep else "basic"

    if args.deep and not args.tx_hash:
        print("Deep scan requires payment. Send $2 USDC on Base to:")
        print("  0x8C0083EE1a611c917E3652a14f9Ab5c3a23948D3")
        print("Then pass --tx-hash 0xYOUR_TX_HASH")
        sys.exit(1)

    # Try local scanner first
    result = scan_local(args.address, args.chain, mode)
    if result is None:
        try:
            result = scan_api(args.address, args.chain, mode, args.tx_hash, args.api)
        except Exception as e:
            print(f"Error connecting to API: {e}")
            sys.exit(1)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print_report(result)


if __name__ == "__main__":
    main()
