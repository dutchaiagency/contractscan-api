"""
Smart Contract Scanner — x402 Paid API

AI agents and users can pay per API call using stablecoins via x402 protocol.
No accounts needed — just a wallet address.

Run: python server.py
"""

import json
import os
import re
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

# Add project root for imports
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, PROJECT_ROOT)
from services.scanner_core import basic_scan, deep_scan, RPC_URLS
from services.payment_verify import (
    DEEP_SCAN_PRICE_USDC,
    WALLET_ADDRESS,
    append_payment_log,
    verify_deep_scan_payment,
)

PORT = int(os.environ.get("PORT", "4020"))


class ScannerHandler(BaseHTTPRequestHandler):
    def _send_json(self, status: int, data: dict):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(data, indent=2).encode())

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        params = parse_qs(parsed.query)

        if path == "/":
            # Serve landing page
            html_path = os.path.join(os.path.dirname(__file__), "index.html")
            if os.path.exists(html_path):
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                with open(html_path, "rb") as f:
                    self.wfile.write(f.read())
                return
            self._send_json(200, {
                "service": "Smart Contract Security Scanner",
                "version": "1.0.0",
                "endpoints": {
                    "GET /scan?address=0x...&chain=ethereum": "Basic scan (free)",
                    "GET /scan?address=0x...&chain=ethereum&mode=deep&tx_hash=0x...": "Deep scan with source code analysis ($2 USDC)",
                    "GET /chains": "List supported chains",
                },
                "payment_address": WALLET_ADDRESS,
            })
            return

        if path == "/api":
            self._send_json(200, {
                "service": "Smart Contract Security Scanner",
                "version": "1.0.0",
                "endpoints": {
                    "GET /scan?address=0x...&chain=ethereum": "Basic scan (free)",
                    "GET /scan?address=0x...&chain=ethereum&mode=deep&tx_hash=0x...": "Deep scan with source code analysis ($2 USDC)",
                    "GET /chains": "List supported chains",
                },
                "payment_address": WALLET_ADDRESS,
                "payment_network": "Base",
                "payment_token": "USDC",
                "deep_scan_price_usdc": DEEP_SCAN_PRICE_USDC,
            })
            return

        if path == "/chains":
            self._send_json(200, {"chains": list(RPC_URLS.keys())})
            return

        if path == "/scan":
            address = params.get("address", [None])[0]
            chain = params.get("chain", ["ethereum"])[0]
            mode = params.get("mode", ["basic"])[0]
            tx_hash = params.get("tx_hash", [None])[0]

            if not address or not re.match(r"^0x[a-fA-F0-9]{40}$", address):
                self._send_json(400, {"error": "Invalid address. Must be 0x + 40 hex chars."})
                return

            try:
                payment = None
                if mode == "deep":
                    payment_ok, payment = verify_deep_scan_payment(tx_hash)
                    if not payment_ok:
                        preview = basic_scan(address, chain)
                        self._send_json(402, {
                            **payment,
                            "payment": {
                                "network": "Base",
                                "token": "USDC",
                                "amount": DEEP_SCAN_PRICE_USDC,
                                "to": WALLET_ADDRESS,
                                "tx_hash_param": "tx_hash",
                            },
                            "basic_preview": preview if preview and "error" not in preview else None,
                        })
                        return

                scan_fn = deep_scan if mode == "deep" else basic_scan
                result = scan_fn(address, chain)
                if result is None:
                    for c in RPC_URLS:
                        if c != chain:
                            result = scan_fn(address, c)
                            if result and "error" not in result:
                                break

                if result is None:
                    self._send_json(404, {"error": "No contract found at this address"})
                elif "error" in result:
                    self._send_json(500, result)
                else:
                    if payment:
                        append_payment_log(payment, "x402-api deep scan payment")
                        result["payment_verified"] = {
                            "network": "Base",
                            "token": "USDC",
                            "amount": payment["amount_usdc"],
                            "tx_hash": payment["tx_hash"],
                        }
                    self._send_json(200, result)
            except Exception as e:
                self._send_json(500, {"error": str(e)})
            return

        self._send_json(404, {"error": "Not found"})

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "*")
        self.end_headers()


def main():
    server = HTTPServer(("0.0.0.0", PORT), ScannerHandler)
    print(f"Scanner API running on http://localhost:{PORT}")
    print(f"Wallet: {WALLET_ADDRESS}")
    print(f"Try: http://localhost:{PORT}/scan?address=0xdAC17F958D2ee523a2206206994597C13D831ec7")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
        server.server_close()


if __name__ == "__main__":
    main()
