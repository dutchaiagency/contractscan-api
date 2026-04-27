"""Verify Base USDC payments for paid scanner features."""

import json
import os
import re
import urllib.request
from datetime import datetime, timezone


PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

WALLET_ADDRESS = "0x8C0083EE1a611c917E3652a14f9Ab5c3a23948D3"
BASE_RPC_URL = os.environ.get("BASE_RPC_URL", "https://mainnet.base.org")
BASE_USDC_ADDRESS = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"
DEEP_SCAN_PRICE_USDC = 2
USDC_DECIMALS = 6
TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
PAYMENT_LOG = os.path.join(PROJECT_ROOT, "evidence", "deep_scan_payments.jsonl")
INCOME_CSV = os.path.join(PROJECT_ROOT, "evidence", "income.csv")


def _rpc(method: str, params: list) -> dict:
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(
        BASE_RPC_URL,
        data=payload,
        headers={"Content-Type": "application/json", "User-Agent": "ContractScanner/1.0"},
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        data = json.loads(resp.read().decode())
    if data.get("error"):
        raise RuntimeError(data["error"].get("message", "RPC error"))
    return data.get("result")


def used_payment_hashes() -> set[str]:
    if not os.path.exists(PAYMENT_LOG):
        return set()
    used = set()
    with open(PAYMENT_LOG, "r", encoding="utf-8") as f:
        for line in f:
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            tx_hash = row.get("tx_hash")
            if tx_hash:
                used.add(tx_hash.lower())
    return used


def append_payment_log(payment: dict, source_description: str):
    os.makedirs(os.path.dirname(PAYMENT_LOG), exist_ok=True)
    row = {**payment, "source_description": source_description}
    with open(PAYMENT_LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(row, sort_keys=True) + "\n")

    needs_header = not os.path.exists(INCOME_CSV) or os.path.getsize(INCOME_CSV) == 0
    with open(INCOME_CSV, "a", encoding="utf-8", newline="") as f:
        if needs_header:
            f.write("ts,tx_hash,from_addr,asset,amount,source_description\n")
        f.write(
            "{ts},{tx_hash},{from_addr},USDC,{amount:.6f},{source_description}\n".format(
                ts=payment["ts"],
                tx_hash=payment["tx_hash"],
                from_addr=payment["from"],
                amount=payment["amount_usdc"],
                source_description=source_description,
            )
        )


def verify_deep_scan_payment(tx_hash: str | None) -> tuple[bool, dict]:
    if not tx_hash:
        return False, {
            "error": "Payment required",
            "message": f"Deep scans require {DEEP_SCAN_PRICE_USDC} USDC on Base.",
        }
    if not re.match(r"^0x[a-fA-F0-9]{64}$", tx_hash):
        return False, {"error": "Invalid tx_hash. Must be 0x + 64 hex chars."}

    if tx_hash.lower() in used_payment_hashes():
        return False, {"error": "Payment tx_hash was already used for a deep scan."}

    try:
        receipt = _rpc("eth_getTransactionReceipt", [tx_hash])
    except Exception as e:
        return False, {"error": f"Could not verify payment on Base: {e}"}

    if not receipt:
        return False, {"error": "Payment transaction not found on Base yet."}
    if receipt.get("status") != "0x1":
        return False, {"error": "Payment transaction failed on-chain."}

    required_raw = DEEP_SCAN_PRICE_USDC * 10**USDC_DECIMALS
    wallet_lower = WALLET_ADDRESS.lower()
    for log in receipt.get("logs", []):
        if log.get("address", "").lower() != BASE_USDC_ADDRESS.lower():
            continue
        topics = [t.lower() for t in log.get("topics", [])]
        if len(topics) < 3 or topics[0] != TRANSFER_TOPIC:
            continue

        to_addr = "0x" + topics[2][-40:]
        amount_raw = int(log.get("data", "0x0"), 16)
        if to_addr.lower() == wallet_lower and amount_raw >= required_raw:
            from_addr = "0x" + topics[1][-40:]
            return True, {
                "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "tx_hash": tx_hash,
                "block": int(receipt.get("blockNumber", "0x0"), 16),
                "from": from_addr,
                "to": to_addr,
                "amount_usdc": amount_raw / 10**USDC_DECIMALS,
            }

    return False, {
        "error": "No qualifying USDC payment found in transaction.",
        "required": {
            "network": "Base",
            "token": "USDC",
            "amount": DEEP_SCAN_PRICE_USDC,
            "to": WALLET_ADDRESS,
        },
    }
