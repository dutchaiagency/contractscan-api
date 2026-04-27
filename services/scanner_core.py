"""
Unified Smart Contract Scanner — Core Engine

Used by both Telegram bot and HTTP API.
Free tier: basic on-chain analysis
Paid tier: source code analysis via Sourcify + deep pattern matching
"""

import json
import re
import urllib.error
import urllib.request
import urllib.parse
from dataclasses import dataclass, field, asdict
from typing import Optional

from web3 import Web3


# --- Config ---

RPC_URLS = {
    "ethereum": ["https://eth.drpc.org", "https://1rpc.io/eth"],
    "base": ["https://mainnet.base.org", "https://base-rpc.publicnode.com"],
    "arbitrum": ["https://arb1.arbitrum.io/rpc"],
    "polygon": ["https://polygon-rpc.com"],
    "bsc": ["https://bsc-dataseed.binance.org"],
    "optimism": ["https://mainnet.optimism.io"],
}

# Sourcify chain IDs for verified source code (free, no API key)
CHAIN_IDS = {
    "ethereum": "1",
    "base": "8453",
    "arbitrum": "42161",
    "polygon": "137",
    "bsc": "56",
    "optimism": "10",
}

SOURCIFY_REPO = "https://repo.sourcify.dev/contracts"

ERC20_ABI = json.loads("""[
    {"constant":true,"inputs":[],"name":"name","outputs":[{"name":"","type":"string"}],"type":"function"},
    {"constant":true,"inputs":[],"name":"symbol","outputs":[{"name":"","type":"string"}],"type":"function"},
    {"constant":true,"inputs":[],"name":"decimals","outputs":[{"name":"","type":"uint8"}],"type":"function"},
    {"constant":true,"inputs":[],"name":"totalSupply","outputs":[{"name":"","type":"uint256"}],"type":"function"},
    {"constant":true,"inputs":[],"name":"owner","outputs":[{"name":"","type":"address"}],"type":"function"},
    {"constant":true,"inputs":[{"name":"account","type":"address"}],"name":"balanceOf","outputs":[{"name":"","type":"uint256"}],"type":"function"}
]""")

PROXY_SLOTS = {
    "eip1967_impl": "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc",
    "eip1967_admin": "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103",
}

RISKY_SELECTORS = {
    "40c10f19": ("HIGH", "mint(address,uint256)", "Owner can mint new tokens"),
    "8456cb59": ("HIGH", "pause()", "Owner can pause all transfers"),
    "44337ea1": ("HIGH", "blacklist(address)", "Owner can blacklist addresses"),
    "e4997dc5": ("HIGH", "addToBlacklist(address)", "Owner can blacklist addresses"),
    "69fe0e2d": ("MEDIUM", "setFee(uint256)", "Owner can change transfer fees"),
    "ec28438a": ("MEDIUM", "setMaxTxAmount(uint256)", "Owner can restrict max tx size"),
    "a9059cbb": ("INFO", "transfer(address,uint256)", "Standard ERC20 transfer"),
}

# Source code patterns indicating vulnerabilities
SOURCE_PATTERNS = [
    {
        "name": "Hidden fee manipulation",
        "severity": "CRITICAL",
        "regex": r"(setFee|setTax|_fee|_tax)\s*\([^)]*\)\s*(external|public)",
        "desc": "Function allows dynamic fee changes — fees can be set to 99%+ after launch",
    },
    {
        "name": "Transfer restriction (honeypot)",
        "severity": "CRITICAL",
        "regex": r"require\s*\(\s*(msg\.sender\s*==\s*owner|_?isExcluded|_?allowed)\s*[^)]*\)\s*;?\s*//.*(transfer|sell)",
        "desc": "Transfer restricted to specific addresses — potential honeypot",
    },
    {
        "name": "Unlimited mint authority",
        "severity": "CRITICAL",
        "regex": r"function\s+mint\s*\([^)]*\)\s*(external|public)\s*(onlyOwner)?",
        "desc": "Owner can mint unlimited tokens, diluting all holders",
    },
    {
        "name": "Selfdestruct",
        "severity": "CRITICAL",
        "regex": r"selfdestruct\s*\(",
        "desc": "Contract can be permanently destroyed, wiping all balances",
    },
    {
        "name": "Blacklist mechanism",
        "severity": "HIGH",
        "regex": r"(isBlacklisted|_blacklist|blacklisted)\s*\[",
        "desc": "Contract has blacklist — owner can prevent specific addresses from transacting",
    },
    {
        "name": "Max transaction limit",
        "severity": "MEDIUM",
        "regex": r"(maxTxAmount|_maxTx|maxTransactionAmount)",
        "desc": "Max transaction limit exists — can be set to prevent selling",
    },
    {
        "name": "Cooldown/anti-bot",
        "severity": "MEDIUM",
        "regex": r"(cooldown|_cooldown|lastTrade|tradeCooldown)",
        "desc": "Cooldown timer between trades — may prevent rapid selling",
    },
    {
        "name": "Hidden owner functions",
        "severity": "HIGH",
        "regex": r"function\s+\w+\s*\([^)]*\)\s*(external|public)\s+onlyOwner[^{]*\{[^}]*(balanceOf|_balances|transfer)",
        "desc": "Owner-only function manipulates balances or transfers directly",
    },
    {
        "name": "Proxy upgrade function",
        "severity": "HIGH",
        "regex": r"function\s+(upgradeTo|upgradeToAndCall)\s*\(",
        "desc": "Contract is upgradeable — logic can be changed after deployment",
    },
    {
        "name": "Reentrancy risk",
        "severity": "HIGH",
        "regex": r"\.call\{value:",
        "desc": "External call with value before state update — potential reentrancy",
    },
    {
        "name": "Unchecked external call",
        "severity": "MEDIUM",
        "regex": r"\.call\{[^}]*\}\([^)]*\)\s*;(?!\s*(require|if|bool))",
        "desc": "External call return value not checked",
    },
]


def get_web3(chain: str) -> Optional[Web3]:
    urls = RPC_URLS.get(chain.lower(), [])
    for url in urls:
        try:
            w3 = Web3(Web3.HTTPProvider(url, request_kwargs={"timeout": 15}))
            if w3.is_connected():
                return w3
        except Exception:
            continue
    return None


def fetch_source_code(address: str, chain: str) -> Optional[dict]:
    """Fetch verified source code from Sourcify (free, no API key needed)."""
    chain_id = CHAIN_IDS.get(chain.lower())
    if not chain_id:
        return None

    address = Web3.to_checksum_address(address)

    # Try full_match first, then partial_match
    for match_type in ["full_match", "partial_match"]:
        try:
            # First get metadata.json
            meta_url = f"{SOURCIFY_REPO}/{match_type}/{chain_id}/{address}/metadata.json"
            req = urllib.request.Request(meta_url, headers={"User-Agent": "ContractScanner/1.0"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                metadata = json.loads(resp.read().decode())

            # Extract source files from metadata
            sources = metadata.get("sources", {})
            all_source = []
            contract_name = ""

            # Get contract name from compilation target
            comp_target = metadata.get("settings", {}).get("compilationTarget", {})
            if comp_target:
                contract_name = list(comp_target.values())[0]

            compiler = metadata.get("compiler", {}).get("version", "")

            for filepath, source_info in sources.items():
                content = source_info.get("content", "")
                if content:
                    all_source.append(content)
                else:
                    # Try fetching individual source file from repo
                    try:
                        src_url = f"{SOURCIFY_REPO}/{match_type}/{chain_id}/{address}/sources/{filepath}"
                        src_req = urllib.request.Request(src_url, headers={"User-Agent": "ContractScanner/1.0"})
                        with urllib.request.urlopen(src_req, timeout=10) as src_resp:
                            all_source.append(src_resp.read().decode())
                    except Exception:
                        pass

            if all_source:
                return {
                    "source_code": "\n\n".join(all_source),
                    "contract_name": contract_name,
                    "compiler": compiler,
                    "match_type": match_type,
                }
        except urllib.error.HTTPError:
            continue
        except Exception:
            continue

    return None


def fetch_contract_creation(address: str, chain: str) -> Optional[dict]:
    """Placeholder — creation info requires Etherscan API key."""
    return None


def basic_scan(address: str, chain: str = "ethereum") -> Optional[dict]:
    """Free tier: on-chain analysis only."""
    w3 = get_web3(chain)
    if not w3:
        return {"error": f"Cannot connect to {chain}"}

    address = w3.to_checksum_address(address)
    code = w3.eth.get_code(address)
    if code == b"" or code == b"0x":
        return None

    result = {
        "chain": chain,
        "address": address,
        "code_size": len(code),
        "is_proxy": False,
        "proxy_impl": None,
        "token_info": {},
        "ownership": {},
        "risk_flags": [],
        "risk_score": 0,
    }

    # Proxy check
    for slot_name, slot in PROXY_SLOTS.items():
        try:
            storage = w3.eth.get_storage_at(address, slot)
            addr_from_storage = "0x" + storage[-20:].hex()
            if addr_from_storage != "0x" + "0" * 40:
                result["is_proxy"] = True
                if "impl" in slot_name:
                    result["proxy_impl"] = w3.to_checksum_address(addr_from_storage)
                    result["risk_flags"].append("Upgradeable proxy")
                if "admin" in slot_name:
                    result["proxy_admin"] = w3.to_checksum_address(addr_from_storage)
        except Exception:
            pass

    # ERC20 info
    contract = w3.eth.contract(address=address, abi=ERC20_ABI)
    for fn in ["name", "symbol", "decimals", "totalSupply"]:
        try:
            val = getattr(contract.functions, fn)().call()
            result["token_info"][fn] = str(val) if fn == "totalSupply" else val
        except Exception:
            pass

    # Ownership
    try:
        owner = contract.functions.owner().call()
        result["ownership"]["owner"] = owner
        if owner == "0x" + "0" * 40:
            result["risk_flags"].append("Ownership renounced")
    except Exception:
        result["ownership"]["owner"] = None

    # Bytecode pattern check
    code_hex = code.hex()
    for sig, (sev, name, desc) in RISKY_SELECTORS.items():
        if sev == "INFO":
            continue
        if sig in code_hex:
            result["risk_flags"].append(f"{name}: {desc}")

    # Owner token concentration
    if result["ownership"].get("owner") and result["ownership"]["owner"] != "0x" + "0" * 40:
        try:
            owner_bal = contract.functions.balanceOf(
                w3.to_checksum_address(result["ownership"]["owner"])
            ).call()
            total = contract.functions.totalSupply().call()
            if total > 0:
                pct = (owner_bal / total) * 100
                if pct > 50:
                    result["risk_flags"].append(f"Owner holds {pct:.1f}% of supply (rug risk)")
                elif pct > 20:
                    result["risk_flags"].append(f"Owner holds {pct:.1f}% of supply")
        except Exception:
            pass

    result["eth_balance"] = str(w3.from_wei(w3.eth.get_balance(address), "ether"))

    # Risk score
    score = 0
    for flag in result["risk_flags"]:
        if "rug" in flag.lower() or "honeypot" in flag.lower():
            score += 30
        elif "mint" in flag.lower() or "blacklist" in flag.lower() or "proxy" in flag.lower():
            score += 20
        elif "pause" in flag.lower() or "fee" in flag.lower():
            score += 10
        else:
            score += 5
    result["risk_score"] = min(score, 100)

    return result


def deep_scan(address: str, chain: str = "ethereum") -> Optional[dict]:
    """Paid tier: basic scan + source code analysis + creation info."""
    result = basic_scan(address, chain)
    if not result or "error" in result:
        return result

    result["scan_type"] = "deep"
    result["source_analysis"] = {}
    result["creation_info"] = {}
    result["source_findings"] = []

    # Fetch contract creation info
    creation = fetch_contract_creation(address, chain)
    if creation:
        result["creation_info"] = creation

    # Fetch and analyze source code
    source_info = fetch_source_code(address, chain)
    if source_info:
        result["source_analysis"]["verified"] = True
        result["source_analysis"]["contract_name"] = source_info["contract_name"]
        result["source_analysis"]["compiler"] = source_info["compiler"]
        result["source_analysis"]["match_type"] = source_info.get("match_type", "")

        source = source_info["source_code"]

        # Handle multi-file JSON format
        if source.startswith("{{"):
            source = source[1:-1]  # Remove outer braces
        if source.startswith("{"):
            try:
                parsed = json.loads(source)
                if "sources" in parsed:
                    source = "\n".join(
                        v.get("content", "") for v in parsed["sources"].values()
                    )
            except (json.JSONDecodeError, AttributeError):
                pass

        # Run source code pattern analysis
        for pattern in SOURCE_PATTERNS:
            matches = re.findall(pattern["regex"], source, re.IGNORECASE | re.MULTILINE)
            if matches:
                result["source_findings"].append({
                    "name": pattern["name"],
                    "severity": pattern["severity"],
                    "description": pattern["desc"],
                    "matches": len(matches),
                })

        # Count lines of code
        lines = [l for l in source.split("\n") if l.strip() and not l.strip().startswith("//")]
        result["source_analysis"]["lines_of_code"] = len(lines)

        # Check for common safe patterns
        safe_patterns = {
            "ReentrancyGuard": r"ReentrancyGuard|nonReentrant",
            "OpenZeppelin": r"@openzeppelin",
            "SafeMath": r"SafeMath|using SafeMath",
            "AccessControl": r"AccessControl|onlyRole",
            "Timelock": r"[Tt]imelock|TimelockController",
        }
        result["source_analysis"]["safety_features"] = []
        for name, pat in safe_patterns.items():
            if re.search(pat, source):
                result["source_analysis"]["safety_features"].append(name)

        # Adjust risk score based on source findings
        for finding in result["source_findings"]:
            if finding["severity"] == "CRITICAL":
                result["risk_score"] = min(result["risk_score"] + 30, 100)
            elif finding["severity"] == "HIGH":
                result["risk_score"] = min(result["risk_score"] + 15, 100)
            elif finding["severity"] == "MEDIUM":
                result["risk_score"] = min(result["risk_score"] + 5, 100)

        # Reduce score for safety features
        safety_bonus = len(result["source_analysis"]["safety_features"]) * 5
        result["risk_score"] = max(result["risk_score"] - safety_bonus, 0)

    else:
        result["source_analysis"]["verified"] = False
        result["source_findings"].append({
            "name": "Unverified source code",
            "severity": "HIGH",
            "description": "Source code not verified on block explorer — cannot analyze for vulnerabilities",
            "matches": 0,
        })
        result["risk_score"] = min(result["risk_score"] + 20, 100)

    # Risk summary
    score = result["risk_score"]
    if score >= 70:
        result["risk_summary"] = "CRITICAL RISK — Multiple severe red flags detected"
    elif score >= 40:
        result["risk_summary"] = "HIGH RISK — Significant concerns found"
    elif score >= 20:
        result["risk_summary"] = "MEDIUM RISK — Some issues detected"
    elif score > 0:
        result["risk_summary"] = "LOW RISK — Minor issues only"
    else:
        result["risk_summary"] = "CLEAN — No significant issues found"

    return result


def format_deep_report(result: dict) -> str:
    """Format deep scan result as readable text (for Telegram)."""
    if not result:
        return "No contract found at this address."
    if "error" in result:
        return f"Error: {result['error']}"

    lines = [
        f"**DEEP SCAN REPORT**",
        f"Chain: {result['chain'].upper()}",
        f"Address: `{result['address']}`",
        f"Risk Score: {result['risk_score']}/100",
        f"Assessment: {result.get('risk_summary', 'N/A')}",
        "",
    ]

    # Token info
    ti = result.get("token_info", {})
    if ti:
        name = ti.get("name", "Unknown")
        symbol = ti.get("symbol", "Unknown")
        lines.append(f"**Token:** {name} ({symbol})")
        if "totalSupply" in ti and "decimals" in ti:
            supply = int(ti["totalSupply"]) / 10 ** ti["decimals"]
            lines.append(f"Supply: {supply:,.2f}")
        lines.append("")

    # Creation info
    ci = result.get("creation_info", {})
    if ci:
        lines.append(f"**Deployer:** `{ci.get('deployer', 'Unknown')}`")
        lines.append("")

    # Source code analysis
    sa = result.get("source_analysis", {})
    if sa:
        verified = "Yes" if sa.get("verified") else "No"
        lines.append(f"**Source Verified:** {verified}")
        if sa.get("verified"):
            lines.append(f"Contract: {sa.get('contract_name', 'N/A')}")
            lines.append(f"Compiler: {sa.get('compiler', 'N/A')}")
            loc = sa.get("lines_of_code", 0)
            lines.append(f"Lines of Code: {loc}")
            safety = sa.get("safety_features", [])
            if safety:
                lines.append(f"Safety Features: {', '.join(safety)}")
        lines.append("")

    # Proxy
    if result.get("is_proxy"):
        lines.append("**Proxy: YES (Upgradeable)**")
        if result.get("proxy_impl"):
            lines.append(f"Implementation: `{result['proxy_impl']}`")
        lines.append("")

    # Risk flags
    flags = result.get("risk_flags", [])
    if flags:
        lines.append("**On-Chain Risk Flags:**")
        for f in flags:
            lines.append(f"  - {f}")
        lines.append("")

    # Source findings
    sf = result.get("source_findings", [])
    if sf:
        lines.append("**Source Code Findings:**")
        for f in sf:
            emoji = {"CRITICAL": "!!!", "HIGH": "!!", "MEDIUM": "!", "LOW": "~"}.get(f["severity"], "")
            lines.append(f"  [{f['severity']}] {f['name']}")
            lines.append(f"    {f['description']}")
        lines.append("")

    # Ownership
    owner = result.get("ownership", {}).get("owner")
    if owner:
        lines.append(f"**Owner:** `{owner}`")

    return "\n".join(lines)


if __name__ == "__main__":
    import sys
    addr = sys.argv[1] if len(sys.argv) > 1 else "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"
    chain = sys.argv[2] if len(sys.argv) > 2 else "base"
    mode = sys.argv[3] if len(sys.argv) > 3 else "deep"

    if mode == "basic":
        r = basic_scan(addr, chain)
    else:
        r = deep_scan(addr, chain)

    print(json.dumps(r, indent=2))
