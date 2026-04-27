# ContractScan API

> Scan any smart contract for rug pulls, honeypots, and hidden risks. Multi-chain. No API key needed.

**6 chains** | **Free basic scans** | **Source code analysis** | **Pay-per-scan with USDC**

## What it detects

| Category | Basic (free) | Deep ($2 USDC) |
|----------|:---:|:---:|
| Proxy / upgradeable contracts | x | x |
| Owner privileges & renouncement | x | x |
| Token metadata (name, symbol, supply) | x | x |
| Bytecode risk flags (mint, pause, blacklist, fees) | x | x |
| Risk score (0-100) | x | x |
| Verified source code analysis (Sourcify) | | x |
| Reentrancy vulnerabilities | | x |
| Hidden owner functions | | x |
| Unchecked external calls | | x |
| Honeypot patterns | | x |
| 11 vulnerability patterns total | | x |

## Quick start

```bash
# Install
pip install web3

# Run
python services/x402-api/server.py
# => http://localhost:4020
```

## API usage

No signup. No API key. Just HTTP GET.

```bash
# Free basic scan
curl "http://localhost:4020/scan?address=0xdAC17F958D2ee523a2206206994597C13D831ec7&chain=ethereum"

# List supported chains
curl "http://localhost:4020/chains"
# => ethereum, base, arbitrum, polygon, bsc, optimism
```

### Example response (basic scan)

```json
{
  "address": "0xdAC17F958D2ee523a2206206994597C13D831ec7",
  "chain": "ethereum",
  "risk_score": 40,
  "is_proxy": true,
  "proxy_impl": "0x...",
  "owner": "0x...",
  "is_token": true,
  "token_name": "Tether USD",
  "token_symbol": "USDT",
  "bytecode_flags": ["has_pause", "has_blacklist"],
  "bytecode_size": 8192
}
```

### Deep scan (paid)

1. Send **$2 USDC** on **Base** to `0x8C0083EE1a611c917E3652a14f9Ab5c3a23948D3`
2. Pass the tx hash:

```bash
curl "http://localhost:4020/scan?address=0x...&chain=ethereum&mode=deep&tx_hash=0xYOUR_PAYMENT_TX"
```

Deep scan returns everything in basic plus source code vulnerability analysis with 11 pattern checks.

## Use cases

- **Trading bots**: Pre-screen tokens before automated buys
- **DeFi users**: Check contracts before interacting
- **Developers**: Integrate security checks into your dApp
- **Security researchers**: Quick triage of contracts across chains

## Deploy

### Docker

```bash
docker build -t contractscan .
docker run -p 4020:4020 contractscan
```

### Render.com

1. Fork this repo
2. Connect to Render.com
3. It auto-detects `render.yaml` - deploy on free tier

### Self-hosted

```bash
pip install -r requirements.txt
PORT=4020 python services/x402-api/server.py
```

## Architecture

```
services/
  scanner_core.py      # Core scanning engine (basic + deep analysis)
  payment_verify.py    # On-chain USDC payment verification (Base)
  x402-api/
    server.py          # HTTP server with landing page
    index.html         # Web UI
```

- Pure Python, minimal dependencies (only `web3`)
- Payment verification checks actual USDC Transfer events on Base
- Each payment tx hash can only be used once
- Source code pulled from Sourcify for deep analysis

## License

MIT
