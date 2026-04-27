# ContractScan API

Smart contract security scanner with multi-chain support. Detects proxies, honeypots, rug pull patterns, and more.

## Features

- **Basic scan (free):** Proxy detection, ownership analysis, token metadata, bytecode risk flags, risk score
- **Deep scan ($2 USDC):** Source code analysis via Sourcify, 11 vulnerability patterns, reentrancy detection
- **6 chains:** Ethereum, Base, Arbitrum, Polygon, BSC, Optimism

## API

```bash
# Basic scan (free)
GET /scan?address=0x...&chain=base

# Deep scan (paid)
GET /scan?address=0x...&chain=base&mode=deep&tx_hash=0x...

# List chains
GET /chains
```

## Payment

Deep scans cost $2 USDC on Base. Send to `0x8C0083EE1a611c917E3652a14f9Ab5c3a23948D3` and pass the tx hash.

## Run locally

```bash
pip install -r requirements.txt
python services/x402-api/server.py
```

## Deploy

Deploy via Docker or Render.com (render.yaml included).
