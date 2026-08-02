# Provider demonstration dapp

This directory is a static, dependency-free demonstration of provider ABI v1.
It has no backend, wallet database, key generation, RPC connection, or custody.

Serve these files from an HTTPS logical origin whose exact main-frame security
receipt is approved by HNS DANE Browser. The extension intentionally does not
inject the provider into `file:` pages, ordinary HTTP pages, stale/restored
documents, or documents for which native wallet ABI v1 is unavailable.

The page uses event-based `hns:requestProvider` / `hns:announceProvider`
discovery. It requests explicit permissions, reads accounts/balances/names,
lists and creates or accepts Shakedex offers, separates HNS/BTC and HNS/ETH
market intents, publishes an intent, requests and approves a fill, monitors a
swap, and requests a refund. All amounts are integer base-unit strings.
