# Karnot Units SDK

SDK for interacting with the Karnot Units Engine.

## Installation

```bash
npm install @karnot/units-sdk
```

## Usage

```typescript
import { UnitsProvider, UnitsAccount } from "@karnot/units-sdk";

const provider = new UnitsProvider("http://localhost:8080");
const account = new UnitsAccount(provider, "ADDRESS", "PRIVATE_KEY");

const chainId = await provider.getChainId();
console.log(chainId);
```

## CLI Usage

The package includes a CLI for common operations. You can run it via the examples or by using the installed binary if configured.

See `examples/` for more detailed usage scripts.
