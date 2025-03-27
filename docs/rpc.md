# RPC Types

UNITS supports two types of RPC interfaces for users:

## Starknet RPC

The Starknet RPC type is designed to maintain compatibility with the existing Starknet tooling ecosystem. The request and response formats strictly follow the Starknet RPC specification to ensure seamless integration.

Note that while we aim for maximum compatibility, not all RPC calls from the Starknet spec are available, and some operations might behave differently due to UNITS' privacy-focused architecture. For example, querying the class of a private contract may not work as expected.

## UNITS RPC

The UNITS RPC is our dedicated RPC interface that is specifically built to handle UNITS-specific logic and privacy primitives. This includes special operations like:

- Managing contract visibility during declaration
- Privacy-aware contract interactions
- UNITS-specific state management

## Future Direction

Our end goal is to establish comprehensive tooling around the UNITS RPC and encourage users to primarily use this interface. The UNITS RPC provides the most accurate and privacy-preserving way to interact with the UNITS ecosystem.
