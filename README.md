# UNITS Engine 🔐

UNITS (Universal Information Tokenisation System) Engine is a confidentiality layer built on top of [Madara](https://docs.madara.build),
designed to offer transaction privacy while maintaining verifiability through Zero-Knowledge proofs. Together, UNITS Engine and Madara
form a complete UNITS implementation, providing both the high-performance ZK infrastructure and the privacy layer needed for confidential
transactions. UNITS is an integral part of the [Finternet](https://finternetlab.io/).

## Overview 🌟

In traditional blockchain architectures and ZK rollups, while write access is carefully controlled through ACLs, read access remains
completely public - anyone can read any data on the chain. UNITS engine takes a different approach by introducing a confidentiality layer
that allows for controlled data visibility while maintaining the benefits of verifiability.

### Key Features ✨

- **Confidential Transactions**: UNITS enables private transactions while maintaining verifiability
- **Flexible Privacy Rules**: Participants can define custom privacy rules that the operator enforces
- **Starknet Compatibility**: Supports Starknet RPC for tooling compatibility
- **Custom UNITS RPC**: Dedicated RPC interface designed specifically for UNITS functionality

## Architecture 🏗️

UNITS engine is built as a layer on top of Madara to leverage its robust infrastructure and high performant ZK architecture. The codebase
is organized into several key components:

### Design Philosophy 💡

By building on top of Madara, UNITS Engine achieves two critical objectives:

1. **Future-Proof Development**: We automatically benefit from the latest advancements in ZK technology and improvements in the
   Starknet (SN) Stack, as Madara stays in sync with these developments
2. **Focused Innovation**: While Madara handles the core ZK infrastructure, UNITS Engine can focus exclusively on building robust
   privacy features and confidentiality mechanisms

This separation of concerns allows us to maintain a cutting-edge ZK foundation while developing specialized privacy features that make
UNITS unique.

### Core Components 🧩

- **Engine**: The main binary and entry point, containing CLI configuration
- **Handlers**: Core business logic implementing UNITS functionality and Madara interactions
- **DB**: Database interaction layer for persistent storage
- **UNITS Primitives**: Core primitives and types used across multiple crates
- **Utils**: Basic utility functions and helpers shared across crates
- **RPC**: Dual RPC implementation:
  - Starknet RPC for tooling compatibility
  - UNITS RPC for native functionality
- **Telemetry**: OpenTelemetry integration for metrics and monitoring
- **Proc Macros**: Procedural macros for code generation
- **Test Utils**: Testing utilities and helpers
- **E2E Tests**: End-to-end test suite

## Getting Started 🚀

### Prerequisites

- Rust (see rust-toolchain.toml for version)
- [Madara CLI](https://docs.madara.build/quickstart/run_devnet)

### Running Tests 🧪

1. First, install and start a Madara devnet:

   ```bash
   # Clone the Madara CLI
   git clone https://github.com/madara-alliance/madara-cli.git
   cd madara-cli

   # Run the devnet
   cargo run create
   # Select "Devnet" mode when prompted
   ```

2. Run the test suite:

   ```bash
   cargo test --workspace --all-features
   ```

## Privacy Model 🛡️

UNITS engine implements a trusted operator model where:

- The operator maintains privacy between participants
- Participants can define and enforce their own privacy rules
- The operator can see all data (by design)
- Future integration with Fully Homomorphic Encryption (FHE) is possible as the technology matures

## RPC Support 🔌

### Starknet RPC

UNITS supports the standard Starknet RPC interface for compatibility with existing tools. However, some calls might fail if users don't
have the required access rights due to privacy constraints.

### UNITS RPC

A custom RPC interface designed specifically for UNITS functionality. This is the recommended interface for new applications as it's built
with privacy in mind from the ground up.

## Performance Benchmarks 📊

UNITS is built on top of Madara, which has demonstrated impressive performance metrics:

- 7,000 TPS with merkleization
- 15,000 TPS without merkleization

Note: Benchmarking integration with CI is in progress to provide more reproducible results across different environments and
configurations.

## Acknowledgments 🙏

UNITS engine is heavily inspired by and built upon [Madara](https://github.com/madara-alliance/madara), which Karnot is a maintainer of
along with Moongsong Labs and Kasar Labs. We're grateful for their foundational work that made this project possible.
