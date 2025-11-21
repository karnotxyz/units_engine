# Default Read ACLs for Starknet Contracts - DEPRECATED

> **⚠️ DEPRECATED**: This document is deprecated and will be removed in a future release.
> Please refer to [getting_started.md](./getting_started.md) for the most up-to-date and comprehensive
> documentation on UNITS privacy features.

---

By default, Starknet RPCs allow any user to fetch certain basic information about contracts, including:

- The nonce of a contract
- The class hash of a contract

## Proposed Standard: Fine-grained Read ACLs

We propose a new standard where contracts can define granular access controls for reading these values through two specific functions:

- `can_read_nonce`
- `can_read_class_hash`

### How it Works

When a user attempts to read either the nonce or class hash of a contract, the RPC will:

1. Call the corresponding access control function on the target contract
2. Only return the requested information if the function returns `true`
3. If the function doesn't exist (for compatibility with existing contracts on Starknet), the read operation is allowed by default

### Example Implementation

Here's an example of how to implement nonce read access control in Cairo
(Note: This is a conceptual example for illustration purposes only and has not been tested on-chain):

```cairo
#[starknet::interface]
trait IReadACL {
    fn can_read_nonce(caller: starknet::ContractAddress) -> bool;
}

#[starknet::contract]
mod MyContract {
    use starknet::ContractAddress;

    #[storage]
    struct Storage {}

    #[external(v0)]
    fn can_read_nonce(self: @ContractState, caller: ContractAddress) -> bool {
        // Example: Only allow address 0x1 to read the nonce
        caller == ContractAddress::from_felt252(1)
    }
}
```

### Backward Compatibility

For contracts that don't implement these functions, the RPC will maintain the current behavior where reading nonce and class hash
is allowed for all users. This ensures compatibility with existing contracts on Starknet while allowing new contracts to implement
more granular access controls.
