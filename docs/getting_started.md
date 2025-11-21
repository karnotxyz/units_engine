# Getting Started with UNITS Privacy

## Table of Contents

- [Introduction](#introduction)
- [Core Concepts](#core-concepts)
  - [Read Signatures](#read-signatures)
  - [Privacy Model](#privacy-model)
  - [Declare ACL Contract](#declare-acl-contract)
- [UNITS RPC Methods](#units-rpc-methods)
  - [units_call](#units_call)
  - [units_declareProgram](#units_declareprogram)
  - [units_getProgram](#units_getprogram)
  - [units_getNonce](#units_getnonce)
  - [units_getTransactionReceipt](#units_gettransactionreceipt)
  - [units_deployAccount](#units_deployaccount)
  - [units_sendTransaction](#units_sendtransaction)
  - [units_getChainId](#units_getchainid)
- [Privacy Patterns](#privacy-patterns)
  - [Private Contract Functions](#private-contract-functions)
  - [Private Class Access](#private-class-access)
  - [Private Nonce Reading](#private-nonce-reading)
  - [Private Event Access](#private-event-access)

---

## Introduction

UNITS (Universal Information Tokenisation System) is a confidentiality layer built on top of Madara that enables
controlled data visibility while maintaining verifiability. Unlike traditional blockchains where all data is publicly
readable, UNITS allows you to define fine-grained access controls for reading various types of data including:

- Smart contract function calls
- Declared classes (contract code)
- Account nonces
- Transaction receipts and events

UNITS operates on a trusted operator model where:

- The operator maintains privacy between participants
- Participants define and enforce their own privacy rules
- The operator can see all data (by design)
- Privacy is enforced through Access Control Lists (ACLs) and read signatures

---

## Core Concepts

### Read Signatures

Read signatures are a fundamental concept in UNITS that enable secure, time-limited authorization for reading data.
They prevent unauthorized access while allowing legitimate users to prove their right to read specific information.

#### What is a Read Signature?

A read signature is a cryptographically signed message that proves:

1. **Identity**: The requester's address
2. **Authorization**: What the requester wants to read
3. **Validity**: Time-limited to prevent replay attacks

#### Structure of Read Data

Every read operation requires signing a `ReadData` object with the following components:

```json
{
  "verifier": {
    "type": "ACCOUNT" | "IDENTITY",
    "signer_address": "0x...",
    "identity_address": "0x..."  // Only for IDENTITY type
  },
  "read_type": [
    {
      "type": "NONCE" | "TRANSACTION_RECEIPT" | "CLASS" | "CALL",
      // ... type-specific fields
    }
  ],
  "read_validity": {
    "type": "BLOCK" | "TIMESTAMP",
    "block": 100000,  // for BLOCK type
    "timestamp": 1234567890  // for TIMESTAMP type
  },
  "chain_id": "0x...",
  "version": "ONE"
}
```

#### Read Verifier Types

##### ACCOUNT Verifier

- Simplest form where the signer address is the same as the address with read permissions
- Use case: Direct account access

```json
{
  "type": "ACCOUNT",
  "signer_address": "0x123..."
}
```

##### IDENTITY Verifier

- Allows delegation where a signer can act on behalf of an identity contract
- **Identity** here refers to [ONCHAINID](https://github.com/NethermindEth/onchain_id_starknet), a Starknet
  implementation for on-chain identity management
- The identity contract must have a method to verify the signer is authorized
- Use case: Multi-sig wallets, corporate accounts, delegation
- **If you're not using ONCHAINID, use the ACCOUNT verifier**

```json
{
  "type": "IDENTITY",
  "signer_address": "0x123...", // The account signing
  "identity_address": "0x456..." // The identity contract with permissions
}
```

#### Read Types

##### NONCE

- Used to read an account's nonce
- The `nonce` field contains the account address whose nonce you want to read

```json
{
  "type": "NONCE",
  "nonce": "0x..." // Account address
}
```

##### TRANSACTION_RECEIPT

- Used to read transaction receipts
- The `transaction_hash` field contains the transaction hash

```json
{
  "type": "TRANSACTION_RECEIPT",
  "transaction_hash": "0x..."
}
```

##### CLASS

- Used to read declared class/contract code
- The `class_hash` field contains the class hash

```json
{
  "type": "CLASS",
  "class_hash": "0x..."
}
```

##### CALL

- Used to call view functions on contracts
- Most complex type as it includes contract address, function, and calldata

```json
{
  "type": "CALL",
  "contract_address": "0x...",
  "function_selector": "0x...", // Starknet selector of function name
  "calldata": ["0x...", "0x..."]
}
```

#### Read Validity

Signatures must have an expiration to prevent replay attacks. You can use either:

##### Block-based expiry

```json
{
  "type": "BLOCK",
  "block": 100000 // Valid until block 100000
}
```

##### Timestamp-based expiry

```json
{
  "type": "TIMESTAMP",
  "timestamp": 1234567890 // Unix timestamp
}
```

#### How Read Signatures are Verified

When you submit a read signature, UNITS:

1. **Computes the hash** of the `ReadData` using Poseidon hash
2. **Calls `is_valid_signature`** on the signer's account contract with:
   - The computed hash
   - The provided signature
3. **Checks expiration** against current block/timestamp
4. **For IDENTITY verifiers**: Calls the identity contract to verify the signer is authorized
5. **Validates permissions**: Ensures the read type matches what's being requested

#### Signing Read Data (Example in TypeScript)

```typescript
import { ec, hash as starknetHash } from "starknet";

// 1. Create ReadData object
const readData = {
  verifier: {
    type: "ACCOUNT",
    signer_address: "0x123...",
  },
  read_type: [
    {
      type: "CALL",
      contract_address: "0x456...",
      function_selector: "0x789...",
      calldata: [],
    },
  ],
  read_validity: {
    type: "TIMESTAMP",
    timestamp: Math.floor(Date.now() / 1000) + 3600, // 1 hour from now
  },
  chain_id: "0x...",
  version: "ONE",
};

// 2. Compute hash using Poseidon
const messageHash = hashReadData(readData);

// 3. Sign with private key
const signature = ec.starkCurve.sign(messageHash, privateKey);

// 4. Create SignedReadData
const signedReadData = {
  read_data: readData,
  signature: [signature.r, signature.s],
};
```

---

### Privacy Model

UNITS implements privacy through a combination of:

1. **Read Signatures**: Cryptographically signed authorization for read operations
2. **Simulation-based Calls**: Using Starknet's simulation API to execute calls with a specific caller address
3. **Access Control Contracts**: On-chain contracts that manage who can access what
4. **Operator Enforcement**: The UNITS operator enforces privacy rules before returning data

The key insight is that UNITS uses **simulation calls** instead of standard view calls. This means:

- When you call a function, UNITS simulates a transaction from your address
- Inside the Cairo contract, you can use `get_caller_address()`, `get_tx_info()`, or other Cairo methods to identify the caller
- The contract can check if the caller has permission and revert if they don't
- The revert prevents unauthorized users from seeing the data

---

### Declare ACL Contract

The Declare ACL Contract is a special contract that manages visibility for all declared classes (smart contracts) in the UNITS system.

#### What It Does

When you start UNITS, you must provide a Declare ACL contract address. This contract:

- Stores visibility settings for all declared classes
- Determines if a class is PUBLIC or ACL-protected
- Manages who can read ACL-protected classes
- Is called automatically during class declaration and retrieval

#### Required Interface

Any Declare ACL contract must implement three core functions:

**1. `set_visibility(class_hash: felt252, visibility: ClassVisibility, granter: ContractAddress)`**

- Called when a class is declared
- `visibility` is an enum: 0 = ACL, 1 = PUBLIC
- `granter` is the address that declared the class
- Can be called multiple times for the same class (if re-declared)

**2. `get_visibility(class_hash: felt252) -> ClassVisibility`**

- Returns whether a class is PUBLIC or ACL
- Called when someone tries to read a class

**3. `has_read_access(class_hash: felt252) -> bool`**

- Only needed if class visibility is ACL
- Uses `get_caller_address()`, `get_tx_info()`, or other Cairo methods to check the reader's address
- Returns true if the caller can read this class

#### Reference Implementation

UNITS provides a reference implementation at `crates/handlers/starknet/src/tests/get_program/test_contracts/src/declare_acl.cairo`.

**Important**: This reference implementation is NOT audited and is provided as-is without any warranties. Users of UNITS
are free to use their own Declare ACL implementation for production or use our reference implementation at their own
risk. We do not take responsibility for any issues, vulnerabilities, or losses that may arise from using this code. For
production deployments, we strongly recommend having any ACL contract professionally audited and thoroughly tested.

**How the Reference Implementation Works:**

The reference implementation uses a counter-based approach with four storage structures:

1. **`class_visibility`** (Map: class_hash → counter)

   - Determines if a class is Public (counter > 0) or ACL/private (counter = 0)
   - When someone declares with Public visibility: counter increments by 1
   - When someone declares with ACL visibility:
     - If they previously made it public: counter decrements by 1
     - If they never made it public: no change (early return)
   - Result: A class is Public if ANY declarer made it public and hasn't revoked

2. **`visibility_granters`** (Map: class_hash → granter_address → bool)

   - Tracks which addresses have set a class to public
   - Prevents double-granting (can't increment counter twice from same granter)
   - Enforces "only revoke what you granted" rule

3. **`class_acl_map`** (Map: class_hash → account_address → counter)

   - Stores which addresses have access to ACL-protected classes
   - Counter increments when a unique granter gives access to an address
   - Counter decrements when a granter who previously gave access removes it
   - Result: An address has access if counter > 0 (at least one granter gave access)

4. **`access_granters`** (Map: class_hash → account_address → granter_address → bool)
   - Tracks which granters have given access to specific addresses
   - Prevents double-granting for access permissions
   - Enforces "only revoke what you granted" rule for access

**`set_visibility` Behavior:**

- Called automatically by UNITS when a class is declared
- Public visibility: Checks if granter already made it public; if not, increments counter
- ACL visibility: Checks if granter previously made it public; if yes, decrements counter; if no, returns early
- Multiple declarers can independently control visibility

**`update_acl` Behavior:**

- Used to grant/revoke access to specific addresses for ACL classes (via separate transactions)
- Grant access: Checks if granter already gave access; if not, increments counter
- Revoke access: Checks if granter previously gave access; if yes, decrements counter; if no, fails with assertion

#### Multiple Declarations

When multiple users declare the same class:

- The class is only declared once on-chain (Starknet behavior)
- `set_visibility` is called for each declaration attempt
- The ACL contract decides how to handle multiple visibility settings
- The reference implementation uses a union approach (any grant gives access)

---

## UNITS RPC Methods

### units_call

Call a view function on a smart contract with privacy controls.

**Key Differences from Standard Starknet**:

- Uses **simulation calls** instead of standard view calls
- The contract can identify your address via `get_caller_address()`, `get_tx_info()`, or other Cairo methods
- Contracts can enforce access control by reverting if caller lacks permission
- Requires a read signature

**Parameters**:

```json
{
  "contract_address": "0x...",
  "function_name": "get_balance",
  "calldata": ["0x..."],
  "signed_read_data": {
    "read_data": {
      /* ReadData object */
    },
    "signature": ["0x...", "0x..."]
  }
}
```

**Read Signature Requirements**:

- Must include a `CALL` read type with matching contract, function, and calldata
- Must not be expired
- Signature must be valid for the signer account

**Privacy Enforcement**:
The contract being called can check the caller and revert:

```cairo
#[external(v0)]
fn read_private_data(self: @ContractState) -> felt252 {
    let caller = get_caller_address();
    let has_access = self.approved_readers.entry(caller).read();
    assert(has_access, 'Not authorized');
    self.private_data.read()
}
```

**Returns**:

```json
{
  "result": ["0x...", "0x..."]
}
```

**Error Cases**:

- `InvalidReadSignature`: Signature verification failed
- `ChainHandlerError`: Simulation failed (e.g., contract reverted)

---

### units_declareProgram

Declare a new smart contract class with visibility controls.

**Parameters**:

```json
{
  "account_address": "0x...",
  "signature": ["0x...", "0x..."],
  "nonce": 0,
  "program": { /* Sierra contract JSON */ },
  "compiled_program_hash": "0x...",
  "class_visibility": "PUBLIC" | "ACL",
  "resource_bounds": {
    "l1_gas": { "max_amount": 1000, "max_price_per_unit": 100 },
    "l1_data_gas": { "max_amount": 1000, "max_price_per_unit": 100 },
    "l2_gas": { "max_amount": 100000, "max_price_per_unit": 100 }
  }
}
```

**How It Works**:

1. UNITS computes the class hash from the program
2. Checks if the class already exists on-chain
3. **Calls `set_visibility` on the Declare ACL contract** (always, even if class exists)
4. If class doesn't exist, declares it on Starknet
5. Returns the class hash and transaction hash

**Class Visibility**:

- `PUBLIC`: Anyone can read the class code
- `ACL`: Only approved addresses (via Declare ACL contract) can read

**Multiple Declarations**:
If the same class is declared multiple times:

- The class is only declared on-chain once
- `set_visibility` is called each time
- The ACL contract determines the final visibility (typically union of all grants)
- Response includes `acl_updated: true` but may have `transaction_hash: null`

**Returns**:

```json
{
  "program_hash": "0x...",
  "transaction_hash": "0x..." | null,
  "acl_updated": true
}
```

---

### units_getProgram

Retrieve the code of a declared smart contract class.

**Parameters**:

```json
{
  "class_hash": "0x...",
  "signed_read_data": {
    /* Optional: required for ACL classes */
  }
}
```

**Read Signature Requirements** (for ACL classes):

- Must include a `CLASS` read type with the class hash
- Must not be expired
- Signature must be valid

**How Privacy is Enforced**:

1. UNITS calls `get_visibility` on the Declare ACL contract
2. If **PUBLIC**: Returns the class immediately
3. If **ACL**:
   - Requires a valid `signed_read_data`
   - Verifies the signature
   - Calls `has_read_access` on the Declare ACL contract with your address as the caller
   - Returns class only if `has_read_access` returns true

**Returns**:

```json
{
  "program": {
    /* Sierra contract JSON */
  }
}
```

**Error Cases**:

- `ReadSignatureNotProvided`: ACL class accessed without signature
- `ClassReadNotAllowed`: `has_read_access` returned false
- `InvalidReadSignature`: Signature verification failed
- `ProgramNotFound`: Class doesn't exist

---

### units_getNonce

Get the nonce of an account with optional privacy controls.

**Parameters**:

```json
{
  "account_address": "0x...",
  "signed_read_data": {
    /* Optional: required if contract enforces privacy */
  }
}
```

**Read Signature Requirements** (if needed):

- Must include a `NONCE` read type with the account address
- Must not be expired
- Signature must be valid

**Privacy Mechanism**:
UNITS checks if the account contract has a `can_read_nonce` function:

**If `can_read_nonce` doesn't exist**:

- Nonce is public (backward compatible with standard Starknet behavior)
- No signature required
- Returns nonce directly

**If `can_read_nonce` exists**:

- Requires a valid `signed_read_data`
- UNITS simulates a call to `can_read_nonce` with your address as the caller
- Only returns nonce if `can_read_nonce` returns true

**Implementing Nonce Privacy**:

```cairo
#[external(v0)]
fn can_read_nonce(self: @ContractState) -> bool {
    let caller = get_caller_address();
    // Only allow specific addresses to read nonce
    caller == self.owner.read() || self.approved_readers.entry(caller).read()
}
```

**Returns**:

```json
{
  "nonce": 0
}
```

**Error Cases**:

- `ReadSignatureNotProvided`: Privacy enabled but no signature
- `NonceReadNotAllowed`: `can_read_nonce` returned false
- `InvalidReadSignature`: Signature verification failed

---

### units_getTransactionReceipt

Get the receipt of a transaction with privacy controls for events.

**Parameters**:

```json
{
  "transaction_hash": "0x...",
  "signed_read_data": {
    "read_data": {
      /* ReadData object */
    },
    "signature": ["0x...", "0x..."]
  }
}
```

**Read Signature Requirements**:

- Must include a `TRANSACTION_RECEIPT` read type with the transaction hash
- Must not be expired
- Signature must be valid

**Privacy Enforcement**:

1. **Transaction-level**: Only the transaction sender can fetch the receipt

   - UNITS checks if `signed_read_data.read_address == transaction.sender_address`
   - This ensures you can only read receipts for your own transactions

2. **Event-level**: Contracts can control who sees their events
   - For each event in the receipt, UNITS checks if the emitting contract has `can_read_event`
   - If `can_read_event` doesn't exist: event is public
   - If it exists: UNITS simulates a call with the event selector and your address
   - Events you can't access are filtered out of the receipt

**Implementing Event Privacy**:

```cairo
#[external(v0)]
fn can_read_event(self: @ContractState, selector: felt252) -> bool {
    let caller = get_caller_address();

    // Example: Private events only for approved users
    if selector == selector!("PrivateTransfer") {
        return self.approved_users.entry(caller).read();
    }

    // Public events
    true
}
```

**Returns**:

```json
{
  "transaction_hash": "0x...",
  "events": [
    {
      "from_address": "0x...",
      "keys": ["0x...", "0x..."],
      "data": ["0x...", "0x..."]
    }
  ],
  "finality_status": "ACCEPTED_ON_UNITS" | "ACCEPTED_ON_PROOF_STORE",
  "execution_status": { "type": "SUCCEEDED" } | { "type": "REVERTED", "error": "..." }
}
```

**Error Cases**:

- `InvalidReadSignature`: Signature verification failed
- `InvalidSenderAddress`: Trying to read someone else's transaction
- Events may be filtered (not an error, just omitted)

---

### units_deployAccount

Deploy a new account contract.

**Parameters**:

```json
{
  "signature": ["0x...", "0x..."],
  "nonce": 0,
  "constructor_calldata": ["0x...", "0x..."],
  "program_hash": "0x...",
  "account_address_salt": "0x...",
  "resource_bounds": {
    "l1_gas": { "max_amount": 1000, "max_price_per_unit": 100 },
    "l1_data_gas": { "max_amount": 1000, "max_price_per_unit": 100 },
    "l2_gas": { "max_amount": 100000, "max_price_per_unit": 100 }
  }
}
```

**Privacy Notes**:

- Works exactly like standard Starknet deploy account
- **No privacy restrictions**: Anyone can deploy an account
- The account address is deterministic based on program hash, salt, and calldata
- No read signature required

**Returns**:

```json
{
  "transaction_hash": "0x..."
}
```

---

### units_sendTransaction

Execute a transaction on the network.

**Parameters**:

```json
{
  "account_address": "0x...",
  "signature": ["0x...", "0x..."],
  "nonce": 0,
  "calldata": ["0x...", "0x..."],
  "resource_bounds": {
    "l1_gas": { "max_amount": 1000, "max_price_per_unit": 100 },
    "l1_data_gas": { "max_amount": 1000, "max_price_per_unit": 100 },
    "l2_gas": { "max_amount": 100000, "max_price_per_unit": 100 }
  }
}
```

**Privacy Notes**:

- Works exactly like standard Starknet transactions
- **No privacy restrictions**: Anyone can send transactions
- No read signature required
- Privacy is enforced when reading transaction receipts (see `units_getTransactionReceipt`)

**Returns**:

```json
{
  "transaction_hash": "0x..."
}
```

---

### units_getChainId

Get the chain ID of the UNITS network.

**Parameters**: None

**Privacy Notes**:

- **Public**: Anyone can fetch the chain ID
- No read signature required
- No privacy restrictions

**Returns**:

```json
{
  "chain_id": "0x..."
}
```

---

## Privacy Patterns

### Private Contract Functions

Make your contract functions readable only by approved users.

**Pattern**: Check caller address in view functions

```cairo
#[starknet::contract]
mod PrivateVault {
    use starknet::ContractAddress;
    use starknet::get_caller_address;
    use starknet::storage::Map;

    #[storage]
    struct Storage {
        balances: Map<ContractAddress, u256>,
        owner: ContractAddress,
        approved_auditors: Map<ContractAddress, bool>,
    }

    #[constructor]
    fn constructor(ref self: ContractState, owner: ContractAddress) {
        self.owner.write(owner);
    }

    // Public write function - anyone can deposit
    #[external(v0)]
    fn deposit(ref self: ContractState, amount: u256) {
        let caller = get_caller_address();
        let current = self.balances.entry(caller).read();
        self.balances.entry(caller).write(current + amount);
    }

    // Private read function - only owner and approved auditors
    #[external(v0)]
    fn get_balance(self: @ContractState, account: ContractAddress) -> u256 {
        let caller = get_caller_address();

        // Owner can read anyone's balance
        if caller == self.owner.read() {
            return self.balances.entry(account).read();
        }

        // Approved auditors can read anyone's balance
        if self.approved_auditors.entry(caller).read() {
            return self.balances.entry(account).read();
        }

        // Users can only read their own balance
        assert(caller == account, 'Not authorized to read balance');
        self.balances.entry(account).read()
    }

    // Only owner can approve auditors
    #[external(v0)]
    fn approve_auditor(ref self: ContractState, auditor: ContractAddress) {
        let caller = get_caller_address();
        assert(caller == self.owner.read(), 'Only owner can approve');
        self.approved_auditors.entry(auditor).write(true);
    }
}
```

**Usage with UNITS**:

```typescript
// This will succeed if you're authorized
const result = await unitsProvider.call({
  contract_address: vaultAddress,
  function_name: "get_balance",
  calldata: [accountAddress],
  signed_read_data: mySignedReadData,
});

// This will fail with "Not authorized to read balance" if you're not
```

---

### Private Class Access

Control who can read your smart contract code.

**Pattern**: Use ACL visibility when declaring

```typescript
// Declare a private contract
const declareResult = await unitsProvider.declareProgram({
  account_address: myAddress,
  signature: mySignature,
  nonce: currentNonce,
  program: contractSierra,
  compiled_program_hash: casmHash,
  class_visibility: "ACL", // Make it private
  resource_bounds: defaultBounds,
});

// Later, grant access to specific addresses via the Declare ACL contract
await myAccount.sendTransaction({
  contractAddress: declareAclAddress,
  entrypoint: "update_acl",
  calldata: [
    declareResult.program_hash,
    partnerAddress,
    1, // has_access = true
    myAddress, // granter
  ],
});
```

**Use Cases**:

- Proprietary trading algorithms
- Confidential business logic
- Contracts under development
- Competitive advantages in DeFi

---

### Private Nonce Reading

Prevent others from monitoring your account activity by hiding nonce.

**Pattern**: Implement `can_read_nonce` function

```cairo
#[starknet::contract]
mod PrivateAccount {
    use starknet::ContractAddress;
    use starknet::get_caller_address;

    #[storage]
    struct Storage {
        owner: ContractAddress,
        allowed_monitoring_services: Map<ContractAddress, bool>,
    }

    // Only owner and approved services can read nonce
    #[external(v0)]
    fn can_read_nonce(self: @ContractState) -> bool {
        let caller = get_caller_address();

        // Owner can always read
        if caller == self.owner.read() {
            return true;
        }

        // Approved monitoring services can read
        if self.allowed_monitoring_services.entry(caller).read() {
            return true;
        }

        false
    }

    #[external(v0)]
    fn allow_monitoring_service(ref self: ContractState, service: ContractAddress) {
        let caller = get_caller_address();
        assert(caller == self.owner.read(), 'Only owner');
        self.allowed_monitoring_services.entry(service).write(true);
    }
}
```

**Why This Matters**:

- Nonce reveals how active an account is
- Can expose trading patterns or business activity
- Privacy-focused accounts may want to hide this

---

### Private Event Access

Control who can see events emitted by your contract.

**Pattern**: Implement `can_read_event` function

```cairo
#[starknet::contract]
mod PrivateMarketplace {
    use starknet::ContractAddress;
    use starknet::get_caller_address;
    use starknet::storage::Map;

    #[storage]
    struct Storage {
        traders: Map<ContractAddress, bool>,
        public_events: Map<felt252, bool>,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        PublicListing: PublicListing,
        PrivateTrade: PrivateTrade,
        ConfidentialOffer: ConfidentialOffer,
    }

    #[derive(Drop, starknet::Event)]
    struct PublicListing {
        item_id: u256,
        price: u256,
    }

    #[derive(Drop, starknet::Event)]
    struct PrivateTrade {
        trader_a: ContractAddress,
        trader_b: ContractAddress,
        amount: u256,
    }

    #[derive(Drop, starknet::Event)]
    struct ConfidentialOffer {
        offer_id: u256,
    }

    #[constructor]
    fn constructor(ref self: ContractState) {
        // Mark PublicListing as public
        self.public_events.entry(selector!("PublicListing")).write(true);
    }

    // Control event visibility
    #[external(v0)]
    fn can_read_event(self: @ContractState, selector: felt252) -> bool {
        let caller = get_caller_address();

        // Public events - anyone can see
        if self.public_events.entry(selector).read() {
            return true;
        }

        // Private events - only registered traders
        self.traders.entry(caller).read()
    }

    #[external(v0)]
    fn register_trader(ref self: ContractState) {
        let caller = get_caller_address();
        // Add registration logic here
        self.traders.entry(caller).write(true);
    }
}
```

**How It Works**:

- When fetching a transaction receipt, UNITS checks each event
- For each event, it calls `can_read_event` with the event selector
- Events you can't access are filtered from the receipt
- You get a partial receipt with only events you're allowed to see
