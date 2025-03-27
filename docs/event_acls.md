# Event Read ACLs for UNITs on Starknet

By default, all events emitted by Starknet contracts are public and can be read by any user. This aligns with the standard behavior of Starknet contracts.

## Proposed Standard: Fine-grained Event Read ACLs

UNITs introduces a new standard where contracts can define granular access controls for reading events through a specific function:

- `can_read_event`

### How it Works

When a user attempts to read events from a contract, the RPC will:

1. Call the `can_read_event` function on the target contract with an array of event selectors
2. The function returns an array of booleans indicating which events can be read
3. Only return the requested events if their corresponding boolean is `true`
4. If the function doesn't exist (for compatibility with existing contracts on Starknet), all events are public by default

### Example Implementation

Here's an example of how to implement event read access control in Cairo (Note: This is a conceptual example for illustration purposes only and has not been tested on-chain):

```cairo
#[starknet::interface]
trait IEventReadACL {
    fn can_read_event(selectors: Array<felt252>) -> Array<bool>;
}

#[starknet::contract]
mod MyContract {
    use starknet::ContractAddress;
    use array::ArrayTrait;

    #[storage]
    struct Storage {
        admin: ContractAddress,
        private_event_selectors: LegacyMap::<felt252, bool>,
    }

    #[constructor]
    fn constructor(ref self: ContractState, admin: ContractAddress) {
        self.admin.write(admin);

        // Example: Mark specific events as private
        self.private_event_selectors.write(selector!("PrivateTransfer"), true);
        self.private_event_selectors.write(selector!("ConfidentialMint"), true);
    }

    #[external(v0)]
    fn can_read_event(self: @ContractState, selectors: Array<felt252>) -> Array<bool> {
        let mut result = ArrayTrait::new();
        let caller = starknet::get_caller_address();
        let is_admin = caller == self.admin.read();

        // Check each selector
        let mut i: u32 = 0;
        loop {
            if i >= selectors.len() {
                break;
            }

            let selector = *selectors.at(i);
            // If event is not marked as private, it's public
            // If it is private, only admin can read it
            let can_read = !self.private_event_selectors.read(selector) || is_admin;
            result.append(can_read);

            i += 1;
        };

        result
    }
}
```

### Backward Compatibility

For contracts that don't implement the `can_read_event` function, the RPC will maintain the current behavior where reading events is allowed for all users. This ensures compatibility with existing contracts on Starknet while allowing new contracts to implement more granular access controls for their events.
