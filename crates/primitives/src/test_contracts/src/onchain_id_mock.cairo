#[starknet::contract]
pub mod OnchainIDMock {
    use core::array::ArrayTrait;
    use core::num::traits::Zero;
    use starknet::storage::Map;
    use starknet::storage::StoragePointerReadAccess;
    use starknet::storage::StoragePointerWriteAccess;
    use starknet::storage::StoragePathEntry;

    // Storage for the mock implementation
    #[storage]
    struct Storage {
        // Map key hash to key details
        Identity_keys: Map::<felt252, KeyDetails>,
    }

    // Key details structure matching the original implementation
    #[derive(Copy, Drop, Serde, starknet::Store)]
    struct KeyDetails {
        key_type: felt252,
        purposes: felt252,
    }

    // Events matching the original implementation
    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        KeyAdded: KeyAdded,
    }

    #[derive(Drop, starknet::Event)]
    struct KeyAdded {
        key: felt252,
        purpose: felt252,
        key_type: felt252,
    }

    #[generate_trait]
    impl KeyDetailsImpl of KeyDetailsTrait {
        fn get_all_purposes(self: KeyDetails) -> Array<felt252> {
            let mut result = ArrayTrait::new();
            if self.purposes.is_non_zero() {
                result.append(self.purposes);
            }
            result
        }
    }

    // Define the interface trait before implementation
    #[starknet::interface]
    trait IOnchainIDMock<TContractState> {
        fn get_key(self: @TContractState, key: felt252) -> (Span<felt252>, felt252, felt252);
        fn set_key(ref self: TContractState, key: felt252, key_type: felt252, purposes: felt252);
    }

    #[abi(embed_v0)]
    impl OnchainIDMockImpl of IOnchainIDMock<ContractState> {
        fn get_key(self: @ContractState, key: felt252) -> (Span<felt252>, felt252, felt252) {
            let key_details = self.Identity_keys.entry(key).read();
            
            if key_details.purposes.is_zero() {
                return (ArrayTrait::new().span(), Zero::zero(), Zero::zero());
            }
            
            (key_details.get_all_purposes().span(), key_details.key_type, key)
        }

        // Helper function to set up keys for testing
        fn set_key(ref self: ContractState, key: felt252, key_type: felt252, purposes: felt252) {
            self.Identity_keys.entry(key).write(KeyDetails { key_type, purposes });
            
            // Emit event to match original behavior
            self.emit(Event::KeyAdded(KeyAdded { 
                key, 
                purpose: purposes, 
                key_type 
            }));
        }
    }
}
