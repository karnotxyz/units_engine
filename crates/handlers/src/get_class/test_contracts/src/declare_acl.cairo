#[starknet::contract]
mod DeclareAclContract {
    use starknet::ContractAddress;
    use starknet::storage::Map;
    use starknet::storage::StoragePointerWriteAccess;
    use starknet::storage::StoragePointerReadAccess;
    use starknet::storage::StoragePathEntry;

    #[derive(Drop, Serde, Copy, PartialEq, starknet::Store, Default)]
    enum ClassVisibility {
        #[default]
        Public, // 0
        Acl, // 1
        // TODO: Add PublicPermanent in future
    }

    #[storage]
    struct Storage {
        // Maps class_hash -> contract_address -> u8
        // The u8 represents the count of access grants
        // If count > 0, access is granted
        class_acl_map: Map<felt252, Map<ContractAddress, u8>>,
        // Maps class_hash -> visibility
        class_visibility: Map<felt252, ClassVisibility>,
        owner: ContractAddress,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event {
        AclUpdate: AclUpdate,
    }

    #[derive(Drop, starknet::Event)]
    struct AclUpdate {
        class_hash: felt252,
        account_contract_address: ContractAddress,
        has_access: bool,
        count: u8,
    }

    #[constructor]
    fn constructor(ref self: ContractState) {
        // Set the deployer as the owner
        let tx_info = starknet::get_tx_info().unbox();
        self.owner.write(tx_info.account_contract_address);
    }

    #[external(v0)]
    fn update_acl(
        ref self: ContractState, 
        class_hash: felt252, 
        account_contract_address: ContractAddress,
        has_access: bool
    ) {
        // Only owner can update ACL
        let tx_info = starknet::get_tx_info().unbox();
        assert!(
            tx_info.account_contract_address == self.owner.read(),
            "Only owner can update ACL"
        );

        // Get current count
        let current_count = self.class_acl_map.entry(class_hash).entry(account_contract_address).read();
        
        // Update the count based on has_access
        let new_count = if has_access {
            // Increment count, but don't overflow
            if current_count == 255_u8 {
                current_count
            } else {
                current_count + 1_u8
            }
        } else {
            // Decrement count, but don't underflow
            if current_count == 0_u8 {
                current_count
            } else {
                current_count - 1_u8
            }
        };

        // Update the ACL mapping with new count
        self.class_acl_map.entry(class_hash).entry(account_contract_address).write(new_count);

        // Emit event for the update
        let acl_update = AclUpdate {
            class_hash,
            account_contract_address,
            has_access,
            count: new_count,
        };
        self.emit(acl_update);
    }

    #[external(v0)]
    fn set_visibility(ref self: ContractState, class_hash: felt252, visibility: ClassVisibility) {
        // Only owner can set visibility
        let tx_info = starknet::get_tx_info().unbox();
        assert!(
            tx_info.account_contract_address == self.owner.read(),
            "Only owner can set visibility"
        );

        // Update the visibility mapping
        self.class_visibility.entry(class_hash).write(visibility);
    }
    

    #[external(v0)]
    fn has_read_access(self: @ContractState, class_hash: felt252) -> bool {
        // Read the count and return true if count > 0
        let tx_info = starknet::get_tx_info().unbox();
        let count = self.class_acl_map.entry(class_hash).entry(tx_info.account_contract_address).read();
        count > 0_u8
    }

    #[external(v0)]
    fn get_owner(self: @ContractState) -> ContractAddress {
        self.owner.read()
    }

    #[external(v0)]
    fn get_access_count(self: @ContractState, class_hash: felt252) -> u8 {
        let tx_info = starknet::get_tx_info().unbox();
        self.class_acl_map.entry(class_hash).entry(tx_info.account_contract_address).read()
    }

    #[external(v0)]
    fn get_visibility(self: @ContractState, class_hash: felt252) -> ClassVisibility {
        // If no visibility is set, return Public by default
        self.class_visibility.entry(class_hash).read()
    }
}

