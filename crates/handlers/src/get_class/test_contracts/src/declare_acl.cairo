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
        Acl, // 0
        Public, // 1
    }

    #[storage]
    struct Storage {
        // Maps class_hash -> contract_address -> u8
        // The u8 represents the count of access grants
        // If count > 0, access is granted
        class_acl_map: Map<felt252, Map<ContractAddress, u8>>,
        // Maps class_hash -> visibility -> u8
        // The u8 represents the count of visibility settings
        // If count > 0, it's public, otherwise it's ACL
        class_visibility: Map<felt252, u8>,
        // Maps class_hash -> grantee -> granter -> bool
        // Tracks who gave access to whom
        access_granters: Map<felt252, Map<ContractAddress, Map<ContractAddress, bool>>>,
        // Maps class_hash -> granter -> bool
        // Tracks who made the class public
        visibility_granters: Map<felt252, Map<ContractAddress, bool>>,
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
        has_access: bool,
        granter: ContractAddress
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
        if has_access {
            // Check if this granter has already given access
            let has_granted = self.access_granters.entry(class_hash).entry(account_contract_address).entry(granter).read();
            if has_granted {
                // Silently return if already granted
                return;
            }

            // Record that this granter gave access
            self.access_granters.entry(class_hash).entry(account_contract_address).entry(granter).write(true);

            // Increment count, but don't overflow
            let new_count = if current_count == 255_u8 {
                current_count
            } else {
                current_count + 1_u8
            };
            self.class_acl_map.entry(class_hash).entry(account_contract_address).write(new_count);

            // Emit event for the update
            let acl_update = AclUpdate {
                class_hash,
                account_contract_address,
                has_access,
                count: new_count,
            };
            self.emit(acl_update);
        } else {
            // Check if this granter previously gave access
            let has_granted = self.access_granters.entry(class_hash).entry(account_contract_address).entry(granter).read();
            assert!(has_granted, "Cannot revoke access that you didn't grant");

            // Remove granter's record
            self.access_granters.entry(class_hash).entry(account_contract_address).entry(granter).write(false);

            // Decrement count, but don't underflow
            let new_count = if current_count == 0_u8 {
                current_count
            } else {
                current_count - 1_u8
            };
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
    }

    #[external(v0)]
    fn set_visibility(
        ref self: ContractState, 
        class_hash: felt252, 
        visibility: ClassVisibility,
        granter: ContractAddress
    ) {
        // Only owner can set visibility
        let tx_info = starknet::get_tx_info().unbox();
        assert!(
            tx_info.account_contract_address == self.owner.read(),
            "Only owner can set visibility"
        );

        // Get current count
        let current_count = self.class_visibility.entry(class_hash).read();
        
        match visibility {
            ClassVisibility::Public => {
                // Check if this granter has already made it public
                let has_granted = self.visibility_granters.entry(class_hash).entry(granter).read();
                if has_granted {
                    // Silently return if already granted
                    return;
                }

                // Record that this granter made it public
                self.visibility_granters.entry(class_hash).entry(granter).write(true);

                // Increment count, but don't overflow
                let new_count = if current_count == 255_u8 {
                    current_count
                } else {
                    current_count + 1_u8
                };
                self.class_visibility.entry(class_hash).write(new_count);
            },
            ClassVisibility::Acl => {
                // Check if this granter previously made it public
                let has_granted = self.visibility_granters.entry(class_hash).entry(granter).read();
                assert!(has_granted, "Cannot revoke public visibility that you didn't grant");

                // Remove granter's record
                self.visibility_granters.entry(class_hash).entry(granter).write(false);

                // Decrement count, but don't underflow
                let new_count = if current_count == 0_u8 {
                    current_count
                } else {
                    current_count - 1_u8
                };
                self.class_visibility.entry(class_hash).write(new_count);
            }
        }
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
        // If count > 0, return Public, otherwise return Acl
        let count = self.class_visibility.entry(class_hash).read();
        if count > 0_u8 {
            ClassVisibility::Public
        } else {
            ClassVisibility::Acl
        }
    }
}

