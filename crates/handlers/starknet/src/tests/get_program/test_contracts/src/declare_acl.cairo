// ============================================================================
// DECLARE ACL CONTRACT - REFERENCE IMPLEMENTATION
// ============================================================================
//
// ⚠️ WARNING: NOT AUDITED - USE AT YOUR OWN RISK
//
// This is a reference implementation of a Declare ACL contract for UNITS.
// It is provided as-is without any warranties or guarantees.
//
// Users of UNITS are free to implement their own Declare ACL contracts
// following the required interface, or use this reference implementation
// at their own risk. We do not take responsibility for any issues,
// vulnerabilities, or losses that may arise from using this code.
//
// ============================================================================
//
// OVERVIEW:
// This contract manages visibility and access control for declared classes
// in the UNITS system. It uses a counter-based approach where multiple
// declarers can independently grant/revoke access and visibility.
//
// KEY CONCEPTS:
// - ClassVisibility: Enum with Acl (0) and Public (1)
// - Default visibility: ACL (private)
// - Counter-based ACL: Each grant increments a counter, revoke decrements
// - Union semantics: Any positive count grants access/visibility
// - Granter tracking: Prevents double-granting and enforces "only revoke what you granted"
//
// REQUIRED INTERFACE (for UNITS compatibility):
// 1. set_visibility(class_hash, visibility, granter) - Called when class is declared
// 2. get_visibility(class_hash) -> ClassVisibility - Returns current visibility
// 3. has_read_access(class_hash) -> bool - Checks if caller can read the class
//
// STORAGE STRUCTURE & TRACKING MECHANISMS:
//
// 1. class_visibility: Map<class_hash -> u8 counter>
//    - Tracks class visibility: count = 0 means ACL (private), count > 0 means Public
//    - When someone declares with Public: increment counter by 1
//    - When someone declares with Acl:
//      * If they made it public before (tracked by visibility_granters): decrement counter
//      * If they never made it public before: no change (just return)
//    - Result: A class is Public if ANY granter made it public and hasn't revoked
//
// 2. visibility_granters: Map<class_hash -> granter_address -> bool>
//    - Tracks which granters have set a specific class to public
//    - Set to true when granter declares class as Public
//    - Set to false when granter revokes (declares as Acl after previously making it Public)
//    - Purpose: Prevents double-granting and ensures only those who made it public can revoke
//
// 3. class_acl_map: Map<class_hash -> account_address -> u8 counter>
//    - Stores who has access to which classes
//    - Counter-based: increments by 1 each time a unique granter gives access to an address
//    - Decrements by 1 when a granter who previously gave access removes it
//    - Result: An address has access if count > 0 (i.e., at least one granter gave access)
//
// 4. access_granters: Map<class_hash -> account_address -> granter_address -> bool>
//    - Tracks if a specific granter has given access to a specific address for a class
//    - Set to true when granter calls update_acl with has_access=true
//    - Set to false when granter calls update_acl with has_access=false
//    - Purpose: Prevents double-granting and ensures only granters who gave access can revoke it
//
// HOW set_visibility WORKS:
// - Called by UNITS when a class is declared with visibility parameter
// - If visibility=Public:
//   * Check if this granter already made it public (via visibility_granters)
//   * If yes: return early (no double-granting)
//   * If no: mark granter in visibility_granters, increment class_visibility counter
// - If visibility=Acl:
//   * Check if this granter ever made it public (via visibility_granters)
//   * If no: return early (this is either first declaration or granter never made it public)
//   * If yes: unmark granter in visibility_granters, decrement class_visibility counter
//
// HOW update_acl WORKS:
// - Called to grant/revoke access to specific addresses for ACL classes
// - If has_access=true (granting):
//   * Check if this granter already gave access (via access_granters)
//   * If yes: return early (no double-granting)
//   * If no: mark granter in access_granters, increment class_acl_map counter
// - If has_access=false (revoking):
//   * Check if this granter previously gave access (via access_granters)
//   * If no: assert/fail (can't revoke what you didn't grant)
//   * If yes: unmark granter in access_granters, decrement class_acl_map counter
//
// ============================================================================

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

            // Increment count, assert on overflow
            assert!(current_count < 255_u8, "Counter overflow: too many access grants");
            let new_count = current_count + 1_u8;
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

            // Decrement count, assert on underflow
            assert!(current_count > 0_u8, "Counter underflow: cannot decrement below zero");
            let new_count = current_count - 1_u8;
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

                // Increment count, assert on overflow
                assert!(current_count < 255_u8, "Counter overflow: too many public visibility grants");
                let new_count = current_count + 1_u8;
                self.class_visibility.entry(class_hash).write(new_count);
            },
            ClassVisibility::Acl => {
                // Check if this granter previously made it public
                let has_granted = self.visibility_granters.entry(class_hash).entry(granter).read();
                
                // If you never granted public visibility, you can't revoke it. However, this is not
                // an error - it's possible you're declaring the program for the first time w/ Acl
                // visibility.
                if !has_granted {
                    return;
                }
                

                // Remove granter's record
                self.visibility_granters.entry(class_hash).entry(granter).write(false);

                // Decrement count, assert on underflow
                assert!(current_count > 0_u8, "Counter underflow: cannot decrement below zero");
                let new_count = current_count - 1_u8;
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

