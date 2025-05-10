#[starknet::contract]
mod ReadWithApproval {
    use starknet::ContractAddress;
    use starknet::get_caller_address;
    use starknet::storage::Map;
    use starknet::storage::StoragePointerWriteAccess;
    use starknet::storage::StoragePointerReadAccess;
    use starknet::storage::StoragePathEntry;

    #[storage]
    struct Storage {
        value: felt252,
        owner: ContractAddress,
        approved_users: Map<ContractAddress, bool>
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        UserApproved: UserApproved
    }

    #[derive(Drop, starknet::Event)]
    struct UserApproved {
        user: ContractAddress
    }

    #[constructor]
    fn constructor(ref self: ContractState, initial_value: felt252) {
        let tx_info = starknet::get_tx_info().unbox();
        let owner = tx_info.account_contract_address;
        self.owner.write(owner);
        self.value.write(initial_value);
        self.approved_users.entry(owner).write(true);
    }

    #[external(v0)]
    fn read_value(self: @ContractState) -> felt252 {
        let caller = get_caller_address();
        let is_approved = self.approved_users.entry(caller).read();
        assert(is_approved, 'Caller is not approved');
        self.value.read()
    }

    #[external(v0)]
    fn add_approved_user(ref self: ContractState, user: ContractAddress) {
        let caller = get_caller_address();
        assert!(caller == self.owner.read(), "Only owner can add approved users");
        self.approved_users.entry(user).write(true);
        self.emit(UserApproved { user });
    }
}
