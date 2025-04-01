#[starknet::contract]
mod ContractWithCanReadEvent {
    use starknet::storage::Map;
    use starknet::storage::StoragePointerWriteAccess;
    use starknet::storage::StoragePointerReadAccess;
    use starknet::storage::StoragePathEntry;
    use starknet::ContractAddress;

    #[storage]
    struct Storage {
        event_acl_map: Map<ContractAddress, Map<felt252, bool>>,
        owner: ContractAddress,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event {
        TestEventOne: TestEventOne,
        TestEventTwo: TestEventTwo,
    }

    #[derive(Drop, starknet::Event)]
    struct TestEventOne {
        data: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct TestEventTwo {
        data: u64,
    }

    const TEST_EVENT_ONE_SELECTOR: felt252 = selector!("TestEventOne");
    const TEST_EVENT_TWO_SELECTOR: felt252 = selector!("TestEventTwo");

    #[constructor]
    fn constructor(ref self: ContractState) {
        let tx_info = starknet::get_tx_info().unbox();
        self.owner.write(tx_info.account_contract_address);
    }

    #[external(v0)]
    fn update_acl(ref self: ContractState, event_selector: felt252, account_contract_address: ContractAddress) {
        let tx_info = starknet::get_tx_info().unbox();
        assert!(
            tx_info.account_contract_address == self.owner.read(),
            "Only owner can update ACL"
        );
        self.event_acl_map.entry(account_contract_address).entry(event_selector).write(true);
    }

    #[external(v0)]
    fn emit_event_one(ref self: ContractState) {
        let event = TestEventOne {
            data: 1,
        };
        self.emit(event);
    }

    #[external(v0)]
    fn emit_event_two(ref self: ContractState) {
        let event = TestEventTwo {
            data: 2,
        };
        self.emit(event);
    }

    #[external(v0)]
    fn emit_event_one_and_two(ref self: ContractState) {
        let event_one = TestEventOne {
            data: 1,
        };
        let event_two = TestEventTwo {
            data: 2,
        };
        self.emit(event_one);
        self.emit(event_two);
    }

    #[external(v0)]
    fn can_read_event(ref self: ContractState) -> bool {
        let tx_info = starknet::get_tx_info().unbox();
        assert!(
            tx_info.account_contract_address == self.owner.read(),
            "Only owner can read nonce"
        );
        true
    }
}
