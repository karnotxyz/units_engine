#[starknet::contract]
mod ContractWithoutCanReadEvent {
    #[storage]
    struct Storage {
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event {
        TestEvent: TestEvent
    }

    #[derive(Drop, starknet::Event)]
    struct TestEvent {
        data: u64,
    }

    #[constructor]
    fn constructor(ref self: ContractState) {
    }

    #[external(v0)]
    fn emit_event(ref self: ContractState) {
        let event = TestEvent {
            data: 1,
        };
        self.emit(event);
    }
}
