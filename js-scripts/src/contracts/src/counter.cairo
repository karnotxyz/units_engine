#[starknet::contract]
mod CounterContract {
    use starknet::storage::{StoragePointerReadAccess, StoragePointerWriteAccess};
    #[storage]
    struct Storage {
        counter: u32,
    }

    #[constructor]
    fn constructor(ref self: ContractState) {
        self.counter.write(0);
    }

    #[external(v0)]
    fn increment(ref self: ContractState, amount: u32) {
        self.counter.write(self.counter.read() + amount);
    }

    #[external(v0)]
    fn decrement(ref self: ContractState, amount: u32) {
        self.counter.write(self.counter.read() - amount);
    }

    #[external(v0)]
    fn get_counter(ref self: ContractState) -> u32 {
        self.counter.read()
    }
}
