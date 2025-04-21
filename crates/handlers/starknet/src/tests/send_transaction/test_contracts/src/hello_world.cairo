#[starknet::contract]
mod HelloWorldContract {
    use starknet::storage::{StoragePointerWriteAccess};

    #[storage]
    struct Storage {
        message: felt252,
    }

    #[constructor]
    fn constructor(ref self: ContractState) {
    }   

    #[external(v0)]
    fn hello_world(ref self: ContractState) {
        self.message.write(1);
    }
}

