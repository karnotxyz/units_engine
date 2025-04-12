#[starknet::contract]
mod EmptyContract {
    #[storage]
    struct Storage {
    }

    #[constructor]
    fn constructor(ref self: ContractState) {
    }
}

