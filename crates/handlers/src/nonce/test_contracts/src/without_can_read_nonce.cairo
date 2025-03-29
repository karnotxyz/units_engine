#[starknet::contract]
mod ContractWithoutCanReadNonce {
    #[storage]
    struct Storage {
    }

    #[constructor]
    fn constructor(ref self: ContractState) {
    }
}

