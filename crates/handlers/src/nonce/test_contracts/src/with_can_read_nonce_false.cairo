#[starknet::contract]
mod ContractWithCanReadNonceFalse {
    #[storage]
    struct Storage {
    }

    #[constructor]
    fn constructor(ref self: ContractState) {
    }

    #[external(v0)]
    fn can_read_nonce(self: @ContractState) -> bool {
        false
    }
}

