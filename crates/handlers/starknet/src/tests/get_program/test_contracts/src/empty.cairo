// TODO: The same contract exists in some other tests too, we should move it to a shared location
#[starknet::contract]
mod EmptyContract {
    #[storage]
    struct Storage {
    }

    #[constructor]
    fn constructor(ref self: ContractState) {
    }
}

