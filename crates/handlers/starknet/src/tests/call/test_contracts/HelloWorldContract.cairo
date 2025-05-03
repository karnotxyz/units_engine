#[starknet::contract]
mod HelloWorldContract {
    #[storage]
    struct Storage {}

    #[external(v0)]
    fn hello_world(self: @ContractState) -> felt252 {
        1
    }
} 