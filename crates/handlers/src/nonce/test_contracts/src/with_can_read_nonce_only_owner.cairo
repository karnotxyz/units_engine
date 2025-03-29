#[starknet::contract]
mod ContractWithCanReadNonceOnlyOwner {
    use starknet::storage::{StoragePointerReadAccess, StoragePointerWriteAccess};
    use starknet::ContractAddress;
    
    #[storage]
    struct Storage {
        owner: ContractAddress,
    }

    #[constructor]
    fn constructor(ref self: ContractState) {
        let tx_info = starknet::get_tx_info().unbox();
        self.owner.write(tx_info.account_contract_address);
    }

    #[external(v0)]
    fn can_read_nonce(self: @ContractState) -> bool {
        let tx_info = starknet::get_tx_info().unbox();
        assert!(
            tx_info.account_contract_address == self.owner.read(),
            "Only owner can read nonce"
        );
        true
    }
}

