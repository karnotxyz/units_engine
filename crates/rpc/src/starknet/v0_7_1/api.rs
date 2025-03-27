use jsonrpsee::core::RpcResult;
use starknet::core::types::{
    BlockHashAndNumber, BlockId, BroadcastedDeclareTransaction,
    BroadcastedDeployAccountTransaction, BroadcastedInvokeTransaction, BroadcastedTransaction,
    ContractClass, DeclareTransactionResult, DeployAccountTransactionResult, EventFilterWithPage,
    EventsPage, FeeEstimate, Felt, FunctionCall, InvokeTransactionResult, MsgFromL1,
    SimulatedTransaction, SimulationFlag, SimulationFlagForEstimateFee, SyncStatusType,
    Transaction, TransactionReceiptWithBlockInfo, TransactionStatus, TransactionTrace,
};
use units_proc_macros::versioned_rpc;

// Starknet RPC API trait and types
//
// Starkware maintains [a description of the Starknet API](https://github.com/starkware-libs/starknet-specs/blob/master/api/starknet_api_openrpc.json)
// using the openRPC specification.
// This crate uses `jsonrpsee` to define such an API in Rust terms.

#[versioned_rpc("V0_7_1", "starknet")]
pub trait StarknetWriteRpcApi {
    /// Submit a new transaction to be added to the chain
    #[method(name = "addInvokeTransaction", and_versions = ["V0_8_0"])]
    async fn add_invoke_transaction(
        &self,
        invoke_transaction: BroadcastedInvokeTransaction,
    ) -> RpcResult<InvokeTransactionResult>;

    /// Submit a new deploy account transaction
    #[method(name = "addDeployAccountTransaction", and_versions = ["V0_8_0"])]
    async fn add_deploy_account_transaction(
        &self,
        deploy_account_transaction: BroadcastedDeployAccountTransaction,
    ) -> RpcResult<DeployAccountTransactionResult>;

    /// Submit a new class declaration transaction
    #[method(name = "addDeclareTransaction", and_versions = ["V0_8_0"])]
    async fn add_declare_transaction(
        &self,
        declare_transaction: BroadcastedDeclareTransaction,
    ) -> RpcResult<DeclareTransactionResult>;
}

#[versioned_rpc("V0_7_1", "starknet")]
pub trait StarknetReadRpcApi {
    /// Get the Version of the StarkNet JSON-RPC Specification Being Used
    #[method(name = "specVersion")]
    fn spec_version(&self) -> RpcResult<String>;

    /// Get the most recent accepted block number
    #[method(name = "blockNumber", and_versions = ["V0_8_0"])]
    fn block_number(&self) -> RpcResult<u64>;

    // Get the most recent accepted block hash and number
    #[method(name = "blockHashAndNumber", and_versions = ["V0_8_0"])]
    fn block_hash_and_number(&self) -> RpcResult<BlockHashAndNumber>;

    /// Call a contract function at a given block id
    #[method(name = "call", and_versions = ["V0_8_0"])]
    fn call(&self, request: FunctionCall, block_id: BlockId) -> RpcResult<Vec<Felt>>;

    /// Get the chain id
    #[method(name = "chainId", and_versions = ["V0_8_0"])]
    async fn chain_id(&self) -> RpcResult<Felt>;

    /// Estimate the fee associated with transaction
    #[method(name = "estimateFee", and_versions = ["V0_8_0"])]
    async fn estimate_fee(
        &self,
        request: Vec<BroadcastedTransaction>,
        simulation_flags: Vec<SimulationFlagForEstimateFee>,
        block_id: BlockId,
    ) -> RpcResult<Vec<FeeEstimate>>;

    /// Estimate the L2 fee of a message sent on L1
    #[method(name = "estimateMessageFee", and_versions = ["V0_8_0"])]
    async fn estimate_message_fee(
        &self,
        message: MsgFromL1,
        block_id: BlockId,
    ) -> RpcResult<FeeEstimate>;

    /// Get the contract class at a given contract address for a given block id
    #[method(name = "getClassAt", and_versions = ["V0_8_0"])]
    fn get_class_at(&self, block_id: BlockId, contract_address: Felt) -> RpcResult<ContractClass>;

    /// Get the contract class hash in the given block for the contract deployed at the given
    /// address
    #[method(name = "getClassHashAt", and_versions = ["V0_8_0"])]
    fn get_class_hash_at(&self, block_id: BlockId, contract_address: Felt) -> RpcResult<Felt>;

    /// Get the contract class definition in the given block associated with the given hash
    #[method(name = "getClass", and_versions = ["V0_8_0"])]
    fn get_class(&self, block_id: BlockId, class_hash: Felt) -> RpcResult<ContractClass>;

    /// Returns all events matching the given filter
    #[method(name = "getEvents", and_versions = ["V0_8_0"])]
    async fn get_events(&self, filter: EventFilterWithPage) -> RpcResult<EventsPage>;

    /// Get the nonce associated with the given address at the given block
    #[method(name = "getNonce", and_versions = ["V0_8_0"])]
    async fn get_nonce(&self, block_id: BlockId, contract_address: Felt) -> RpcResult<Felt>;

    /// Get the details of a transaction by a given block id and index
    #[method(name = "getTransactionByBlockIdAndIndex", and_versions = ["V0_8_0"])]
    fn get_transaction_by_block_id_and_index(
        &self,
        block_id: BlockId,
        index: u64,
    ) -> RpcResult<Transaction>;

    /// Returns the information about a transaction by transaction hash.
    #[method(name = "getTransactionByHash", and_versions = ["V0_8_0"])]
    fn get_transaction_by_hash(&self, transaction_hash: Felt) -> RpcResult<Transaction>;

    /// Returns the receipt of a transaction by transaction hash.
    #[method(name = "getTransactionReceipt", and_versions = ["V0_8_0"])]
    async fn get_transaction_receipt(
        &self,
        transaction_hash: Felt,
    ) -> RpcResult<TransactionReceiptWithBlockInfo>;

    /// Gets the Transaction Status, Including Mempool Status and Execution Details
    #[method(name = "getTransactionStatus", and_versions = ["V0_8_0"])]
    fn get_transaction_status(&self, transaction_hash: Felt) -> RpcResult<TransactionStatus>;

    /// Get an object about the sync status, or false if the node is not syncing
    #[method(name = "syncing", and_versions = ["V0_8_0"])]
    async fn syncing(&self) -> RpcResult<SyncStatusType>;
}

#[versioned_rpc("V0_7_1", "starknet")]
pub trait StarknetTraceRpcApi {
    /// Returns the execution trace of a transaction by simulating it in the runtime.
    #[method(name = "simulateTransactions", and_versions = ["V0_8_0"])]
    async fn simulate_transactions(
        &self,
        block_id: BlockId,
        transactions: Vec<BroadcastedTransaction>,
        simulation_flags: Vec<SimulationFlag>,
    ) -> RpcResult<Vec<SimulatedTransaction>>;

    #[method(name = "traceTransaction", and_versions = ["V0_8_0"])]
    /// Returns the execution trace of a transaction
    async fn trace_transaction(&self, transaction_hash: Felt) -> RpcResult<TransactionTrace>;
}
